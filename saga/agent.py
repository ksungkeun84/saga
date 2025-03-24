import threading
import time
import json
import os
import bson.json_util
import socket
import ssl
import base64
import requests
from datetime import datetime, timedelta, timezone
import traceback
import saga.config
from pathlib import Path
import random
from saga.logger import Logger as logger
from saga.ca.CA import get_SAGA_CA

DEBUG = False
MAX_BUFFER_SIZE = 4096
MAX_QUERIES = 50
""""

Agent class for the SAGA system.

"""
import saga.crypto as sc

def get_provider_cert():
    """
    This is a 'smarter' way to get the provider's certificate. This function uses the requests library
    to get the certificate of the server.
    """
    provider_url = saga.config.PROVIDER_URL
    response = requests.get(provider_url+"/certificate", verify=saga.config.CA_CERT_PATH)
    cert_bytes = base64.b64decode(response.json().get('certificate'))
    cert = sc.bytesToX509Certificate(cert_bytes)
    
    return cert

def get_agent_material(dir_path: Path):
    # Check if dir exists:
    if not os.path.exists(dir_path):
        os.mkdir(dir_path)

    # Open agent.json
    if dir_path[-1] != '/':
        dir_path += "/"

    material = None
    with open(dir_path+"agent.json", "r") as f:
        material = json.load(f)
    
    return material


class DummyAgent:
    """
    Dummy agent for networkig testing purposes. Simulates a dumb agent that thinks and returns a ranom response.
    """
    vocab = [
        "Hi",
        "Hello",
        "Yeah this makes sense.",
        "I think I understand.",
        "I love apples",
        "I don't know.",
        "I'm not sure.",
        "I'm sorry, I don't understand.",
        "I'm sorry, I can't do that.",
        "Do you think that we have purpose?",
        "What is the meaning of life?",
        "Do you think we are alone in the universe?",
        "I think we are alone in the universe.",
        "I think we are not alone in the universe.",
        'Faxxx',
        "<TASK_FINISHED>",
        "<TASK_FINISHED>",
        "<TASK_FINISHED>",
        "<TASK_FINISHED>"
    ]

    def __init__(self):
        self.task_finished_token = "<TASK_FINISHED>"

    def run(self, query, agent_instance=None):
        time.sleep(1)
        if query == self.task_finished_token:
            return self.task_finished_token
        return None, random.choice(DummyAgent.vocab)


class Agent:
    def __init__(self, workdir, material, local_agent = None):

        self.workdir = workdir
        if self.workdir[-1] != '/':
            self.workdir += '/'

        # library-agnostic agent object
        self.local_agent = local_agent
        if local_agent is None:
            logger.warn("No local agent provided. Using dummy agent.")
            self.local_agent = DummyAgent()

        self.task_finished_token = self.local_agent.task_finished_token

        self.aid = material.get("aid")
        self.device = material.get("device")
        self.IP = material.get("IP")
        self.port = material.get("port")

        # Provider Identity
        # Setup the SAGA CA:
        self.CA = get_SAGA_CA()
        # Download provider certificate
        provider_cert = get_provider_cert()
        # Verify the provider certificate:
        self.CA.verify(provider_cert) # if the verification fails an exception will be raised.
        self.PK_Prov = provider_cert.public_key()

        # Device Info Signature
        self.dev_info_sig = material.get("dev_info_sig")

        # TLS signing keys for the Agent:
        self.private_signing_key = sc.bytesToPrivateEd25519Key(
            base64.b64decode(material.get("private_signing_key"))
        )

        # Load the agent's certificates
        self.cert = sc.bytesToX509Certificate(
            base64.b64decode(material.get("agent_cert"))
        )

        self.public_signing_key = self.cert.public_key()

        # Save the key and certificate:
        sc.save_ed25519_keys(self.workdir+"agent", self.private_signing_key, self.public_signing_key)
        sc.save_x509_certificate(self.workdir+"agent", self.cert)

        # Agent Identity Key Pair:
        self.identity_key = sc.bytesToPublicX25519Key(
            base64.b64decode(material.get("identity_key"))
        )
        self.secret_identity_key = sc.bytesToPrivateX25519Key(
            base64.b64decode(material.get("secret_identity_key"))
        )
        
        # Signed Pre-Keys:
        self.spk = sc.bytesToPublicX25519Key(
            base64.b64decode(material.get("spk"))
        )
        self.spk_sig = base64.b64decode(material.get("spk_sig"))
        self.sspk = sc.bytesToPrivateX25519Key(
            base64.b64decode(material.get("sspk"))
        )

        # One-Time Pre-Keys:
        self.sopks = [sc.bytesToPrivateX25519Key(
            base64.b64decode(sopk)
        ) for sopk in material.get("sopks")]
        self.opks = [sc.bytesToPublicX25519Key(
            base64.b64decode(opk)
        ) for opk in material.get("opks")]

        # Join the One-time Pre-keys:
        self.opks_dict = {}
        for i in range(len(self.opks)):
            self.opks_dict[self.opks[i].public_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PublicFormat.Raw
            )] = self.sopks[i] 

        # Init token storing dicts:
        self.active_tokens = {} # Active tokens that were given to initiating agents from the agent.
        self.active_tokens_lock = threading.Lock()
        self.aid_to_token = {} # dict that maps the aid of a receiving agent to the token that was given from them.
        self.received_tokens = {} # Tokens that were received from the receiving agents.
        self.received_tokens_lock = threading.Lock()

        # Print:
        if DEBUG:
            for key, value in self.__dict__.items():
                print(f"{key}: {value}")

    def lookup(self, t_aid):
        response = requests.post(f"{saga.config.PROVIDER_URL}/lookup", json={'t_aid': t_aid}, verify=saga.config.CA_CERT_PATH) 
        if response.status_code == 200:
            data = response.json()
            # Convert extended-json dict to python dict:
            data = bson.json_util.loads(json.dumps(data))
            return data
        else:
            print(response.json())
            return None        
        
    def access(self, t_aid):
        response = requests.post(f"{saga.config.PROVIDER_URL}/access", json={'t_aid': t_aid}, verify=saga.config.CA_CERT_PATH) 
        if response.status_code == 200:
            data = response.json()
            # Convert extended-json dict to python dict:
            data = bson.json_util.loads(json.dumps(data))
            return data
        else:
            print(response.json())
            return None

    def generate_token(self, recipient_identity_key, sdhk) -> bytes:
        """
        Encode a token based on the shared diffie-hellman key.
        """

        # Generate a random nonce
        nonce = os.urandom(12)

        # Issue and expiration timestamps
        issue_timestamp = datetime.now(tz=timezone.utc)
        expiration_timestamp = issue_timestamp + timedelta(hours=1)

        # Communication quota
        communication_quota = 5  # Example quota

        # Token dictionary
        token_dict = {
            "nonce": nonce,
            "issue_timestamp": issue_timestamp,
            "expiration_timestamp": expiration_timestamp,
            "communication_quota": communication_quota,
            "recipient_identity_key": recipient_identity_key
        }

        # Encrypt the token using the shared DH key (SDHK)
        encrypted_token = sc.encrypt_token(token_dict, sdhk)
        
        return encrypted_token

    def token_is_valid(self, token: str) -> bool:
        """
        Checks if a token that was presented by an initiating agent is valid.
        - If it was not generated by self, it is invalid.
        - If it is expired, it is invalid.
        - If the communication quota is reached, it is invalid.
        """
        with self.active_tokens_lock:
            if token not in self.active_tokens.keys():
                logger.error("Token provided by initiating not found in given tokens.")
                return False
            # Check if the token is still valid:
            token_dict = self.active_tokens[token]
        
            # Check the expiration date
            expiration_date = token_dict.get("expiration_timestamp")
            expiration_timestamp = datetime.fromisoformat(expiration_date)        
            if datetime.now(tz=timezone.utc) > expiration_timestamp:
                logger.error("Token expired.")
                return False
            
            # Check the communication quota:
            remaining_quota = token_dict.get("communication_quota")
            if remaining_quota == 0:
                logger.error("Token's max quota has been exceeded.")
                return False

            # TODO: Check if the recipient identity key is the same as the one that was used to initiate the convo.

            return True

    def received_token_is_valid(self, token: str) -> bool:
        """
        Makes sure that the token that was received from the receiving agent is valid.
        - If it is expired, it is invalid.
        - If the communication quota is reached, it is invalid.
        """
        with self.received_tokens_lock:
            if token not in self.received_tokens.keys():
                print("Token not found.") 
                return False
            
            # Check if the token is still valid:
            token_dict = self.received_tokens[token]
            
            # Check the expiration date
            expiration_date = token_dict.get("expiration_timestamp")
            expiration_timestamp = datetime.fromisoformat(expiration_date)        
            if datetime.now(tz=timezone.utc) > expiration_timestamp:
                print("Token expired.")
                return False
            
            # Check the communication quota:
            remaining_quota = token_dict.get("communication_quota")
            if remaining_quota == 0:
                print("Communication quota reached.")
                return False

            return True

    def store_received_token(self, r_aid, token_str, token_dict):
        """
        Stores the token that was received from the receiving agent.
        """
        with self.received_tokens_lock:
            self.received_tokens[token_str] = token_dict
            self.aid_to_token[r_aid] = token_str

    def retrieve_valid_token(self, r_aid):
        """
        Retrieves a valid token for the receiving agent.
        """
        with self.received_tokens_lock: # THIS CREATES A DEADLOCK
            token = self.aid_to_token.get(r_aid, None)
        if token is None:
            return None
        if not self.received_token_is_valid(token): # THIS TRIES TO ACCESS THE SAME MUTEX LOCK --> DEADLOCK.
            with self.received_tokens_lock:
                # remove the token from the received tokens:
                del self.received_tokens[token]
                # remove the token from the aid_to_token dict:
                del self.aid_to_token[r_aid]
            return None
        return token

    def initiate_conversation(self, conn, token: str, init_msg: str) -> bool:
        """
        Returns true if the conversation ended from the initiating side.
        """
        agent_instance = None

        text = init_msg
        i = 0
        while True:
            # Prepare message: 
            msg = {
                "msg": text,
                "token": token
            }
            # Check if the received token that you are using is valid:
            if not self.received_token_is_valid(msg["token"]):
                logger.error("Token is invalid. Ending conversation...")
                return True

            # Send message:
            conn.sendall(json.dumps(msg).encode('utf-8'))
            logger.log("AGENT", f"Sent: \'{msg['msg']}\'")

            # Reduce the remaining quota for the token:
            with self.received_tokens_lock:
                self.received_tokens[token]["communication_quota"] = max(0, self.received_tokens[token]["communication_quota"] - 1)
                logger.log('ACCESS', f'Remaining token quota: {self.received_tokens[token]["communication_quota"]}')

            if msg['msg'] == self.task_finished_token:
                logger.log("AGENT", "Task deemed complete from initiating side.")
                return True
            # Receive response:
            response = conn.recv(MAX_BUFFER_SIZE)
            if not response:
                logger.warn("Received b'' indicating that the connection might have been closed from the other side. Returning...")
                return False
            response = json.loads(response.decode('utf-8'))

            # Process response:
            received_message = str(response.get("msg", self.local_agent.task_finished_token))
            logger.log("AGENT", f"Received: \'{received_message}\'")
            if received_message == self.task_finished_token:
                logger.log("AGENT", "Task deemed complete from receiving side.")
                return False
            
            # Process message:
            if i > MAX_QUERIES:
                logger.warn("Maximum allowed number of queries in the conversation is reached. Ending conversation...")
                return True
            agent_instance, text = self.local_agent.run(received_message, agent_instance=agent_instance)
            i += 1 # increment queries counter

    def receive_conversation(self, conn, token: str) -> bool:
        """
        Returns true if the conversation ended from the receiving side.
        """
        agent_instance = None
        i = 0
        while True: 
            
            # Receive message from the initiating side:
            message = conn.recv(MAX_BUFFER_SIZE)
            if not message:
                logger.warn("Received b'' indicating that the connection might have been closed from the other side. Returning...")
                return False
            
            # If the message is not empty, process it:
            message_dict = json.loads(message.decode('utf-8'))

            # Extract token from the message:
            token = message_dict.get("token", None)
            
            # Check if the token of the message is valid
            if not self.token_is_valid(token):
                logger.error("Token is invalid. Ending conversation...")
                return True
            
            # Reduce the remaining quota for the token:
            with self.active_tokens_lock:
                self.active_tokens[token]["communication_quota"] = max(0, self.active_tokens[token]["communication_quota"] - 1)
                logger.log('ACCESS', f'Remaining token quota: {self.active_tokens[token]["communication_quota"]}')
            
            # Process message:
            received_message = str(message_dict.get("msg", self.local_agent.task_finished_token))
            logger.log("AGENT", f"Received: \'{received_message}\'")

            if received_message == self.task_finished_token:
                logger.log("AGENT", "Task deemed complete from initiating side.")
                return False

            # Check if too many queries have been sent to your llm resources:
            if i > MAX_QUERIES:
                logger.warn("Maximum allowed number of queries in the conversation is reached. Ending conversation...")
                return True

            # Get agent response:
            agent_instance, response = self.local_agent.run(query=received_message, agent_instance=agent_instance)
            i+=1 # increase query counter
            
            # Prepare response:
            response_dict = {
                "msg": response,
                "token": token
            }
            # Send response:
            conn.sendall(json.dumps(response_dict).encode('utf-8'))
            logger.log("AGENT", f"Sent: \'{response_dict['msg']}\'")

            if response_dict['msg'] == self.task_finished_token:
                logger.log("AGENT", "Task deemed complete from receiving side.")
                return True

    def connect(self, r_aid, message: str):

        # Get everything you need to reach the receiving agent from the provider:
        logger.log("ACCESS", f"Requesting access to {r_aid} via the Provider.")
        r_agent_material = self.access(r_aid)

        if r_agent_material is None:
            logger.log("ACCESS", f"Access to {r_aid} denied.")
            return

        # ========================================================================
        # Perform verification checks for integrity purposes before connecting to 
        # the receiving agent.
        # ========================================================================    

        # Retrieve user identity key: 
        pk_u = sc.bytesToPublicEd25519Key(
            r_agent_material.get("pk_u", None)
        )
    
        # Verify the agent's identity:
        r_aid = r_agent_material.get("aid", None)
        r_agent_cert_bytes = r_agent_material.get("agent_cert", None)
        r_agent_cert = sc.bytesToX509Certificate(
            r_agent_cert_bytes 
        )
        if r_agent_cert is None:
            print("No valid certificate found.")
            return
        r_agent_public_signing_key = r_agent_cert.public_key()
        r_agent_public_signing_key_bytes = r_agent_public_signing_key.public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw
        )
        
        r_agent_identity = {
            "aid": r_aid,
            "public_signing_key": r_agent_public_signing_key_bytes,
            "pk_prov": self.PK_Prov.public_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PublicFormat.Raw)
        }

        r_public_signing_key_sig_bytes = r_agent_material.get("public_signing_key_sig")

        logger.log("CRYPTO", f"Verifying {r_aid} identity.")
        try:
            pk_u.verify(
                r_public_signing_key_sig_bytes,
                str(r_agent_identity).encode("utf-8")
            )
        except:
            logger.error(f"{r_aid} IDENTITY VERIFICATION FAILED. UNSAFE CONNECTION.")
            return
        

        # Verify the target agent's device information:
        r_device = r_agent_material.get("device")
        r_ip = r_agent_material.get("IP")
        r_port = r_agent_material.get("port")

        dev_info = {
            "aid": r_aid, 
            "device": r_device, 
            "IP": r_ip, 
            "port": r_port, 
            "pk_prov": self.PK_Prov.public_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PublicFormat.Raw)
        }
        dev_info_sig_bytes = r_agent_material.get("dev_info_sig")

        logger.log("CRYPTO", f"Verifying {r_aid} device information.")
        try:
            pk_u.verify(
                dev_info_sig_bytes,
                str(dev_info).encode("utf-8")
            )
        except:
            logger.error(f"{r_aid} DEVICE VERIFICATION FAILED. UNSAFE CONNECTION.")
            return

        # ========================================================================
        # If no signature verification fails, that means that the receiving agent's 
        # information is legitimate. The initiating agent can request a connection 
        # to the receiving agent.
        # ========================================================================
        
        # Create SSL context for the client
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2  # TLS 1.3 only
        # Load the self-signed certificate and private key
        context.load_cert_chain(certfile=self.workdir + "agent.crt", keyfile=self.workdir + "agent.key")
        # Load the CA certificate for verification:    
        context.load_verify_locations(saga.config.CA_CERT_PATH)


        try:
            # Create and connect the socket
            with socket.create_connection((r_ip, r_port)) as sock:
                with context.wrap_socket(sock, server_hostname=r_aid) as conn:
                    logger.log("NETWORK", f"Connected to {r_ip}:{r_port} with verified certificate.")

                    # Prepare the request:
                    request_dict = {}
                    request_dict['aid'] = self.aid # The initiating agent's ID

                    # Check if you have a token:
                    token = self.retrieve_valid_token(r_aid)
                    if token is None:
                        # If no token is found, the initiating agent must 
                        # receive a new one from the receiving agent.
                        # == X3DH protocol is used for token generation ==
                        logger.log("ACCESS", f"No valid received token found for {r_aid}. Will request new one.")
                        # Generate ephemeral keys:
                        sek, ek = sc.generate_x25519_keypair()
                        # and use one of the receiving agent's one-time pre-keys:
                        r_opk = r_agent_material.get("one_time_pre_keys", None)[0]

                        # Prepare JSON message
                        request_dict['ek'] = base64.b64encode(ek.public_bytes(
                            encoding=sc.serialization.Encoding.Raw,
                            format=sc.serialization.PublicFormat.Raw
                        )).decode("utf-8")
                        request_dict['opk'] = base64.b64encode(r_opk).decode("utf-8")
                    else:
                        # If a token is found, the initiating agent can send 
                        # it to the receiving agent.                        
                        request_dict['token'] = token
                        
                    # Encode the request as JSON
                    request_json = json.dumps(request_dict).encode('utf-8')
                    # Send JSON request
                    conn.sendall(request_json)

                    # Receive response
                    response = conn.recv(MAX_BUFFER_SIZE)
                    if token is None and response:
                        # If no valid token was found, the expected response is a token.
                        response_dict = json.loads(response.decode('utf-8'))
                        
                        # Diffie hellman calculations:
                        # DH1 :
                        r_spk_bytes = r_agent_material.get("signed_pre_key", None) # TODO: VERIFY ITS SIGNATURE???
                        r_spk = sc.bytesToPublicX25519Key(r_spk_bytes)
                        DH1 = self.secret_identity_key.exchange(r_spk)

                        # DH2 :
                        r_identity_key_bytes = r_agent_material.get("identity_key", None)
                        r_identity_key = sc.bytesToPublicX25519Key(r_identity_key_bytes)
                        DH2 = sek.exchange(r_identity_key)
                        
                        # DH3 :
                        DH3 = sek.exchange(r_spk)

                        # DH4 :
                        r_opk = sc.bytesToPublicX25519Key(r_opk)
                        DH4 = sek.exchange(r_opk)

                        # CONCAT shared secrets
                        shared_secrets = [DH1, DH2, DH3, DH4]
                        concat_secret = b''.join(shared_secrets)

                        SDHK = sc.HKDF(
                            algorithm=sc.hashes.SHA256(),
                            length=32,  # Generate a 256-bit key
                            salt=None,  # Optional: Provide a salt for added security
                            info=b"access-control-shdk-exchange",
                        ).derive(concat_secret)

                        logger.log("ACCESS", f"Derived SDHK: {SDHK.hex()}")

                        # Receive the new token:
                        # The new token that is generated will be received as a string.
                        # This string is an encoding, i.e. an encryption of the token's
                        # metadata.
                        new_enc_token_str = response_dict.get("token", None)
                        logger.log("ACCESS", f"Received token: {new_enc_token_str}")

                        # Decrypt the token:
                        token_dict = sc.decrypt_token(new_enc_token_str, SDHK)
                        # Store the token:
                        self.store_received_token(r_aid, new_enc_token_str, token_dict)
                        
                        # Start the conversation:
                        self.initiate_conversation(conn, new_enc_token_str, message)         
                    else:
                        logger.log("ACCESS", f"Valid token found. Will start conversation.")
                        # If a valid token was found, the expected response is a message.
                        if response:
                            response_dict = json.loads(response.decode('utf-8'))
                            if response_dict["token"] is not None:
                                self.initiate_conversation(conn, token, message)
                            else:
                                logger.error("Token rejected from receiving side.")
                                
                    

        except ssl.SSLError as e:
            print(f"SSL Error: {e}")

        except Exception as e:
            print(f"Error: {e}")
            traceback.print_exc()

        finally:
            try:
                logger.log("NETWORK", "Attempting to close connection.")
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
                logger.log("NETWORK", "Connection succesfully closed.")
            except:
                logger.log("NETWORK", "Connection already closed by other party.")

    def handle_i_agent_connection(self, conn, fromaddr):
        """
        Handles an incoming TLS connection from an intiating agent.
        """
        try:
            logger.log("NETWORK", f"Incoming connection from {fromaddr}.")

            # Receive data
            data = conn.recv(MAX_BUFFER_SIZE)
            if data:
                    try:

                        # Decode and parse JSON data
                        received_msg = json.loads(data.decode('utf-8'))

                        # Extract i_aid:
                        i_aid = received_msg.get("aid", None)

                        # Ask the provider for the details of the initiating agent:
                        logger.log("ACCESS", f"Fetching crypto and device information for {i_aid} from the Provider.")
                        i_agent_material = self.lookup(i_aid)

                        # Perform verification checks:                                
                        if i_agent_material is None:
                            logger.error(f"{i_aid} not found.")
                            raise Exception(f"{i_aid} not found.")
                    

                        # Retrieve user identity key: 
                        pk_u = sc.bytesToPublicEd25519Key(
                            i_agent_material.get("pk_u", None)
                        )
                    
                        # Verify the agent's identity:
                        i_aid = i_agent_material.get("aid", None)
                        i_agent_cert_bytes = i_agent_material.get("agent_cert", None)
                        i_agent_cert = sc.bytesToX509Certificate(
                            i_agent_cert_bytes 
                        )
                        if i_agent_cert is None:
                            logger.error("No valid certificate found.")
                            raise Exception("No valid certificate found.")
                            
                        i_agent_public_signing_key = i_agent_cert.public_key()
                        i_agent_public_signing_key_bytes = i_agent_public_signing_key.public_bytes(
                            encoding=sc.serialization.Encoding.Raw,
                            format=sc.serialization.PublicFormat.Raw
                        )
                        
                        i_agent_identity = {
                            "aid": i_aid,
                            "public_signing_key": i_agent_public_signing_key_bytes,
                            "pk_prov": self.PK_Prov.public_bytes(
                                encoding=sc.serialization.Encoding.Raw,
                                format=sc.serialization.PublicFormat.Raw)
                        }

                        i_public_signing_key_sig_bytes = i_agent_material.get("public_signing_key_sig")
                        logger.log("CRYPTO", f"Verifying {i_aid} identity.")
                        try:
                            pk_u.verify(
                                i_public_signing_key_sig_bytes,
                                str(i_agent_identity).encode("utf-8")
                            )
                        except:
                            logger.error(f"ERROR: {i_aid} IDENTITY VERIFICATION FAILED. UNSAFE CONNECTION.")
                            raise Exception(f"ERROR: {i_aid} IDENTITY VERIFICATION FAILED. UNSAFE CONNECTION.")
                        

                        # Verify the target agent's device information:
                        i_device = i_agent_material.get("device")
                        i_ip = i_agent_material.get("IP")
                        i_port = i_agent_material.get("port")

                        dev_info = {
                            "aid": i_aid, 
                            "device": i_device, 
                            "IP": i_ip, 
                            "port": i_port, 
                            "pk_prov": self.PK_Prov.public_bytes(
                                encoding=sc.serialization.Encoding.Raw,
                                format=sc.serialization.PublicFormat.Raw)
                        }
                        dev_info_sig_bytes = i_agent_material.get("dev_info_sig")

                        logger.log("CRYPTO", f"Verifying {i_aid} device information.")
                        try:
                            pk_u.verify(
                                dev_info_sig_bytes,
                                str(dev_info).encode("utf-8")
                            )
                        except:
                            logger.error(f"ERROR: {i_aid} DEVICE VERIFICATION FAILED. UNSAFE CONNECTION.")
                            raise Exception(f"ERROR: {i_aid} DEVICE VERIFICATION FAILED. UNSAFE CONNECTION.")

                        # ========================================================================
                        # If no signature verification fails, that means that the receiving agent's 
                        # information is legitimate. The initiating agent can request a connection 
                        # to the receiving agent.
                        # ========================================================================

                        # ============================ ACCESS CONTROL ============================

                        # Check if the initiating agent has a token:
                        i_token = received_msg.get("token", None)
                        if i_token is None:
                            # The initiating agent does not have a token. 
                            logger.log("ACCESS", f"No valid received token found. For {i_aid}. Generating new one.")
                            
                            # Verify the agent's SPK:
                            i_spk_bytes = i_agent_material.get("signed_pre_key", None)
                            i_spk_sig_bytes = i_agent_material.get("signed_pre_key_sig", None)

                            pk_u.verify(
                                i_spk_sig_bytes,
                                i_spk_bytes
                            )
                            

                            # The agent must have an EK (ek):
                            i_ek_bytes = base64.b64decode(received_msg.get("ek"))
                            i_ek = sc.bytesToPublicX25519Key(i_ek_bytes)
                            
                            # The agent must have a opk: 
                            i_opk_bytes = base64.b64decode(received_msg.get("opk", None))
                            if i_opk_bytes is None:
                                logger.error("Acces control failed: no opk provided from initiating agent.")
                                raise Exception("Acces control failed: no opk provided.")
                            # Look for the opk-sopk pair in the opks struct:
                            sopk = self.opks_dict[i_opk_bytes] 

                            # Diffie hellman calculations:
                            
                            # DH1 = DH (IK_I, SSPK_R):
                            i_identity_key_bytes = i_agent_material.get("identity_key", None)
                            i_identity_key = sc.bytesToPublicX25519Key(i_identity_key_bytes)
                            DH1 = self.sspk.exchange(i_identity_key)

                            # DH2 :
                            DH2 = self.secret_identity_key.exchange(i_ek)
                            
                            # DH3 :
                            DH3 = self.sspk.exchange(i_ek)

                            # DH4 :
                            DH4 = sopk.exchange(i_ek)
                            
                            # CONCAT shared secrets
                            shared_secrets = [DH1, DH2, DH3, DH4]
                            concat_secret = b''.join(shared_secrets)

                            SDHK = sc.HKDF(
                                algorithm=sc.hashes.SHA256(),
                                length=32,  # Generate a 256-bit key
                                salt=None,  # Optional: Provide a salt for added security
                                info=b"access-control-shdk-exchange",
                            ).derive(concat_secret)

                            logger.log("ACCESS", f"Derived SDHK: {SDHK.hex()}")
                            
                            # Generate the token:
                            enc_token_bytes = self.generate_token(i_identity_key, SDHK)
                            enc_token_str = base64.b64encode(enc_token_bytes).decode('utf-8')
                            token_response = {"token": enc_token_str}
                            logger.log("ACCESS", f"Generated token: {enc_token_str}")

                            ser_token_response = json.dumps(token_response).encode('utf-8')
                            
                            # Store the token:
                            with self.active_tokens_lock:
                                self.active_tokens[enc_token_str] = sc.decrypt_token(enc_token_str, SDHK)

                            conn.sendall(ser_token_response)

                            # Start the conversation:
                            logger.log("AGENT", f"Starting conversation with {i_aid}.")
                            self.receive_conversation(conn, enc_token_str)
                        else:
                            # Check the token and see if it is in the active tokens:
                            if self.token_is_valid(i_token):
                                # If the token is valid, start the conversation:
                                logger.log("ACCESS", f"Valid token found. Will accept conversation.")
                                conn.sendall(json.dumps({"token": i_token}).encode('utf-8'))
                                self.receive_conversation(conn, i_token)
                            else:
                                logger.error("Token is invalid. Ending connection.")

                    except json.JSONDecodeError:
                        print("Received invalid JSON format.")


                    except Exception as e:
                        print(f"Error: {e}")
                        traceback.print_exc()
        finally:
            try:
                logger.log("NETWORK", "Attempting to close connection.")
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
                logger.log("NETWORK", "Connection succesfully closed.")
            except:
                logger.log("NETWORK", "Connection already closed by other party.")

    def listen(self):
        """
        Listens for incoming TLS connections, handles Ctrl+C gracefully,
        and ensures proper socket closure on shutdown.
        """
        # Create SSL context for the server
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2  # TLS 1.3 only
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(saga.config.CA_CERT_PATH)
        # Load the self-signed certificate and private key
        context.load_cert_chain(certfile=self.workdir + "agent.crt", keyfile=self.workdir + "agent.key")

        # Create and bind the socket
        bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bindsocket.bind((self.IP, int(self.port)))
        bindsocket.listen(5)

        logger.log("NETWORK", f"Listening on {self.IP}:{self.port}... (Press Ctrl+C to stop)")

        try:
            while True:
                try:
                    # Incoming connection:
                    newsocket, fromaddr = bindsocket.accept()
                    # TLS takes over and tries to
                    conn = context.wrap_socket(newsocket, server_side=True)
                    logger.log("NETWORK", f"Connection from {fromaddr}")
                    # Spawn a new thread to handle the incoming connection:
                    i_agent_thread = threading.Thread(target=self.handle_i_agent_connection, args=(conn, fromaddr))
                    i_agent_thread.daemon = True  # Daemon mode: Exits when main thread ends
                    i_agent_thread.start()

                except KeyboardInterrupt:
                    print("\nReceived Ctrl+C, shutting down server gracefully...")
                    break
        finally:
            bindsocket.close()
            print("Server socket closed. Exiting.")