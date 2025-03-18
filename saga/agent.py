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

DEBUG = False
MAX_BUFFER_SIZE = 4096

""""

Agent class for the SAGA system.

"""
import saga.crypto as sc


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
    def __init__(self):
        self.task_finished_token = "<TASK_FINISHED>"

    def run(self):
        return "I love apples"


class Agent:
    def __init__(self, workdir, material, local_agent = None):

        self.workdir = workdir
        if self.workdir[-1] != '/':
            self.workdir += '/'

        # library-agnostic agent object
        self.local_agent = local_agent
        if local_agent is None:
            print("WARNING: No local agent provided. Using dummy agent.")
            self.local_agent = DummyAgent()

        self.task_finished_token = self.local_agent.task_finished_token

        self.aid = material.get("aid")
        self.device = material.get("device")
        self.IP = material.get("IP")
        self.port = material.get("port")

        # Provider Identity
        self.PIK = sc.bytesToPublicEd25519Key(
            base64.b64decode(material.get("pik"))
        )

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

        self.active_tokens = {}

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
        communication_quota = 10  # Example quota

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

    def token_is_valid(self, token) -> bool:
        if token not in self.active_tokens.keys():
            print("Token not found.")
            return False
        # Check if the token is still valid:
        token_dict = self.active_tokens[token]
        
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

    def initiate_conversation(self, conn, token, init_msg: str):
        MAX_YAP = 5
        text = init_msg
        while MAX_YAP > 0:
            # Prepare message: 
            msg = {
                "msg": text,
                "token": token
            }
            # Send message:
            conn.sendall(json.dumps(msg).encode('utf-8'))
            print(f"Sent: {msg['msg']}")
            # Receive response:
            response = conn.recv(MAX_BUFFER_SIZE) # TODO: vary buffer size depending on how long the LLM answers are going to be
            response = json.loads(response.decode('utf-8'))
            # Process response:
            print(f"Received: {response['msg']}")
            text = self.local_agent.run(str(response.get("msg", None))) # TODO: Handle None (missing) msg gracefully

            if text == self.task_finished_token:
                print("Task finished.")
                break

            # text = None if len(convo) == 0 else convo.pop() # Model conversation    
            MAX_YAP -= 1

    def receive_conversation(self, conn, token):
        while True: 
            
            # Receive message:
            message = conn.recv(MAX_BUFFER_SIZE) # TODO: vary buffer size depending on how long the LLM answers are going to be
            if message != b'':
                message = json.loads(message.decode('utf-8'))
            else:
                break
            
            # Extract token from the message:
            token = message.get("token", None)
            # Check if the token of the message is valid
            if not self.token_is_valid(token):
                break
            # Reduce the remaining quota for the token:
            self.active_tokens[token]["communication_quota"] = max(0, self.active_tokens[token]["communication_quota"] - 1)
            
            # Process message:
            print(f"Received: {message['msg']}")

            if message['msg'] == self.task_finished_token:
                print("Task finished.")
                break

            response = self.local_agent.run(str(message.get("msg", None))) # TODO: Handle None (missing) msg gracefully
            if response == self.task_finished_token:
                print("Task finished.")
                break

            # Prepare response:
            response_dict = {
                "msg": response,
                "token": token
            }
            # Send response:
            conn.sendall(json.dumps(response_dict).encode('utf-8'))
            print(f"Sent: {response_dict['msg']}")

    def connect(self, r_aid, message: str):

        # Get everything you need to reach the receiving agent from the provider:
        r_agent_material = self.access(r_aid)

        if r_agent_material is None:
            return

        # ========================================================================
        # Perform verification checks for integrity purposes before connecting to 
        # the receiving agent.
        # ========================================================================    

        # Retrieve user identity key: 
        user_identity_key = sc.bytesToPublicEd25519Key(
            r_agent_material.get("user_identity_key", None)
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
            "pik": self.PIK.public_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PublicFormat.Raw)
        }

        r_public_signing_key_sig_bytes = r_agent_material.get("public_signing_key_sig")

        try:
            user_identity_key.verify(
                r_public_signing_key_sig_bytes,
                str(r_agent_identity).encode("utf-8")
            )
        except:
            print(f"ERROR: {r_aid} IDENTITY VERIFICATION FAILED. UNSAFE CONNECTION.")
        

        # Verify the target agent's device information:
        r_device = r_agent_material.get("device")
        r_ip = r_agent_material.get("IP")
        r_port = r_agent_material.get("port")

        dev_info = {
            "aid": r_aid, 
            "device": r_device, 
            "IP": r_ip, 
            "port": r_port, 
            "pik": self.PIK.public_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PublicFormat.Raw)
        }
        dev_info_sig_bytes = r_agent_material.get("dev_info_sig")

        try:
            user_identity_key.verify(
                dev_info_sig_bytes,
                str(dev_info).encode("utf-8")
            )
        except:
            print(f"ERROR: {r_aid} DEVICE VERIFICATION FAILED. UNSAFE CONNECTION.")

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
                    print(f"Connected to {r_ip}:{r_port} with verified certificate")

                    # else generate ephemeral key:
                    sek, ek = sc.generate_x25519_keypair()
                    # and use one of the receiving agent's one-time pre-keys:
                    r_opk = r_agent_material.get("one_time_pre_keys", None)[0]

                    # Prepare JSON message
                    request_dict = {
                        "aid": self.aid,
                        "ek": base64.b64encode(ek.public_bytes(
                            encoding=sc.serialization.Encoding.Raw,
                            format=sc.serialization.PublicFormat.Raw
                        )).decode("utf-8"),
                        "opk": base64.b64encode(r_opk).decode("utf-8")
                    }
                    request_json = json.dumps(request_dict).encode('utf-8')

                    # Send JSON request
                    conn.sendall(request_json)

                    # Receive response
                    response = conn.recv(MAX_BUFFER_SIZE)
                    if response:
                        accept_response = json.loads(response.decode('utf-8'))
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

                        # Receive token:
                        enc_token_str = accept_response.get("token", None)
                        # Decrypt the token (testing purposes):
                        # token_dict = self.decrypt_token(token, SDHK)
                        
                        # Start the conversation:
                        self.initiate_conversation(conn, enc_token_str, message)

        except ssl.SSLError as e:
            print(f"SSL Error: {e}")

        except Exception as e:
            print(f"Error: {e}")

        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
                print(f"Conversation ended.")
            except:
                print("Connection already closed by other party.")

    def handle_i_agent_connection(self, conn, fromaddr):
        """
        Handles an incoming TLS connection from an intiating agent.
        """
        try:
            print(f"Connection from {fromaddr}")

            # Receive data
            data = conn.recv(MAX_BUFFER_SIZE)
            if data:
                    try:

                        # Decode and parse JSON data
                        received_msg = json.loads(data.decode('utf-8'))

                        # Extract i_aid:
                        i_aid = received_msg.get("aid", None)

                        # Ask the provider for the details of the initiating agent:
                        i_agent_material = self.lookup(i_aid)

                        # Perform verification checks:                                
                        if i_agent_material is None:
                            print(f"{i_aid} not found.")
                            conn.close()
                            return
                    

                        # Retrieve user identity key: 
                        user_identity_key = sc.bytesToPublicEd25519Key(
                            i_agent_material.get("user_identity_key", None)
                        )
                    
                        # Verify the agent's identity:
                        i_aid = i_agent_material.get("aid", None)
                        i_agent_cert_bytes = i_agent_material.get("agent_cert", None)
                        i_agent_cert = sc.bytesToX509Certificate(
                            i_agent_cert_bytes 
                        )
                        if i_agent_cert is None:
                            print("No valid certificate found.")
                            return
                        i_agent_public_signing_key = i_agent_cert.public_key()
                        i_agent_public_signing_key_bytes = i_agent_public_signing_key.public_bytes(
                            encoding=sc.serialization.Encoding.Raw,
                            format=sc.serialization.PublicFormat.Raw
                        )
                        
                        i_agent_identity = {
                            "aid": i_aid,
                            "public_signing_key": i_agent_public_signing_key_bytes,
                            "pik": self.PIK.public_bytes(
                                encoding=sc.serialization.Encoding.Raw,
                                format=sc.serialization.PublicFormat.Raw)
                        }

                        i_public_signing_key_sig_bytes = i_agent_material.get("public_signing_key_sig")

                        try:
                            user_identity_key.verify(
                                i_public_signing_key_sig_bytes,
                                str(i_agent_identity).encode("utf-8")
                            )
                        except:
                            print(f"ERROR: {i_aid} IDENTITY VERIFICATION FAILED. UNSAFE CONNECTION.")
                        

                        # Verify the target agent's device information:
                        i_device = i_agent_material.get("device")
                        i_ip = i_agent_material.get("IP")
                        i_port = i_agent_material.get("port")

                        dev_info = {
                            "aid": i_aid, 
                            "device": i_device, 
                            "IP": i_ip, 
                            "port": i_port, 
                            "pik": self.PIK.public_bytes(
                                encoding=sc.serialization.Encoding.Raw,
                                format=sc.serialization.PublicFormat.Raw)
                        }
                        dev_info_sig_bytes = i_agent_material.get("dev_info_sig")

                        try:
                            user_identity_key.verify(
                                dev_info_sig_bytes,
                                str(dev_info).encode("utf-8")
                            )
                        except:
                            print(f"ERROR: {i_aid} DEVICE VERIFICATION FAILED. UNSAFE CONNECTION.")

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
                            
                            # Verify the agent's SPK:
                            i_spk_bytes = i_agent_material.get("signed_pre_key", None)
                            i_spk_sig_bytes = i_agent_material.get("signed_pre_key_sig", None)

                            user_identity_key.verify(
                                i_spk_sig_bytes,
                                i_spk_bytes
                            )
                            

                            # The agent must have an EK (ek):
                            i_ek_bytes = base64.b64decode(received_msg.get("ek"))
                            i_ek = sc.bytesToPublicX25519Key(i_ek_bytes)
                            
                            # The agent must have a opk: 
                            i_opk_bytes = base64.b64decode(received_msg.get("opk", None))
                            if i_opk_bytes is None:
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
                            
                            # Generate the token:
                            enc_token_bytes = self.generate_token(i_identity_key, SDHK)
                            enc_token_str = base64.b64encode(enc_token_bytes).decode('utf-8')
                            token_response = {"token": enc_token_str}

                            ser_token_response = json.dumps(token_response).encode('utf-8')
                            
                            # Store the token:
                            self.active_tokens[enc_token_str] = json.loads(sc.decrypt_token(enc_token_str, SDHK))

                            conn.sendall(ser_token_response)

                            # Start the conversation:
                            self.receive_conversation(conn, enc_token_str)

                        else:
                            # Check the token and see if it is in the firt
                            # if i_token in self.active_tokens.keys():
                            #     conn.shutdown(socket.SHUT_RDWR)
                            #     conn.close()
                            raise Exception("EXISTING TOKEN LOGIC NOT IMPLEMENTED.")

                    except json.JSONDecodeError:
                        print("Received invalid JSON format.")


                    except Exception as e:
                        print(f"Error: {e}")
                        traceback.print_exc()

            print(f"Connection from {fromaddr} closed.")
        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
                print(f"Conversation ended.")
            except:
                print("Connection already closed by other party.")

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

        print(f"Listening on {self.IP}:{self.port}... (Press Ctrl+C to stop)")

        try:
            while True:
                try:
                    # Incoming connection:
                    newsocket, fromaddr = bindsocket.accept()
                    # TLS takes over and tries to
                    conn = context.wrap_socket(newsocket, server_side=True)

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