import json
import os
import bson.json_util
import socket
import ssl
import base64
import requests
import saga.config

DEBUG = False

""""

Agent class for the SAGA system.

"""
import saga.crypto as sc

class LocalAent:
    
    def __init__(self, agent):
        self.agent = agent

    def query(self, query):
        pass

class Agent:

    def fromDir(agent_dir_path):

        # Check if dir exists:
        if not os.path.exists(agent_dir_path):
            os.mkdir(agent_dir_path)

        # Open agent.json
        if agent_dir_path[-1] != '/':
            agent_dir_path += "/"

        material = None
        with open(agent_dir_path+"agent.json", "r") as f:
            material = json.load(f)
    
        return Agent(agent_dir_path, material)


    def __init__(self, workdir, material):

        self.workdir = workdir
        if self.workdir[-1] != '/':
            self.workdir += '/'

        self.agent = None # library-agnostic agent object
        
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
            print(data)
            return data
        else:
            print(response.json())
            return None

    def send_hello(self):
        # Create SSL context for the client
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2  # TLS 1.3 only
        # Load the self-signed certificate and private key
        context.load_cert_chain(certfile=self.workdir + "agent.crt", keyfile=self.workdir + "agent.key")
        # Load the CA certificate for verification:    
        context.load_verify_locations(saga.config.CA_CERT_PATH)

        try:
            # Create and connect the socket
            with socket.create_connection(("127.0.0.1", 6000)) as sock:
                with context.wrap_socket(sock, server_hostname="geo2001s@gmail.com:astro") as conn:
                    print(f"Connected to 127.0.0.1:6000 with verified certificate")

                    # Prepare JSON message
                    request_dict = {"message": "Hello, Server!"}
                    request_json = json.dumps(request_dict).encode('utf-8')

                    # Send JSON request
                    conn.sendall(request_json)
                    print(f"Sent JSON: {request_json}")

                    # Receive response
                    response = conn.recv(1024)
                    if response:
                        response_dict = json.loads(response.decode('utf-8'))
                        print(f"Received JSON: {response_dict}")

        except ssl.SSLError as e:
            print(f"SSL Error: {e}")

        except Exception as e:
            print(f"Error: {e}")
    
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
                    newsocket, fromaddr = bindsocket.accept()
                    conn = context.wrap_socket(newsocket, server_side=True)
                    try:
                        print(f"Connection from {fromaddr}")

                        # Receive data
                        data = conn.recv(1024)
                        if data:
                            try:
                                # Decode and parse JSON data
                                received_dict = json.loads(data.decode('utf-8'))
                                print(f"Received JSON: {received_dict}")

                                # Prepare JSON response
                                response_dict = {"message": "Hello, World!"}
                                response_json = json.dumps(response_dict).encode('utf-8')

                                # Send JSON response
                                conn.sendall(response_json)
                                print(f"Sent JSON: {response_json}")

                            except json.JSONDecodeError:
                                print("Received invalid JSON format.")
                                error_response = json.dumps({"error": "Invalid JSON format"}).encode('utf-8')
                                conn.sendall(error_response)

                    except Exception as e:
                        print(f"Error: {e}")

                    finally:
                        conn.shutdown(socket.SHUT_RDWR)
                        conn.close()

                except KeyboardInterrupt:
                    print("\nReceived Ctrl+C, shutting down server gracefully...")
                    break
        finally:
            bindsocket.close()
            print("Server socket closed. Exiting.")