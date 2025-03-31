import socket
import ssl
import requests
import base64
import saga.config
import saga.crypto as sc
from saga.ca.CA import get_SAGA_CA
import os
import json


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

# Instanciate the CA object:
CA = get_SAGA_CA()

# Provider state:
# Open tls/localhost.crt and read the Provider public key
PROVIDER_CERT = get_provider_cert()
# Verify the provider certificate:
CA.verify(PROVIDER_CERT) # if the verification fails an exception will be raised.
PK_Prov = PROVIDER_CERT.public_key()

# User state:
provider_tokens = []
uid = None
state = {}
state['keys'] = {}
state['agents'] = {}


def register():
    email = input("Enter email: ")
    password = input("Enter password: ")

    print("Generating cryptographic material...")
    # Generate user signing key pair:
    sk_u, pk_u = sc.generate_ed25519_keypair()

    # Generate user certificate:
    custom_user_config = saga.config.USER_DEFAULT_CONFIG.copy()
    custom_user_config["COMMON_NAME"] = email
    user_cert = CA.sign(
        public_key=pk_u, # PK_U 
        config=custom_user_config
    )

    response = requests.post(f"{saga.config.PROVIDER_URL}/register", json={
        'uid': email, # uid
        'password': password, # pwd 
        # CRYPTOGRAPHIC MATERIAL TO SUBMIT TO THE PROVIDER:
        # - USER CERTIFICATE
        'crt_u': base64.b64encode(
            user_cert.public_bytes(sc.serialization.Encoding.PEM)
        ).decode("utf-8")
    }, verify=saga.config.CA_CERT_PATH)
    print(response.json())
    if response.status_code == 201:
        # Store the uid:
        state['uid'] = email
        # Store the key pair:
        state['keys']['signing'] = {
            'public': pk_u,
            'private': sk_u
        }
        # Save the keys to disk:
        if not os.path.exists(saga.config.USER_WORKDIR+"/keys"):
            os.mkdir(saga.config.USER_WORKDIR+"/keys")
        sc.save_ed25519_keys(saga.config.USER_WORKDIR+"/keys/"+email, sk_u, pk_u)
        sc.save_x509_certificate(saga.config.USER_WORKDIR+"/keys/"+email, user_cert)

def login():
    email = input("Enter email: ")
    password = input("Enter password: ")

    response = requests.post(f"{saga.config.PROVIDER_URL}/login", json={'uid': email, 'password': password}, verify=saga.config.CA_CERT_PATH) 
    if response.status_code == 200:
        token = response.json().get("access_token")
        print("Login successful. Token:", token)
        provider_tokens.append(token)
        state["uid"] = email
        # Load the keys from disk:
        sk_u, pk_u = sc.load_ed25519_keys("./keys/"+email)
        state['keys']['signing'] = {
            'public': pk_u,
            'secret': sk_u
        }
        return token
    else:
        print(response.json())
        return None

def oauth_login():
    print("Open the following URL in a browser to authenticate via Google:")
    print(f"{saga.config.PROVIDER_URL}/oauth_login")

def register_agent():
    
    name = input("Enter agent name: ")
    device = input("Enter device name: ")
    IP = input("Enter IP address: ")
    port = input("Enter port: ")
    num_one_time_keys = int(input("Enter number of one-time access keys: "))

    # Assign the aid:
    aid = state['uid'] + ":" + name

    # Generate the device info:
    dev_network_info = {
        "aid":aid, 
        "device":device, 
        "IP":IP, 
        "port":port
    }

    # Generate TLS signing keys for the Agent:
    sk_a, pk_a = sc.generate_ed25519_keypair() # SK_A, PK_A

    # Generate the certificate of the Agent for TLS communication:
    custom_agent_config = saga.config.AGENT_DEFAULT_CONFIG.copy()
    custom_agent_config["COMMON_NAME"] = aid
    custom_agent_config["IP"] = IP
    agent_cert = CA.sign(
        public_key=pk_a, # PK_A
        config=custom_agent_config
    )

    # -- ACCESS CONTROL KEYS -- :
    # Generate long term Access Control Key Pair:
    sac, pac = sc.generate_x25519_keypair()
    crypto_info = {
        "pk_a":pk_a.public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw),
        "pac":pac.public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw),
        "pk_prov": PK_Prov.public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw)
    }

    # Generate One-Time Keys:
    private_one_time_keys = []
    public_one_time_keys = []
    for _ in range(num_one_time_keys):
        private_one_time_key, public_one_time_key = sc.generate_x25519_keypair()
        private_one_time_keys.append(private_one_time_key)
        public_one_time_keys.append(public_one_time_key)

    public_one_time_keys_2_b64 = [base64.b64encode(key.public_bytes(
        encoding=sc.serialization.Encoding.Raw,
        format=sc.serialization.PublicFormat.Raw)).decode("utf-8") for key in public_one_time_keys]

    private_one_time_keys_2_b64 = [base64.b64encode(key.private_bytes(
        encoding=sc.serialization.Encoding.Raw,
        format=sc.serialization.PrivateFormat.Raw,
        encryption_algorithm=sc.serialization.NoEncryption())).decode("utf-8") for key in private_one_time_keys]

    # -- SIGNATURE GENERATIONS -- :
    # Generate the agent signature:
    block = {}
    block.update(dev_network_info)
    block.update(crypto_info)
    agent_sig = state['keys']['signing']['secret'].sign(str(block).encode("utf-8"))

    # Generate the signature of every OTK with the user's secret signing key:
    otk_sigs_2_b64 = []
    for key in public_one_time_keys:
        sig = state['keys']['signing']['secret'].sign(
            key.public_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PublicFormat.Raw
            )
        )
        otk_sigs_2_b64.append(base64.b64encode(sig).decode("utf-8"))


    # Collect all the required material for the agent registration application:
    application = {
        # The agent's AID
        'aid': aid, 
        # The agent's device name
        'device': device,
        # The host device IP address
        'IP': IP,
        # The host device port
        'port': port,
        # The agent certificate containing the agent's public signing key
        'agent_cert': base64.b64encode(
            agent_cert.public_bytes(sc.serialization.Encoding.PEM)
        ).decode("utf-8"),
        # Public Access Control Key (PAC):
        'pac': base64.b64encode(pac.public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw)).decode("utf-8"),
        # batch of public one-time keys
        'otks': public_one_time_keys_2_b64,
        # SIGNATURES:
        'agent_sig': base64.b64encode(agent_sig).decode("utf-8"), # Agent signature
        # and their corresponding signatures
        'otk_sigs': otk_sigs_2_b64, 
    }

    response = requests.post(f"{saga.config.PROVIDER_URL}/register_agent", json={
        'uid': state['uid'], # The user's uid
        'jwt': provider_tokens[-1], # Provider's JWT
        'application': application
    }, verify=saga.config.CA_CERT_PATH)

    # Based on the provider's response, store the agent's cryptographic material
    if response.status_code == 201:  
        # Save the agent's cryptographic material
        print(f"Agent {name} registered successfully.")  
        state['agents'][name]= {
            'signing_key': {
                'public': pk_a,
                'secret': sk_a
            },
            'access_control': {
                'public': pac,
                'private': sac
            },
            'one_time_keys': [list(zip(private_one_time_keys, public_one_time_keys))],
        }
        # Spawn Agent with the given material:
        
        application.update({
            "secret_signing_key": base64.b64encode(sk_a.private_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PrivateFormat.Raw,
                encryption_algorithm=sc.serialization.NoEncryption()
            )).decode("utf-8"),
            "sac": base64.b64encode(sac.private_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PrivateFormat.Raw,
                encryption_algorithm=sc.serialization.NoEncryption()
            )).decode("utf-8"),
            "sotks": private_one_time_keys_2_b64
        })
        spawn_agent(application)
    else:
        print(response.json())

def spawn_agent(application):
    # Create agent directory if not exists:
    agent_dir_path = f"./{application.get('aid')}"
    if not os.path.exists(agent_dir_path):
        os.mkdir(agent_dir_path)

    # Dump application material in json format:
    with open(agent_dir_path+"/agent.json", "w") as f:
        json.dump(application, f, indent=4)

    # TODO: Start the agent process with the given material.
    # For now, this will be done manually from the dev.

if __name__ == "__main__":

    while True:
        print("======= SAGA User Client CLI =======")
        print("1. Register\n2. Login\n3. Google OAuth Login\n4. Register Agent\n5. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            register()
        elif choice == '2':
            login()
        elif choice == '3':
            oauth_login()
        elif choice == '4':
            register_agent()
        elif choice == '5':
            print("Exiting...")
            exit(0)
