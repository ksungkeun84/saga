import requests
import base64
import saga.config
import saga.crypto as sc
from saga.ca.CA import get_SAGA_CA
import os
import json

# Instanciate the CA object:
CA = get_SAGA_CA()

# Provider state:
# Open tls/localhost.crt and read the Provider public key
PROVIDER_CERT = sc.load_x509_certificate(saga.config.PROVIDER_CERT_PATH)
# Verify the provider certificate:
CA.verify(PROVIDER_CERT) # if the verification fails an exception will be raised.
PIK = PROVIDER_CERT.public_key()

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
    # Generate user identity key pair:
    private_key, public_key = sc.generate_ed25519_keypair()

    response = requests.post(f"{saga.config.PROVIDER_URL}/register", json={
        'uid': email, # uid
        'password': password, # pwd 
        # CRYPTOGRAPHIC MATERIAL TO SUBMIT TO THE PROVIDER:
        # - PUBLIC IDENTITY KEY OF USER FOR SIGNING
        'identity_key': base64.b64encode(public_key.public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw
        )).decode("utf-8")
    }, verify=saga.config.CA_CERT_PATH)
    print(response.json())
    if response.status_code == 201:
        # Store the uid:
        state['uid'] = email
        # Store the key pair:
        state['keys']['identity'] = {
            'public': public_key,
            'private': private_key
        }
        # Save the keys to disk:
        sc.save_ed25519_keys(saga.config.USER_WORKDIR+"/keys/"+email, private_key, public_key)


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
        private_key, public_key = sc.load_ed25519_keys("./keys/"+email)
        state['keys']['identity'] = {
            'public': public_key,
            'private': private_key
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
    num_one_time_pre = int(input("Enter number of one-time prekeys: "))

    # Assign the aid:
    aid = state['uid'] + ":" + name

    # Generate the device info:
    dev_info = {
        "aid":aid, 
        "device":device, 
        "IP":IP, 
        "port":port, 
        "pik": PIK.public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw)
    }
    dev_info_sig = state['keys']['identity']['private'].sign(str(dev_info).encode("utf-8"))

    # Generate TLS signing keys for the Agent:
    private_signing_key, public_signing_key = sc.generate_ed25519_keypair() # SK_A, PK_A

    # Generate the certificate of the Agent for TLS communication:
    custom_agent_config = saga.config.AGENT_DEFAULT_CONFIG.copy()
    custom_agent_config["COMMON_NAME"] = aid
    custom_agent_config["IP"] = IP
    agent_cert = CA.sign(
        public_key=public_signing_key, # PK_A
        config=custom_agent_config
    )


    agent_identity = {
        "aid":aid,
        "public_signing_key":public_signing_key.public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw),
        "pik": PIK.public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw)
    }
    agent_identity_sig = state['keys']['identity']['private'].sign(str(agent_identity).encode("utf-8"))

    # -- ACCESS CONTROL KEYS -- :
    # Generate Agent Identity Key Pair:
    private_identity_key, public_identity_key = sc.generate_x25519_keypair()
    # Generate Signed Pre-Keys:
    private_signed_prekey, public_signed_prekey = sc.generate_x25519_keypair()
    # --> Sign the public pre-key:
    spk_sig = state['keys']['identity']['private'].sign(public_signed_prekey.public_bytes(
        encoding=sc.serialization.Encoding.Raw,
        format=sc.serialization.PublicFormat.Raw)
    )
    # Generate One-Time Pre-Keys:
    private_one_time_prekeys = []
    public_one_time_prekeys = []
    for _ in range(num_one_time_pre):
        private_one_time_prekey, public_one_time_prekey = sc.generate_x25519_keypair()
        private_one_time_prekeys.append(private_one_time_prekey)
        public_one_time_prekeys.append(public_one_time_prekey)

    public_one_time_prekeys_2_b64 = [base64.b64encode(key.public_bytes(
        encoding=sc.serialization.Encoding.Raw,
        format=sc.serialization.PublicFormat.Raw)).decode("utf-8") for key in public_one_time_prekeys]

    private_one_time_prekeys_2_b64 = [base64.b64encode(key.private_bytes(
        encoding=sc.serialization.Encoding.Raw,
        format=sc.serialization.PrivateFormat.Raw,
        encryption_algorithm=sc.serialization.NoEncryption())).decode("utf-8") for key in private_one_time_prekeys]



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
        # The signature of the device info (aid, device, IP, port, PIK)
        'dev_info_sig': base64.b64encode(dev_info_sig).decode("utf-8"),
        
        # The public TLS signing key of the agent # PK!!!!!! TODO: UPDATE TO CERTIFICATE
        # 'public_signing_key': base64.b64encode(public_signing_key.public_bytes(
        #     encoding=sc.serialization.Encoding.Raw,
        #     format=sc.serialization.PublicFormat.Raw)).decode("utf-8"),
        
        # The agent certificate containing the agent's public_signing_key
        'agent_cert': base64.b64encode(
            agent_cert.public_bytes(sc.serialization.Encoding.PEM)
        ).decode("utf-8"),
        # and its signature = sign_{user_secret_identity_key}(aid, public_signing_key, PIK)
        'public_signing_key_sig': base64.b64encode(agent_identity_sig).decode("utf-8"),
        
        # Agent Identity Key (IK):
        'identity_key': base64.b64encode(public_identity_key.public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw)).decode("utf-8"),

        # Access Control Keys:
        # The public signed prekey of the agent
        'spk': base64.b64encode(public_signed_prekey.public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw)).decode("utf-8"),
        # and its signature
        'spk_sig': base64.b64encode(spk_sig).decode("utf-8"),
        # batch of public one-time prekeys
        'opks': public_one_time_prekeys_2_b64
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
                'public': public_signing_key,
                'private': private_signing_key
            },
            'identity_key': {
                'public': public_identity_key,
                'private': private_identity_key
            },
            'signed_prekey': {
                'public': public_signed_prekey,
                'private': private_signed_prekey
            },
            'one_time_prekeys': [list(zip(private_one_time_prekeys, public_one_time_prekeys))],
        }
        # Spawn Agent with the given material:
        
        application.update({
            "private_signing_key": base64.b64encode(private_signing_key.private_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PrivateFormat.Raw,
                encryption_algorithm=sc.serialization.NoEncryption()
            )).decode("utf-8"),
            "secret_identity_key": base64.b64encode(private_identity_key.private_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PrivateFormat.Raw,
                encryption_algorithm=sc.serialization.NoEncryption()
            )).decode("utf-8"),
            "sspk": base64.b64encode(private_signed_prekey.private_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PrivateFormat.Raw,
                encryption_algorithm=sc.serialization.NoEncryption()
            )).decode("utf-8"),
            "sopks": private_one_time_prekeys_2_b64,
            "pik": base64.b64encode(PIK.public_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PublicFormat.Raw
            )).decode("utf-8")
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

    # TODO: start the agent process? 

if __name__ == "__main__":

    while True:
        print("1. Register\n2. Login\n3. Google OAuth Login\n4. Register Agent")
        choice = input("Choose an option: ")

        if choice == '1':
            register()
        elif choice == '2':
            login()
        elif choice == '3':
            oauth_login()
        elif choice == '4':
            register_agent()
