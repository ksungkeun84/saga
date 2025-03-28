"""
    SAGA Cryptographic module for key generation.
"""

import base64
import ipaddress
import json
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography import x509
import datetime

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def cure(path):
    return path if path[-1]=='/' else path+"/"

def generate_ed25519_keypair():
    """
    Generate a public-private keypair using the ed25519 algorithm.
    """

    # Generate Ed25519 Private Key (for signing)
    ed25519_private_key = ed25519.Ed25519PrivateKey.generate()

    # Extract Ed25519 Public Key
    ed25519_public_key = ed25519_private_key.public_key()

    return ed25519_private_key, ed25519_public_key

def bytesToPublicEd25519Key(key_bytes):
    """
    Convert bytes to an Ed25519 Public key
    """
    return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)

def bytesToPrivateEd25519Key(key_bytes):
    """
    Convert bytes to an Ed25519 Private key
    """
    return ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)

def generate_x25519_keypair():
    """
    Generate a public-private keypair using the x25519 algorithm.
    """

    # Generate
    x25519_private_key = x25519.X25519PrivateKey.generate()
    x25519_public_key = x25519_private_key.public_key()
    return x25519_private_key, x25519_public_key

def bytesToPublicX25519Key(key_bytes):
    """
    Convert bytes to an X25519 Public key
    """
    return x25519.X25519PublicKey.from_public_bytes(key_bytes)

def bytesToPrivateX25519Key(key_bytes):
    """
    Convert bytes to an X25519 Public key
    """
    return x25519.X25519PrivateKey.from_private_bytes(key_bytes)

def sign_message(ed25519_private_key, message):
    """
    Sign a message using the Ed25519 private key.
    """

    # Sign the Message Using the Ed25519 Private Key
    signature = ed25519_private_key.sign(
        message.encode("utf-8")
    )
    return message, signature

def verify_signature(ed25519_public_key, message, signature):
    """
    Verify a signature using the Ed25519 public key.
    """

    # Verify the Signature Using the Ed25519 Public Key
    try:
        ed25519_public_key.verify(
            signature,
            message.encode("utf-8")
        )
        return True
    except:
        return False

def derive_x25519_keypair(ed25519_private_key):
    
    # Convert Ed25519 Key to X25519 Key (for Diffie-Hellman Key Exchange)
    # XEdDSA allows deriving an X25519 key from an Ed25519 key.
    x25519_private_key = x25519.X25519PrivateKey.from_private_bytes(
        ed25519_private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    )
    x25519_public_key = x25519_private_key.public_key()

    return x25519_private_key, x25519_public_key

def save_ed25519_keys(name, ed25519_private_key, ed25519_public_key):

    # Save the Ed25519 Private Key
    with open(f"{name}.key", "wb") as f:
        f.write(ed25519_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save the Ed25519 Public Key
    with open(f"{name}.pub", "wb") as f:
        f.write(ed25519_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return f"{name}.key", f"{name}.pub"

def load_ed25519_keys(name):
    # Load the Ed25519 Private Key
    with open(f"{name}.key", "rb") as f:
        ed25519_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    # Extract the Ed25519 Public Key
    ed25519_public_key = ed25519_private_key.public_key()

    return ed25519_private_key, ed25519_public_key

def save_x25519_keys(name, x25519_private_key, x25519_public_key):

    # Save the X25519 Public Key (for Diffie-Hellman Key Exchange)
    with open(f"{name}.pub", "wb") as f:
        f.write(x25519_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ))

    # Save the X25519 Private Key (optional, for DH key exchange)
    with open(f"{name}.key", "wb") as f:
        f.write(x25519_private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ))

def generate_x509_certificate(config, public_key, ca_private_key, ca_certificate):
    """
    Generates an X.509 certificate signed by a Certificate Authority (CA).

    :param config: A dictionary containing certificate information (e.g., COUNTRY_NAME).
    :param public_key: The public key associated with the certificate.
    :param ca_private_key: The private key of the Certificate Authority (used for signing).
    :param ca_certificate: The certificate of the Certificate Authority (used as issuer).
    :return: The signed certificate.
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, config.get("COUNTRY_NAME", "US")),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config.get("STATE_NAME", "MA")),
        x509.NameAttribute(NameOID.LOCALITY_NAME, config.get("LOCALITY_NAME", "Boston")),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.get("ORG_NAME", "NDS2 Lab")),
        x509.NameAttribute(NameOID.COMMON_NAME, config.get("COMMON_NAME", "localhost")),
    ])

    
    ip_address = ipaddress.ip_address(config.get("IP", "127.0.0.1"))
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)  # CA is the issuer
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now())
        .not_valid_after(datetime.datetime.now() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)  # Not a CA certificate
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(config.get("COMMON_NAME", "localhost")),  # Ensure localhost is a SAN entry
                x509.IPAddress(ip_address)  # Also include localhost IP
            ]),
            critical=True
        )
        .sign(ca_private_key, algorithm=None)  # Signed by the CA's private key
    )

    return cert

def verify_x509_certificate(certificate, ca_certificate):
    """
    Verify a given certificate using the CA certificate.

    :param certificate: The certificate to verify.
    :param ca_certificate: The CA certificate used for verification.
    :return: True if the certificate is valid, False otherwise.
    """
    
    # Use the CA's public key to verify the certificate's signature
    ca_certificate.public_key().verify(
        certificate.signature,
        certificate.tbs_certificate_bytes,
    )

def generate_self_signed_x509_certificate(config, private_key, public_key):
    """
    Generate a self-signed X.509 certificate using the Ed25519 keypair.
    """

    # Generate a Self-Signed X.509 Certificate Using Ed25519 Key
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, config["COUNTRY_NAME"]),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config["STATE_OR_PROVINCE_NAME"]),
        x509.NameAttribute(NameOID.LOCALITY_NAME, config["LOCALITY_NAME"]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, config["ORGANIZATION_NAME"]),
        x509.NameAttribute(NameOID.COMMON_NAME, config["COMMON_NAME"]),
    ])

    ip_address = ipaddress.ip_address(config["IP"])  
    san = x509.SubjectAlternativeName([
        x509.DNSName(config["COMMON_NAME"]),  # Keep the DNS name
        x509.IPAddress(ip_address)  # Add IP address to certificate
    ])

    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now()
    ).not_valid_after(
        datetime.datetime.now() + datetime.timedelta(days=365)
    ).add_extension(
        san, critical=False # Add SAN extension
    ).sign(
        private_key,  # Self-signing with the Ed25519 private key
        algorithm=None  # No hash needed for Ed25519
    )

    return certificate

def save_x509_certificate(name, certificate):
    # Save the Self-Signed Certificate
    with open(f"{name}.crt", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    return f"{name}.crt"

def bytesToX509Certificate(bytes):
    return x509.load_pem_x509_certificate(bytes)


def load_x509_certificate(path):
    # Load the Self-Signed Certificate
    with open(path, "rb") as f:
        certificate = x509.load_pem_x509_certificate(f.read())

    return certificate

def generate_ca(config):
    """
    Generates a self-signed Certificate Authority (CA) with an Ed25519 key pair.

    :return: Tuple containing (ca_private_key, ca_certificate)
    """
    # Generate Ed25519 private key
    ca_private_key, ca_public_key = generate_ed25519_keypair()

    # Define the CA's distinguished name
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, config.get("COUNTRY_NAME", "US")),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config.get("STATE_OR_PROVINCE_NAME", "MA")),
        x509.NameAttribute(NameOID.LOCALITY_NAME, config.get("LOCALITY_NAME", "Boston")),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.get("ORG_NAME", "CA")),
        x509.NameAttribute(NameOID.COMMON_NAME, config.get("COMMON_NAME", "localhost")),
    ])

    # Create a self-signed CA certificate
    ip_address = ipaddress.ip_address(config.get("IP", "127.0.0.1"))
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)  # Self-signed
        .public_key(ca_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(tz=datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=10 * 365))  # Valid for 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1), critical=True
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(config.get("COMMON_NAME", "localhost")),  # Add hostname in SAN
                x509.IPAddress(ip_address)  # Also allow loopback IP
            ]),
            critical=True
        )
        .sign(ca_private_key, algorithm=None)  # Self-sign with CA's private key
    )
    return ca_private_key, ca_public_key, ca_certificate

def save_ca(path, orgname, ca_private_key, ca_public_key, ca_certificate):
    """
    Saves the CA's private key, public key, and certificate to files in `.key`, `.pub`, and `.crt` formats.
    """

    if path[-1] != '/':
        path += '/'

    # Save Private Key (PEM)
    with open(path+f"{orgname}.key", "wb") as key_file:
        key_file.write(
            ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,  # PKCS8 is the correct format for Ed25519
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save Public Key (Raw bytes for Ed25519)
    with open(path+f"{orgname}.pub", "wb") as pub_file:
        pub_file.write(
            ca_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        )

    # Save CA Certificate (.crt)
    with open(path+f"{orgname}.crt", "wb") as cert_file:
        cert_file.write(ca_certificate.public_bytes(serialization.Encoding.PEM))

def load_ca(path, orgname):
    path = cure(path)
    private_key, public_key = load_ed25519_keys(path+f"{orgname}")
    cert = load_x509_certificate(path+f"{orgname}.crt")
    return private_key, public_key, cert


def encrypt_token(token_dict, sdhkey) -> bytes:
    """
    Encrypts a token dictionary using AES-GCM with a Diffie-Hellman shared key.

    :param token_dict: The dictionary containing the token data.
    :param sdhkey: The shared DH key (must be 32 bytes for AES-256).
    :return: Base64-encoded encrypted token.
    """
    nonce = token_dict['nonce']
    

    # Convert complex objects to serializable formats
    serializable_token = {
        "nonce": base64.b64encode(token_dict['nonce']).decode('utf-8'),
        "issue_timestamp": token_dict["issue_timestamp"].isoformat(),
        "expiration_timestamp": token_dict["expiration_timestamp"].isoformat(),
        "communication_quota": token_dict["communication_quota"],
        "recipient_pac": base64.b64encode(
            token_dict["recipient_pac"].public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        ).decode('utf-8')
    }

    # Serialize to JSON and encode to bytes
    token_json = json.dumps(serializable_token).encode('utf-8')

    # Encrypt using AES-GCM
    cipher = Cipher(algorithms.AES(sdhkey), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(token_json) + encryptor.finalize()

    # Concatenate nonce + ciphertext + authentication tag
    encrypted_data = nonce + ciphertext + encryptor.tag

    # Return Base64-encoded encrypted data
    return encrypted_data

def decrypt_token(encrypted_token, sdhkey) -> dict:

    # Decode the encrypted token
    encrypted_data = base64.b64decode(encrypted_token.encode('utf-8'))

    # Extract the nonce, ciphertext, and tag
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:-16]
    tag = encrypted_data[-16:]

    # Decrypt the token
    cipher = Cipher(algorithms.AES(sdhkey), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    token = decryptor.update(ciphertext) + decryptor.finalize()

    return json.loads(token.decode('utf-8'))

