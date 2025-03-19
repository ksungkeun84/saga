import os
import saga.crypto as sc
import saga.config
import requests


def download_file(url, save_path):
    response = requests.get(url, stream=True)
    if response.status_code == 200:
        with open(save_path, 'wb') as file:
            for chunk in response.iter_content(1024):
                file.write(chunk)
        print(f"File downloaded: {save_path}")
    else:
        raise ValueError(f"Failed to download file from {url}. Status code: {response.status_code}")


class CA:
    """
    A class to represent a Certificate Authority (CA).
    """
    def __init__(self, workdir, config):
        self.orgname = config.get("ORG_NAME", "CA")
        self.workdir = workdir
        if self.workdir[-1] != '/':
            self.workdir += '/'
        
        if not os.path.exists(self.workdir):
            os.mkdir(self.workdir)
        
        # Download relevant files from endpoint into current directory
        endpoint = saga.config.CA_ENDPOINT
        if endpoint is None:
            raise ValueError("CA_ENDPOINT is None - please specify endpoint for CA")
        
        # Download files from endpoint
        for file in ["key", "pub", "crt"]:
            url = f"{endpoint}/{self.orgname}.{file}"
            save_path = os.path.join(self.workdir, f"{self.orgname}.{file}")
            download_file(url, save_path)

    def _old_init(self, workdir, config):

        self.orgname = config.get("ORG_NAME", "CA")
        self.workdir = workdir
        if self.workdir[-1] != '/':
            self.workdir += '/'
        
        if not os.path.exists(self.workdir):
            os.mkdir(self.workdir)

        # Check the the CA crypto does not exist:
        if not (
            os.path.exists(self.workdir+f"{self.orgname}.key") and 
            os.path.exists(self.workdir+f"{self.orgname}.pub") and 
            os.path.exists(self.workdir+f"{self.orgname}.crt")
        ):
            # Generate the keys and certificate of the CA:
            self.private_key, self.public_key, self.cert = sc.generate_ca(config)
            sc.save_ca(self.workdir, self.orgname, self.private_key, self.public_key, self.cert)
        else:
            # Load the keys and certificate of the CA, since they exist:
            self.private_key, self.public_key, self.cert = sc.load_ca(self.workdir, self.orgname)

    def sign(self, public_key, config):
        """
        Generates a signed X.509 certificate.
        """
        return sc.generate_x509_certificate(
            config, 
            public_key,
            ca_private_key=self.private_key,
            ca_certificate=self.cert
        )

    def verify(self, certificate):
        """
        Verifies a X.509 certificate.
        """
        sc.verify_x509_certificate(
            certificate=certificate, 
            ca_certificate=self.cert
        )

def get_SAGA_CA():
    return CA(
        workdir=saga.config.CA_WORKDIR,
        config=saga.config.CA_CONFIG
    )