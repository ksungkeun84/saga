### SAGA ###

ROOT_DIR = "/home/georgios/saga/saga"

### CA ###
# Endpoint where CA hosts relevant files
CA_ENDPOINT = "http://129.10.186.246:8000"

CA_WORKDIR = ROOT_DIR+"/ca"
CA_CONFIG = {
    "COUNTRY_NAME": "US",
    "STATE_NAME": "MA",
    "LOCALITY_NAME": "Boston",
    "ORG_NAME": "ca",
    "COMMON_NAME": "localhost",
    "IP": "127.0.0.1"
}
CA_CERT_PATH = ROOT_DIR+'/ca/ca.crt'

### PROVIDER ###
PROVIDER_WORKDIR = ROOT_DIR+"/provider"
PROVIDER_CONFIG = {
    "COUNTRY_NAME": "US",
    "STATE_NAME": "MA",
    "LOCALITY_NAME": "Boston",
    "ORG_NAME": "provider",
    "COMMON_NAME": "localhost",
    "IP": "127.0.0.1"
}
PROVIDER_CERT_PATH = ROOT_DIR+'/provider/provider.crt'
PROVIDER_URL = "https://localhost:5000"

### USER ###
USER_WORKDIR = ROOT_DIR+"/user"

### AGENTS ###

AGENT_DEFAULT_CONFIG = {
    "COUNTRY_NAME": "US",
    "STATE_OR_PROVINCE_NAME": "MA",
    "LOCALITY_NAME": "Boston",
    "ORGANIZATION_NAME": "SAGA"
}

### 3 Testing agents ###
ASTRO_WORKDIR = ROOT_DIR+"/user/test@test.com:astro"
BOBA_WORKDIR = ROOT_DIR+"/user/test@test.com:boba"
COSMO_WORKDIR = None