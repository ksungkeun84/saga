### SAGA ###
import saga
import os

# TODO: Have some offline config file with this information, read it here and make available in these variables

# MondoDB connection string (for tool-related data)
MONGO_URI_FOR_TOOLS = "mongodb://129.10.187.52:27017/saga_tools"

# Get root-dir automatically
ROOT_DIR = os.path.dirname(saga.__file__)

### CA ### (Runs on nds2 starscream)
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

### PROVIDER ### (Runs on nds2 lambda)
PROVIDER_WORKDIR = ROOT_DIR+"/provider"
PROVIDER_CONFIG = {
    "COUNTRY_NAME": "US",
    "STATE_NAME": "MA",
    "LOCALITY_NAME": "Boston",
    "ORG_NAME": "provider",
    "COMMON_NAME": "129.10.187.52", 
    "IP": "129.10.187.52"
}
PROVIDER_CERT_PATH = ROOT_DIR+'/provider/provider.crt'
PROVIDER_URL = "https://129.10.187.52:5000"

### USER ###
USER_WORKDIR = ROOT_DIR+"/user"
USER_DEFAULT_CONFIG = {
    "COUNTRY_NAME": "US",
    "STATE_NAME": "MA",
    "LOCALITY_NAME": "Boston",
    "ORG_NAME": "SAGA USER", 
    "IP": "127.0.0.1"
}

### AGENTS ###

AGENT_DEFAULT_CONFIG = {
    "COUNTRY_NAME": "US",
    "STATE_OR_PROVINCE_NAME": "MA",
    "LOCALITY_NAME": "Boston",
    "ORGANIZATION_NAME": "SAGA"
}

### TOKEN SETTINGS ###
Q_MAX = 50

### 3 Testing agents ###
AGENT_GEORGE_WORKDIR = ROOT_DIR+"/user/george@mail.com:dummy_agent"
AGENT_JOHN_WORKDIR = ROOT_DIR+"/user/john@mail.com:dummy_agent"
AGENT_MOM_WORKDIR = ROOT_DIR+"/user/mom@mail.com:dummy_agent"