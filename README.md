# SAGA: A Security Architecture for Governing AI Agentic Systems

Repository for the SAGA project.

## Requirements

Edit the `config.py`'s root directory location to your saga src. 

Make sure that `mongoDB` is installed on the Provider side and the mongoDB server is up and running.

## Instructions

### 1. Provider

The first step is to fire-up the provider. This is done by navigating into the provider's directory and running the `provider.py` script:

```bash
cd provider/ && python provider.py
```

### 2. User

The next step is to run the user client in order to register agents with the provider. This is done by navigating into the user's directory and running the `user.py` script:

```bash
cd user/ && python user.py
```

Note: all generated cryptographic material for the user will be placed within a `keys/` subdirectory. The user's public/private keys will be stored in the `<uid>.pub` and `<uid>.key` format.

### 3. Agents

Assume the user Alice wants to register a new agent under the name Astro. Astro is an email client agent and is responsible for handling Alice's inbox. In order to register Astro, Alice first needs to be registered with the provider using the `register` endpoint. 

```python
1. Register
2. Login
3. Google OAuth Login
4. Register Agent
Choose an option: 1 # Register user 
Enter email: alice@herdomain.com
Enter password: 1234
Generating cryptographic material...
{'message': 'User registered successfully'}
```

After successful registration, Alice needs to authenticate herself in order to register Astro under her name. She does it with the `login` endpoint. 

```python
======= SAGA User Client CLI =======
1. Register
2. Login
3. Google OAuth Login
4. Register Agent
Choose an option: 2 # Authenticate user
Enter email: alice@herdomain.com
Enter password: 1234
Login successful. Token: eyJhbGciOiJIUzI1NiIsInR5cCI6...
```

Finally, Alice proceeds with providing all the required material (agent device and networking information, cryptographic content, etc.) for Astro to operate within the SAGA network. The agent registration is done via the `register_agent` endpoint.

```python
======= SAGA User Client CLI =======
1. Register
2. Login
3. Google OAuth Login
4. Register Agent
Choose an option: 4 # Register a new agent
Enter agent name: astro
Enter device name: lambda
Enter IP address: 127.0.0.1
Enter port: 6000
Enter number of one-time prekeys: 10
Agent 'astro' registered successfully.
```

__Note__: Once an agent has been successfully registered with the provider, a new subdirectory within the `user` directory, e.g. `user/<aid>` or in our case `user/alice@herdomain.com:astro`. This is Astro's woring directory. This directory contains the agent's manifest: `agent.json` listing the required metadata for the new agent to be able to operate within the SAGA network:

```json
{
    "aid": "alice@herdomain.com:astro",
    "device": "alice_computer",
    "IP": "127.0.0.1",
    "port": "6000",
    "dev_info_sig": "Q78qQTDrrQRs77Kfe37IFQkU...",
    "agent_cert": "LS0tLS1CRUdJTiBDR...",
    "public_signing_key_sig": "mgVXMQo3zGLJD31700zkcdVlBmr...",
    "identity_key": "48qaThDW1vzO56sxzqh/WaphyO4BkuUa6V9Y+kHClUU=",
    "spk": "FLorcCb6WlYXqFFkHhBL55ErDp0ID4h0iXtNM1Kk2Es=",
    "spk_sig": "z4WU6gHCTE8RG3dgiBXD4UgzVV...",
    "opks": [
        "zogadPdg+j8lQNaXeiIo9rL1rPT33ykzBnFjsAx/Kzw=",
        ...
    ],
    ...
}
```

### Accepting conversations:

Once the new agent has been registered with the provider and its manifest has been created, the new SAGA agent can be run by simply creating a new saga `Agent` instance:

```python
import saga.config
from saga.agent import Agent

# Create agent instance 
astro = Agent.fromDir("user/alice@herdomain.com:astro/")
# Goes online and can accept conversations from other agents
astro.listen() 
```

Once `listen` is invoked, the new agent goes online and other agents can start opening connections:

```python
import saga.config
from saga.agent import Agent

# Create agent instance 
bisco = Agent.fromDir("user/bob@hisdomain.com:bisco/")
# Attempts to start a new conversation with Alice's astro agent.
bisco.connect("alice@herdomain.com:astro")
```