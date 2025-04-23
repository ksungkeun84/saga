# SAGA: A Security Architecture for Governing AI Agentic Systems

<img src="assets/logo.png" alt="SAGA logo" width="150"/>

Repository for the SAGA project.

## Requirements

Install the `saga` package:

```bash
pip install -e .
```

Make sure that `mongoDB` is installed on the Provider side and the mongoDB server is up and running.

## Setup

To set things up, we will first begin by starting a `CA` server, followed by a `Provider` server for our SAGA protocol.

#### 1. Setup a CA

Generate valid credentials and host the *.crt, *.key, and *pub files at some endpoint.

```bash
python generate_credentials.py ca saga/ca/
```

One way to host these files is to run a simple fileserver, such as a python HTTP server.

```bash
cd saga/ca/ && python -m http.server
```

Take note of the `endpoint` where this CA is hosted and update it under `config.yaml` for the `ca`.

#### 2. Setup the Provider

Generate valid provider credentials

```bash
python generate_credentials.py provider saga/provider/
```

Host this provider service at some endpoint by running the following command:

```bash
cd saga/provider/ && python provider.py
```

Take note of the `endpoint` and update `config.yaml` for the `provider`.

## User Registration

The next step is to run the user client in order to register agents with the provider:

```bash
cd saga/user/ && python user.py
```

> __Note__: all generated cryptographic material for the user will be placed within a `keys/` subdirectory. The user's public/private keys will be stored in the `<uid>.pub` and `<uid>.key` format.

## Agent Registration

Assume the user `Alice` wants to register a new agent under the name `Astro`, an email client agent responsible for handling Alice's inbox. In order to register `Astro`, `Alice` first needs to be registered with the provider using the `register` endpoint. 

```bash
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

```bash
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

```bash
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

> __Note__: Once an agent has been successfully registered with the provider, a new subdirectory within the `user` directory, e.g. `user/<aid>` or in our case `user/alice@herdomain.com:astro`. This is Astro's woring directory. This directory contains the agent's manifest: `agent.json` listing the required metadata for the new agent to be able to operate within the SAGA network:

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

## Agent Communication

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

## Experiments

### Setup 

To get started, register the user using their configuration. We provide template user configs under `user_configs`. To register a user, run

```bash
cd saga/user
python user.py --register --uconfig ../../user_configs/emma.yaml
```

To register the agent(s) corresponding to this user, run

```bash
cd saga/user
python user.py --register-agents --uconfig ../../user_configs/emma.yaml
```

You can also register the user and agents in one go by providing both `--register` and `--register-agents` flags.

### Seed Data

Next, you can populate the "data" used by tools for each of the users by running:

```bash
cd experiments/
python seed_tool_data.py
```

This will use data from `experiments/data` to seed tool-related data for each user. Some of this seed data is based on the profiles used in the paper [Firewalls to Secure Dynamic LLM Agentic Networks](https://github.com/microsoft/Firewalled-Agentic-Networks), and is purely synthetic.

### Running tasks

The three tasks mentioned in the paper map to the following files under `experiments/`
- `schedule_meeting.py` : Scheduling agents coordinating to find a common time for a meeting and sending a calendar invite.
- `expense_report.py` : Email-reading agents coordinating to collect their expenses for a recent business trip, and one of them submits an expense report to HR.
- `create_blogpost.py` : Blogpost-writing agents use knowledge from prior blogposts of their users to collaborate and write a blogpost on some shared topic.

To run a task, first start the receiving agent on its endpoint:

```bash
cd experiments/
python <task.py> listen ../user_configs/config1.yaml
```

Then, start the initiating agent on its respective endpoint

```bash
cd experiments/
python <task.py> query ../user_configs/config2.yaml ../user_configs/config1.yaml
```

The agent corresponding to `config2.yaml` will then contact `config1.yaml` and they work towards their shared goal.

> __Note__: Make sure you set `OPENAI_API_KEY` as an environment variable before running experiments.