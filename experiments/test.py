from agent_backend.config import UserConfig
from agent_backend.base import AgentWrapper

from saga.agent import Agent, get_agent_material


def main(mode, config_path, other_user_config_path=None):
    AGENT_FOCUS = 0
    config = UserConfig.load(config_path, drop_extra_fields=False)

    # Initialize local agent
    local_agent = AgentWrapper(config, config.agents[0])

    # Focus on first agent - infer credentials endpoint
    credentials_endpoint = f"user/{config.email}:{config.agents[AGENT_FOCUS].name}/"
    # Read agent material
    material = get_agent_material (credentials_endpoint)
    agent = Agent(workdir=credentials_endpoint,
                  material=material,
                  local_agent=local_agent)
    
    # agent.locarun(4.991452365949993)
    # exit(0)

    if mode == "listen":
        agent.listen()
    else:
        # Get endpoint for other agent
        other_user_config = UserConfig.load(other_user_config_path, drop_extra_fields=False)
        other_agent_credentials_endpoint = f"{other_user_config.email}:{other_user_config.agents[AGENT_FOCUS].name}"
        print(other_agent_credentials_endpoint)
        agent.connect(other_agent_credentials_endpoint, "Hey - how are you?")


if __name__ == "__main__":
    # Get path to config file
    import sys
    mode = sys.argv[1]
    if mode not in ["listen", "query"]:
        raise ValueError("Mode (first argument) must be either 'listen' or 'query'")
    config_path = sys.argv[2]
    other_user_config_path = sys.argv[3] if len(sys.argv) > 3 else None
    
    if mode == "query" and other_user_config_path is None:
        raise ValueError("Endpoint (third argument) must be provided in query mode")
    main(mode=mode,
         config_path=config_path,
         other_user_config_path=other_user_config_path)
