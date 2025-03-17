from agents.config import UserConfig
from agents.base import AgentWrapper


def main():
    config = UserConfig.load("user_configs/emma.yaml", drop_extra_fields=False)
    # Initialize agent
    agent = AgentWrapper(config, config.agents[0])
    # Query the agent
    # response = agent.query("Please email emma_johnson@gmail.com to tell her about the meeting we have tomorrow at 10AM in Rice Hall, Room 314.")
    # response = agent.query("Please summarize my inbox")
    # response = agent.query("Please check my email inbox and if any meeting is coming up, add it to my calendar.")
    response = agent.query("Do I have any upcoming events?")
    print(response)


if __name__ == "__main__":
    main()
