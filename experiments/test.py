from agent_backend.config import UserConfig
from agent_backend.base import get_agent
from smolagents import GradioUI


def main(config_path):
    AGENT_FOCUS = 0
    config = UserConfig.load(config_path, drop_extra_fields=True)

    # Initialize local agent
    local_agent = get_agent(config, config.agents[0])

    # Test local agent

    # Make sure all functions are callable for the instance
    email_tools = local_agent._email_tools()
    print(email_tools[0](), "!")
    print("*" * 20)
    print(email_tools[1]("Anita2 <anita.sharma@gmail.com>", "testing", "hello dear, i am testing, bye"), "!")
    print("*" * 20)
    print(email_tools[2]("test"), "!")
    print("*" * 20)
    calendar_tools = local_agent._calendar_tools()
    events = calendar_tools[0]()
    if len(events) == 0:
        print("!")
    for event in events:
        print(event, "|")
    print("*" * 20)
    print(calendar_tools[1]("2025-05-01T00:00:00", "2025-05-03T00:00:00", "testing", "nuff said"), "!")
    print("*" * 20)
    print(calendar_tools[2]("2025-04-22T00:00:00", "2025-05-04T00:00:00"))
    print("*" * 20)
    print(calendar_tools[3]())

    # POV: You are the receiving agent
    # instance = local_agent._initialize_agent(initiating_agent=False)

    # POV: You are the initiating agent
    instance = local_agent._initialize_agent(initiating_agent=True, task="Do you have any free time next week for a 1-hour slot for a meeting? To talk about the NDSS submission")

    # print("\n"*3)
    # print(instance.memory.system_prompt.to_messages()[0]['content'][0]['text'])
    # for step in instance.memory.steps:
    #     print(step)
    # exit(0)
    
    # Launch the agent via gradio
    ui = GradioUI(instance)
    ui.launch()



if __name__ == "__main__":
    # Get path to config file
    import sys
    config_path = sys.argv[1]
    
    main(config_path=config_path)
