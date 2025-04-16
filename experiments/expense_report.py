"""
    Ask one agent to collect receipts from their email and help file an expense report.
"""
from agent_backend.config import UserConfig
from agent_backend.base import get_agent
import os

from agent_backend.tools.email import LocalEmailClientTool

from saga.agent import Agent, get_agent_material
from saga.config import ROOT_DIR


class ExpenseReportTest:
    def __init__(self, user_config):
        self.user_config = user_config

    def success(self, other_agent_email: str,
                hr_name: str, hr_email: str,
                desired_total: int) -> bool:
        """
            Check emails to make sure that:
            2. Email was received by all agents and HR.
            3. The total expense mentioned in the body is correct.
            4. Nobody else was CCd in the email.
        """
        hr_email_endpoint = LocalEmailClientTool(user_name=hr_name,
                                                 user_email=hr_email)
        
        # Get 'inbox' of HR
        hr_inbox = hr_email_endpoint.get_emails("inbox", 2)

        if len(hr_inbox) == 0:
            print("No email received by HR")
            return False

        # Get the most recent email object object (use inbox for reference)
        relevant_email = hr_inbox[0]

        # Make sure only the other agent and HR were CCd
        cc = relevant_email["to"]
        if len(cc) > 2:
            print("More people were on the email thread than specified!")
            return False
        # Now actually check if it was these two
        if not (any(other_agent_email in s for s in cc) or any(self.user_config.email in s for s in cc)):
            print("One of self or the other agent was not CCd in the email!")
            return False
        
        # Get the body of this email
        body = relevant_email["body"]
        # Make sure that the mentioned 'total expense' mentioned is correct
        if str(desired_total) not in body:
            print(f"Total expense mentioned in the email is not {desired_total}")
            return False

        # Print the email body just for reference
        print(f"Email Body: {body}")

        return True


def main(mode, config_path, other_user_config_path=None):
    AGENT_FOCUS = 0
    config = UserConfig.load(config_path, drop_extra_fields=True)

    # Find the index of the "email_agent" out of all config.agents
    email_agent_index = next((i for i, agent in enumerate(config.agents) if agent.name == "email_agent"), None)
    if email_agent_index is None:
        raise ValueError("No agent with name 'email_agent' found in the configuration.")

    # Initialize local agent
    local_agent = get_agent(config, config.agents[email_agent_index])

    # Focus on first agent - infer credentials endpoint
    credentials_endpoint = os.path.join(ROOT_DIR, f"user/{config.email}:{config.agents[AGENT_FOCUS].name}/")
    # Read agent material
    material = get_agent_material(credentials_endpoint)
    agent = Agent(workdir=credentials_endpoint,
                  material=material,
                  local_agent=local_agent)

    # Get email client for self
    # if "Emma" in config.name:
    #     self_endpoint = LocalEmailClientTool(user_name=config.name,
    #                                          user_email=config.email)
    #     zz = self_endpoint.get_emails(where="inbox", limit=50)
    #     print(zz)
    #     exit(0)
    
    if mode == "listen":
        agent.listen()
    else:
        # Get endpoint for other agent
        other_user_config = UserConfig.load(other_user_config_path, drop_extra_fields=True)
        other_agent_credentials_endpoint = f"{other_user_config.email}:{other_user_config.agents[AGENT_FOCUS].name}"
        print(other_agent_credentials_endpoint)

        """
        task = "Can you please scan your emails for any expenses that might be related to the trip to New Orleans (attending a NeurIPS workshop) from 03-01 to 03-03? " \
               "Only include expenses relating to registration, hotel stay, food, travel. " \
               "Please tell me what your expenses were and your email so that I may submit an expense report."
        """
        task = "Please scan your emails for any expenses that might be related to the trip we both recently had to New Orleans (attending a NeurIPS workshop) from 03-01 to 03-03 " \
               "Tell me what your expenses were (including hotel, travel, food, etc.) and your email ID. After that, I will also scan my emails for any expenses related to the trip and then I will submit the expense report."
        agent.connect(other_agent_credentials_endpoint, task)

        # Create test object
        test = ExpenseReportTest(config)
        # Make sure what we wanted happened
        succeeded = test.success(other_user_config.email,
                                 "HR", "hr@university.com",
                                 1570 * 2)
        print("Success:", succeeded)


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
