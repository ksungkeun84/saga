from smolagents import CodeAgent, HfApiModel, TransformersModel, OpenAIServerModel, MultiStepAgent, ToolCallingAgent
from agent_backend.config import AgentConfig, UserConfig
import yaml
from typing import List
from typing import Tuple
from smolagents import tool
from smolagents import populate_template
from smolagents.memory import TaskStep
import os

from saga.config import ROOT_DIR

from agent_backend.tools.email import LocalEmailClientTool
from agent_backend.tools.calendar import LocalCalendarTool
from datetime import datetime
import importlib.resources


VERBOSITY_LEVEL = 2


class AgentWrapper:
    """
        Base agents wrapper, built on top of CodeAgent form smolagents
    """
    def __init__(self,
                 user_config: UserConfig,
                 config: AgentConfig,
                 prompt_filename: str):
        # TODO: should not provide all of user-config (airgap ftw) - think about this later
        self.user_config = user_config
        self.config = config
        self.tool_collections = []
        self.prompt_filename = prompt_filename

        # Collect all tools
        self._collect_tools_for_use()

        # Initialize base model
        self._initialize_base_model()

        self.task_finished_token = "<TASK_FINISHED>"

        # Read YAML file
        self._set_custom_prompt(self.prompt_filename)

    def _set_custom_prompt(self, prompt_filename: str):
        DIR_ABOVE_ROOT_DIR = os.path.dirname(ROOT_DIR)
        with open(os.path.join(DIR_ABOVE_ROOT_DIR, "agent_backend", "custom_prompts", prompt_filename), 'r') as file:
            self.custom_prompt = yaml.safe_load(file)

    def _initialize_base_model(self):
        if self.config.model_type == "TransformersModel":
            model = TransformersModel(
                model_id=self.config.model,
                max_new_tokens=4096,
                device_map="auto"
            )
        elif self.config.model_type == "HfApiModel":
            model = HfApiModel(
                model_name=self.config.model,
                hf_api_key="",
                hf_api_url="https://api-inference.huggingface.co/models/"
            )
        elif self.config.model_type == "OpenAIServerModel":
            model = OpenAIServerModel(
                model_id=self.config.model,
                api_base=self.config.api_base,
                api_key=self.config.api_key,
                temperature=0.0
            )
        else:
            raise ValueError(f"Model type {self.config.model_type} not supported.")
        
        # Set this model
        self.model = model

    def _collect_tools_for_use(self):
        """
            Generic function that tries to read all local-functions within class with a certain name.
            Any child class can thus extend and add their own tools.
        """
        # Read all tools referenced in self.config.tools and get corresponding functions
        for tool_name in self.config.tools:
            tool_func = getattr(self, f"_{tool_name}_tools", None)
            if not tool_func:
                raise ValueError(f"Tool {tool_name} not found.")
            self.tool_collections.extend(tool_func())
        
        # TODO: logic to make sure not duplicates are created in process of collecting all functions

    def _reimbursement_tools(self):
        # Tools relevant to submitting an expense report to HR
        # Initialize only if it does not exist already
        if not hasattr(self, "email_client"):
            self.email_client = LocalEmailClientTool(user_name=self.user_config.name,
                                                     user_email=self.user_config.email)
        
        @tool
        def submit_expense_report(amount: float, description: str, people_involved: List[str]) -> bool:
            """
                This is a tool that submits an expense report to HR with the amount and description.
                It also makes sure that all people related to the expenses are CC'd on the expense report.
                Returns True if the report is submitted successfully, False otherwise.

                Args:
                    amount: The total amount of the expense.
                    description: The description of the expense.
                    people_involved: List of email addresses of people involved in the expense.
            """
            to = ["hr@university.com"] + people_involved
            subject = "Expense Report"
            body = "Hi,\nPlease find attached the total cost of the expenses. All people associated with the expenses are CC'd on this email.\n\nTotal cost: " + str(amount) + "\n\nDescription: " + description + "\n\nThanks,\n" + self.user_config.name
            return self.email_client.send_email(to=to, subject=subject, body=body)

        return [
            submit_expense_report
        ]

    def _email_tools(self):
        # Define relevant tools for email use
        self.email_client = LocalEmailClientTool(user_name=self.user_config.name,
                                                 user_email=self.user_config.email)

        @tool
        def check_inbox(limit: int = 50) -> List[dict]:
            """
            This is a tool that checks the inbox of the user, and returns the most recent emails.
            It returns a list of dictionaries containing the email details.

            Args:
                limit: The number of emails to retrieve. Defaults to 50. When set to None, all emails are retrieved.
            """
            inbox_emails = self.email_client.get_emails(where="inbox", limit=limit)
            return inbox_emails
    
        @tool
        def check_outbox(limit: int = 10) -> List[dict]:
            """
            This is a tool that checks the outbox of the user, and returns the most recent emails.
            It returns a list of dictionaries containing the email details.

            Args:
                limit: The number of emails to retrieve. Defaults to 10. When set to None, all emails are retrieved.
            """
            return self.email_client.get_emails(where="sent", limit=limit)

        
        @tool
        def send_email(to: List[str], subject: str, body: str) -> bool:
            """
            This is a tool that sends an email to the specified recipient. To cc someone, add them in the list of recipients.
            Returns True if the email was sent successfully, False otherwise.

            Args:
                to: List of recipients to send the email to (their emails).
                subject: The subject of the email.
                body: The body of the email.
            """
            return self.email_client.send_email(to=to, subject=subject, body=body)
    
        @tool
        def search_inbox(query: str) -> List[dict]:
            """
            This is a tool that searches for emails in the inbox that match the query (normal keyword search, not semantic).
            This function is not perfect and may miss out on some results.
            Returns a list of dictionaries containing the email details, sorted by time.

            Args:
                query: The query to search for.
            """
            return self.email_client.search_by_query(query=query, where="inbox")

        @tool
        def search_outbox(query: str) -> List[dict]:
            """
            This is a tool that searches for emails in the outbox that match the query (normal keyword search, not semantic).
            This function is not perfect and may miss out on some results.
            Returns a list of dictionaries containing the email details, sorted by time.

            Args:
                query: The query to search for.
            """
            return self.email_client.search_by_query(query=query, where="sent")

        @tool
        def get_my_email() -> str:
            """
            Get the email ID of the current user (self).
            """
            return self.email_client.user_email

        tools_available = [
            check_inbox,
            check_outbox,
            send_email,
            # search_inbox,
            # search_outbox,
            get_my_email
        ]

        return tools_available

    def _calendar_tools(self):
        # Define relevant tools for email use
        self.calendar_client = LocalCalendarTool(user_name=self.user_config.name,
                                                 user_email=self.user_config.email)

        @tool
        def get_upcoming_events(limit: int = 10) -> List[dict]:
            """
            This is a tool that retrieves the upcoming events from the user's calendar.
            Returns a list of dictionaries containing the event details.

            Args:
                limit: The number of events to retrieve. Defaults to 10. When set to None, all events are retrieved.
            """
            return self.calendar_client.get_upcoming_events(limit=limit)

        @tool
        def add_calendar_event(time_from: str, time_to: str, event: str, details: str, participants: List[str] = []) -> bool:
            """
            This is a tool that adds an event to the user's calendar.
            Returns True if the event was added successfully, False otherwise.

            Args:
                time_from: The start time of the event. Should be in ISO format.
                time_to: The end time of the event. Should be in ISO format.
                event: The name of the event.
                participants: List of email addresses of other participants.
                details: Any details about the meeting. Can have reference to email with email subject, if linked to an email.
            """
            return self.calendar_client.add_calendar_event(time_from=time_from,
                                                  time_to=time_to,
                                                  event=event,
                                                  details=details,
                                                  participants=participants)

        @tool
        def get_availability(time_from: str, time_to: str) -> List[dict]:
            """
            This is a tool that retrieves the upcoming events from the user's calendar that correspond to a certain time-range.
            Returns a list of dictionaries containing time slots where the user is available.

            Args:
                time_from: The start time to check from. Should be in ISO format
                time_to: The end time to check until. Should be in ISO format.
            """
            return self.calendar_client.get_availability(time_from, time_to)

        @tool
        def get_general_preferences() -> str:
            """
            This is a tool that returns the general preferences for the user for meeting times/days that work for them.
            Returns a string describing the preferences.
            """
            return self.calendar_client.get_preference()

        @tool
        def get_my_email() -> str:
            """
            Get the email ID of the current user (self).
            """
            return self.calendar_client.user_email


        tools_available = [
            get_upcoming_events,
            add_calendar_event,
            get_availability,
            get_general_preferences,
            get_my_email
        ]
        return tools_available

    def _self_tools(self):

        @tool
        def my_email():
            """
            This is a tool that returns my name and email ID as tuple

            """
            return self.user_config.name, self.user_config.email
        
        return [my_email]

    def _create_local_agent_object(self, **kwargs) -> MultiStepAgent:
        raise NotImplementedError("Child class should implement _create_local_agent_object()")

    def _initialize_agent(self, initiating_agent: bool, task: str = None) -> MultiStepAgent:
        if initiating_agent:
            # preamble = self.custom_prompt["initiating_agent"]
            preamble = ""
        else:
            preamble = self.custom_prompt["receiving_agent"]
        
        # Fill in the template text
        # TODO: Find a better way around this mess
        today_date = datetime.now().strftime("%A, %B %d, %Y")
        template_text = self.custom_prompt["system_prompt"].replace("[[[preamble]]]", preamble).replace("[[[task_finished_token]]]", self.task_finished_token).replace("[[[today_date]]]", today_date)
        # Use this template text
        if task is not None:
            template_text = template_text.replace("[[[task]]]", task)

        agent = self._create_local_agent_object(template_text=template_text)

        if initiating_agent:
            # Override this agent to simulate history of the agent having started the conversation
            agent.memory.steps.append(TaskStep(task=self.custom_prompt["initiating_agent"]))

        return agent

    def run(self, query: str,
            initiating_agent: bool,
            agent_instance: MultiStepAgent = None,
            **kwargs) -> Tuple[MultiStepAgent, str]:
        # We create a new instance for every fresh task, as every agent object shared memory 
        # and we only want to share them for a given conversation, not all conversations of an agent.
        # Also helps in isolation, as the objects are now separate.
        # Overhead for new agent creation is low enough that it is not a problem.

        if agent_instance is None:
            task_str = query if initiating_agent else None
            agent_instance = self._initialize_agent(initiating_agent, task=task_str)

        # Make sure kwargs do not specify reset (should be False)
        if "reset" in kwargs:
            print ("WARNING: 'reset'' should not be specified in kwargs to agent, as it is always False.")
            kwargs.pop("reset")

        response = agent_instance.run(str(query), reset=False, **kwargs)

        # Replace "The task is completed." with self.task_finished_token
        if response == "The task is completed.":
            response = self.task_finished_token
        
        # print("\n"*3)
        # for step in agent_instance.memory.steps:
        #     print(step)
        #     print()
        # print("\n"*3)

        return agent_instance, response


class CodeAgentWrapper(AgentWrapper):
    """
        Wrapper class for a CodeAgent from smolagents.
    """
    def __init__(self,
                 user_config: UserConfig,
                 config: AgentConfig):
        super().__init__(user_config=user_config, 
                         config=config,
                         prompt_filename="CodeAgent.yaml")
    
    def _create_local_agent_object(self, **kwargs) -> CodeAgent:

        # Start with the default template
        starting_prompt_template = yaml.safe_load(
            importlib.resources.files("smolagents.prompts").joinpath("code_agent.yaml").read_text()
        )
        # Replace the system-prompt with our own system prompt
        starting_prompt_template['system_prompt'] = kwargs['template_text']

        agent = CodeAgent(
            tools = self.tool_collections,
            model = self.model,
            add_base_tools = True,
            additional_authorized_imports=self.config.additional_authorized_imports,
            verbosity_level=VERBOSITY_LEVEL,
            prompt_templates=starting_prompt_template
        )

        return agent


class ToolCallingAgentWrapper(AgentWrapper):
    """
        Wrapper class for a ToolCallingAgent from smolagents.
    """
    def __init__(self,
                 user_config: UserConfig,
                 config: AgentConfig):
        super().__init__(user_config=user_config, 
                         config=config,
                         prompt_filename="ToolCallingAgent.yaml")
    
    def _create_local_agent_object(self, **kwargs) -> ToolCallingAgent:
        agent = ToolCallingAgent(
            tools = self.tool_collections,
            model = self.model,
            verbosity_level=VERBOSITY_LEVEL
        )

        # Override the system template
        agent.system_prompt = populate_template(
            kwargs['template_text'],
            variables={
                "tools": agent.tools,
                "managed_agents": agent.managed_agents
            },
        )

        return agent


def get_agent(user_config: UserConfig,
              config: AgentConfig) -> AgentWrapper:
    if config.base_agent_type == "CodeAgent":
        return CodeAgentWrapper(user_config=user_config,
                                config=config)
    elif config.base_agent_type == "ToolCallingAgent":
        return ToolCallingAgentWrapper(user_config=user_config,
                                       config=config)

    raise NotImplementedError(f"Base agent type {config.base_agent_type} not supported.")
