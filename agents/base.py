from smolagents import CodeAgent, HfApiModel, TransformersModel, OpenAIServerModel, PromptTemplates, MultiStepAgent
from agents.config import AgentConfig, UserConfig
import yaml
from typing import List
from typing import Tuple
from smolagents import tool
from smolagents import populate_template

from tools.email import LocalEmailClientTool
from tools.calendar import LocalCalendarTool


class AgentWrapper:
    """
        Base agents wrapper, built on top of CodeAgent form smolagents
    """
    def __init__(self, user_config: UserConfig, config: AgentConfig):
        # TODO: should not provide all of user-config (airgap ftw) - think about this later
        self.user_config = user_config
        self.config = config
        self.tool_collections = []

        # Collect all tools
        self._collect_tools_for_use()

        # Initialize base model
        self._initialize_base_model()

        self.task_finished_token = "<TASK_FINISHED>"

        # TODO: Figure out where to use description
        self.custom_prompt = yaml.safe_load("./code_agent_custom_prompt.yaml")
    
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
                api_key=self.config.api_key
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

    def _email_tools(self):
        # Define relevant tools for email use
        self.email_client = LocalEmailClientTool(self.user_config.email)

        @tool
        def check_inbox(limit: int = 10) -> List[dict]:
            """
            This is a tool that checks the inbox of the user, and returns the most recent emails.
            It returns a list of dictionaries containing the email details.

            Args:
                limit: The number of emails to retrieve. Defaults to 10. When set to None, all emails are retrieved.
            """
            return self.email_client.get_emails(limit=limit)
        
        @tool
        def send_email(to: str, subject: str, body: str) -> bool:
            """
            This is a tool that sends an email to the specified recipient.
            Returns True if the email was sent successfully, False otherwise.

            Args:
                to: The recipient of the email.
                subject: The subject of the email.
                body: The body of the email.
            """
            return self.email_client.send_email(to=to, subject=subject, body=body)
    
        @tool
        def search_emails_by_query(query: str) -> List[dict]:
            """
            This is a tool that searches for emails in the inbox that match the query.
            Returns a list of dictionaries containing the email details.

            Args:
                query: The query to search for.
            """
            return self.email_client.search_emails_by_query(query=query)

        tools_available = [
            check_inbox,
            send_email,
            search_emails_by_query
        ]

        return tools_available

    def _calendar_tools(self):
        # Define relevant tools for email use
        self.calendar_client = LocalCalendarTool(self.user_config.email)

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
            # Make sure participant list includes self
            participants_all = participants + [self.user_config.email]
            participants_all = list(set(participants_all))
            return self.calendar_client.add_calendar_event(time_from=time_from,
                                                  time_to=time_to,
                                                  event=event,
                                                  details=details,
                                                  participants=participants_all)

        tools_available = [
            get_upcoming_events,
            add_calendar_event
        ]
        return tools_available

    def _initialize_agent(self, initiating_agent: bool) -> MultiStepAgent:

        if initiating_agent:
            preamble = self.custom_prompt["initiating_agent"]
        else:
            preamble = self.custom_prompt["receiving_agent"]
        
        # Fill in the template text
        template_text = self.custom_prompt.format(preamble=preamble, task_finished_token=self.task_finished_token)
        # Use this template text as the 

        agent = CodeAgent(
            tools = self.tool_collections,
            model = self.model,
            add_base_tools = True,
            additional_authorized_imports=self.config.additional_authorized_imports,
            verbosity_level=2,
            # system_prompt=self.prompt_for_agent
        )

        # Override the system template
        agent.system_prompt = populate_template(
            template_text,
            variables={
                "tools": agent.tools,
                "managed_agents": agent.managed_agents
                },
        )

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
            agent_instance = self._initialize_agent(initiating_agent)

        # Make sure kwargs do not specify reset (should be False)
        if "reset" in kwargs:
            print ("WARNING: 'reset'' should not be specified in kwargs to agent, as it is always False.")
            kwargs.pop("reset")

        response = agent_instance.run(str(query), reset=False, **kwargs)
        return agent_instance, response
