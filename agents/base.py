from smolagents import CodeAgent, HfApiModel, TransformersModel
from agents.config import AgentConfig, UserConfig
from typing import List
from smolagents import tool
import inspect
from transformers import pipeline

from tools.email import LocalEmailClientTool
from tools.calendar import LocalCalendarClientTool


class AgentWrapper:
    def __init__(self, user_config: UserConfig, config: AgentConfig):
        # TODO: should not provide all of user-config (airgap ftw) - think about this later
        self.user_config = user_config
        self.config = config
        self.tool_collections = []

        # Collect all tools
        self._collect_tools_for_use()

        # Initialize base model
        model = self._initialize_base_model()

        # TODO: Figure out where to use description

        # Initialize agent
        self.agent = CodeAgent(
            tools = self.tool_collections,
            model = model,
            add_base_tools = True,
            additional_authorized_imports=self.config.additional_authorized_imports,
            verbosity_level=2
        )
    
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
        else:
            raise ValueError(f"Model type {self.config.model_type} not supported.")
        return model

    def _collect_tools_for_use(self):
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
        self.calendar_client = LocalCalendarClientTool(self.user_config.email)

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

    def query(self, query: str) -> str:
        # TODO: Think of conversation history later
        response = self.agent.run(query)
        return response
