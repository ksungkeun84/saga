"""
    Definitions for configurations.
"""
from dataclasses import dataclass, field
from typing import Optional, List
from simple_parsing.helpers import Serializable


@dataclass
class LocalAgentConfig(Serializable):
    """
    Configuration for a local agent.
    This is specific to the way agents are setup for SAGA, but can be replaced with any configuration that matches the way you want to implement your agents.
    The important part is that 'some' configuration is used to create the agent.
    """
    model: str
    """The actual model (LLM) to use"""
    tools: List[str]
    """List of tools available to the agent."""
    specific_agent_instruction: Optional[str] = ""
    """Specific prompt instructions for the agent"""
    additional_authorized_imports: List[str] = field(default_factory=list)
    """List of additional authorized imports for the agent."""
    api_base: Optional[str] = None
    """API base URL for the agent, if using an API model."""
    api_key: Optional[str] = "token-abc123"
    """API key for the agent, if using an API model."""
    model_type: Optional[str] =  "TransformersModel"
    """Type of backbone model for the agent. One of: TransformersModel, HfApiModel (for now; will add support later)"""
    base_agent_type: Optional[str] = "CodeAgent"
    """Wrapper class for the agent. Use one of: ['CodeAgent', 'ToolCallingAgent'] (for now; may add support later)"""
    def __post_init__(self):
        if self.model_type in ["OpenAIServerModel"]:
            # Make sure api_base and api_key are set
            if not self.api_base:
                raise ValueError("api_base must be set for OpenAIServerModel")



@dataclass
class EndPointConfig(Serializable):
    """
    Configuration to capture the endpoint details for the agent.
    """
    ip: str
    """Endpoint IP of the agent."""
    port: int
    """Endpoint port of the agent."""
    device_name: str
    """Name of the device."""
    def __post_init__(self):
        if self.port <= 0 or self.port > 65535:
            raise ValueError("Port must be between 1 and 65535")


@dataclass
class AgentConfig(Serializable):
    """
    Configuration for an agent.
    This includes the agent's name, description, local agent configuration, endpoint details, and contact rule-book.
    """
    name: str
    """Name of the agent."""
    description: str
    """Description of the agent."""
    local_agent_config: LocalAgentConfig
    """Config to use for the local agent."""
    endpoint: EndPointConfig
    """Endpoint details for where the agent will be hosted."""
    contact_rulebook: Optional[List[str]] = field(default_factory=list)
    """Contact rule-book for this particular agent (who can contact it, etc.)"""
    num_one_time_keys: Optional[int] = 100
    """Number of one-time-keys to generate for this agent. Defaults to 100"""


@dataclass
class UserConfig(Serializable):
    """
    Configuration for a user.
    """
    name: str
    """Name of the user."""
    email: str
    """Email ID of the user."""
    agents: List[AgentConfig] = field(default_factory=list)
    """List of agents associated with the user."""


def get_index_of_agent(config: UserConfig, agent_name: str) -> int:
    """
        Helper function to get the index of an agent (out of all agents) that matches a given name.

        Args:
            config (UserConfig): The user configuration containing the agents.
            agent_name (str): The name of the agent to find.
        Returns:
            int: The index of the agent in the list of agents, or None if not found.
    """
    # Find the index of the "writing_agent" out of all config.agents
    agent_index = next((i for i, agent in enumerate(config.agents) if agent.name == agent_name), None)
    return agent_index
