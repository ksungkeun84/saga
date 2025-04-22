"""
    Definitions for configurations.
"""
from dataclasses import dataclass, field
from typing import Optional, List
from simple_parsing.helpers import Serializable


@dataclass
class EndPoint(Serializable):
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
    name: str
    """Name of the agent."""
    model: str
    """The actual model (LLM) to use"""
    description: str
    """Description of the agent."""
    endpoint: EndPoint
    """Endpoint details for where the agent will be hosted."""
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
    contact_rulebook: Optional[List[str]] = field(default_factory=list)
    """Contact rule-book for this particular agent (who can contact it, etc.)"""
    num_one_time_keys: Optional[int] = 100
    """Number of one-time-keys to generate for this agent. Defaults to 100"""
    def __post_init__(self):
        if self.model_type in ["OpenAIServerModel"]:
            # Make sure api_base and api_key are set
            if not self.api_base:
                raise ValueError("api_base must be set for OpenAIServerModel")


@dataclass
class UserConfig(Serializable):
    name: str
    """Name of the user."""
    email: str
    """Email ID of the user."""


    # TODO: Implement this later
    # agents_contact_list: List[str]
    # """List of agents that I can contact"""
    agents: List[AgentConfig] = field(default_factory=list)
    """List of agents associated with the user."""


def get_index_of_agent(config: UserConfig, agent_name: str):
    """
        Get the index out of all agents that matches a given name for agent
    """
    # Find the index of the "writing_agent" out of all config.agents
    agent_index = next((i for i, agent in enumerate(config.agents) if agent.name == agent_name), None)
    return agent_index
