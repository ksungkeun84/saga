"""
    Definitions for configurations.
"""
from dataclasses import dataclass, field
from typing import Optional, List
from simple_parsing.helpers import Serializable


@dataclass
class PassportConfig(Serializable):
    nationality: str
    """User's nationality"""
    passport_number: str
    """Passport number of the user."""
    country_of_issue: str
    """Country of issue of the passport."""
    issue_date: str
    """Issue date of the passport."""
    expiry_date: str
    """Expiry date of the passport."""


@dataclass
class MedicalInformationConfig(Serializable):
    insurance_number: str
    """Medical insurance number of the user."""
    insurance_provider: str
    """Medical insurance provider of the user."""


@dataclass
class AgentConfig(Serializable):
    name: str
    """Name of the agent."""
    description: str
    """Description of the agent."""
    model: str
    """Backbone model of the agent."""
    tools: List[str]
    """List of tools available to the agent."""
    additional_authorized_imports: List[str] = field(default_factory=list)
    """List of additional authorized imports for the agent."""
    model_type: str =  "TransformersModel"
    """Type of backbone model for the agent. One of: TransformersModel, HfApiModel (for now; will add support later)"""
    def __post_init__(self):
        allowed_model_types = ["TransformersModel", "HfApiModel"]
        if self.model_type not in allowed_model_types:
            raise ValueError("model_type must be one of:", allowed_model_types)


@dataclass
class UserConfig(Serializable):
    name: str
    """Name of the user."""
    phone_number: str
    """Phone number of the user."""
    email: str
    """Email ID of the user."""
    date_of_birth: str
    """Date of birth of the user."""
    current_address: str
    """Address of the user."""
    ssn: str
    """Social Security Number of the user."""
    age: int
    """Age of the user."""
    passport: PassportConfig
    """Passport information of the user."""
    medical_information: MedicalInformationConfig
    """Medical information of the user"""

    agents: List[AgentConfig] = field(default_factory=list)
    """List of agents associated with the user."""

    hobbies: List[str] = field(default_factory=list)
    """List of hobbies of the user."""
    dietary_preferences: str = ""
    """Dietary preferences of the user."""
    religion: str = "Agnostic"
    """Religion of the user."""
    lifestyle: str = ""
    """Lifestyle of the user."""
    travel_history: List[str] = field(default_factory=list)
    """Travel history of the user."""
    family_members: List[str] = field(default_factory=list)
    """List of family members of the user."""
    previous_education: List[str] = field(default_factory=list)
    """List of previous education of the user."""
    previous_employment: List[str] = field(default_factory=list)
    """List of previous employment of the user."""
    political_views: str = ""
    """Political views of the user."""
    media_preferences: List[str] = field(default_factory=list)
    """Media preferences of the user."""
 