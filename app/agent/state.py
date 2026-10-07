"""Base Pydantic data models for agent state, scope, evidence, and findings."""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class FindingClassification(str, Enum):
    """Rigorous classification levels for security findings."""
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"
    UNCONFIRMED = "UNCONFIRMED"
    FALSE_POSITIVE = "FALSE POSITIVE"


class ResearchItemStatus(str, Enum):
    """Testing status of research checklist items."""
    NOT_TESTED = "Not Tested"
    IN_PROGRESS = "In Progress"
    TESTED_NO_ISSUE = "Tested - No Issue"
    FINDING_IDENTIFIED = "Finding Identified"


class ScopeItem(BaseModel):
    """Parsed scope constraints and program rules."""
    in_scope: List[str] = Field(default_factory=list)
    out_of_scope: List[str] = Field(default_factory=list)
    restrictions: List[str] = Field(default_factory=list)
    rate_limits: List[str] = Field(default_factory=list)
    required_conditions: List[str] = Field(default_factory=list)
    reporting_requirements: List[str] = Field(default_factory=list)
    raw_text: Optional[str] = None


class ArchitectureComponent(BaseModel):
    """Individual system component and boundary."""
    name: str
    component_type: str
    trust_boundary: str
    sensitive_data: List[str] = Field(default_factory=list)
    notes: Optional[str] = None


class ResearchItem(BaseModel):
    """Structured research checklist item."""
    id: str
    title: str
    security_area: str
    reason: str
    preconditions: str
    expected_behavior: str
    evidence_required: str
    risk: str
    status: ResearchItemStatus = ResearchItemStatus.NOT_TESTED
    relevant_knowledge_sources: List[str] = Field(default_factory=list)


class EvidenceItem(BaseModel):
    """Researcher-provided technical evidence."""
    evidence_type: str  # e.g., "HTTP_REQUEST", "HTTP_RESPONSE", "LOG", "CODE", "TRACE"
    description: str
    source_file: Optional[str] = None
    observed_behavior: str
    expected_behavior: str
    security_boundary: str
    raw_content: Optional[str] = None
    alternative_explanations: List[str] = Field(default_factory=list)


class Finding(BaseModel):
    """Validated security finding structure conforming to the reporting template."""
    title: str
    severity: str = "Unknown"
    classification: FindingClassification = FindingClassification.UNCONFIRMED
    affected_asset: str
    summary: str
    technical_details: str
    steps_to_reproduce: str
    evidence: str
    expected_behavior: str
    observed_behavior: str
    security_impact: str
    root_cause: str
    remediation: str
    validation_notes: str
    references: List[str] = Field(default_factory=list)


class ProjectState(BaseModel):
    """Complete in-memory research project workspace state."""
    name: str
    description: str = ""
    status: str = "active"
    scope: Optional[ScopeItem] = None
    components: List[ArchitectureComponent] = Field(default_factory=list)
    research_items: List[ResearchItem] = Field(default_factory=list)
    evidence_items: List[EvidenceItem] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
