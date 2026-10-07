"""Phase 5 Pydantic data models for structured research project intelligence."""

import json
import re
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ScopeStatus(str, Enum):
    """Authorization / scope classification for an asset."""
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNKNOWN = "UNKNOWN"


class AssetType(str, Enum):
    """Asset category taxonomy."""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    URL = "url"
    API = "api"
    WEB_APPLICATION = "web_application"
    MOBILE_APPLICATION = "mobile_application"
    REPOSITORY = "repository"
    SERVICE = "service"
    CLOUD_RESOURCE = "cloud_resource"
    OTHER = "other"


class ObjectiveStatus(str, Enum):
    """Lifecycle status of a research objective."""
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    BLOCKED = "BLOCKED"
    COMPLETED = "COMPLETED"


class ObjectivePriority(str, Enum):
    """Priority level of a research objective."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class HypothesisStatus(str, Enum):
    """State of a research hypothesis after testing."""
    UNTESTED = "UNTESTED"
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ConfidenceLevel(str, Enum):
    """Confidence attached to a hypothesis or evidence item."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class EvidenceStrength(str, Enum):
    """Empirical strength of researcher-collected evidence supporting a claim."""
    NONE = "NONE"
    WEAK = "WEAK"
    MODERATE = "MODERATE"
    STRONG = "STRONG"
    CONCLUSIVE = "CONCLUSIVE"

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            return self.value.upper() == other.strip().upper()
        if isinstance(other, EvidenceStrength):
            return self.value == other.value
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash(self.value)


class EvidenceType(str, Enum):
    """Category of researcher-supplied evidence."""
    OBSERVATION = "OBSERVATION"
    HTTP_REQUEST = "HTTP_REQUEST"
    HTTP_RESPONSE = "HTTP_RESPONSE"
    SCREENSHOT = "SCREENSHOT"
    LOG = "LOG"
    SOURCE_CODE = "SOURCE_CODE"
    CONFIGURATION = "CONFIGURATION"
    DOCUMENT = "DOCUMENT"
    RESEARCHER_NOTE = "RESEARCHER_NOTE"
    OTHER = "OTHER"


class ActivityEventType(str, Enum):
    """Types of research timeline events."""
    PROJECT_CREATED = "PROJECT_CREATED"
    ASSET_ADDED = "ASSET_ADDED"
    OBJECTIVE_CREATED = "OBJECTIVE_CREATED"
    HYPOTHESIS_CREATED = "HYPOTHESIS_CREATED"
    EVIDENCE_ADDED = "EVIDENCE_ADDED"
    FINDING_CREATED = "FINDING_CREATED"
    FINDING_UPDATED = "FINDING_UPDATED"
    NOTE_ADDED = "NOTE_ADDED"
    VALIDATION_COMPLETED = "VALIDATION_COMPLETED"
    SCOPE_UPDATED = "SCOPE_UPDATED"
    ARTIFACT_IMPORTED = "ARTIFACT_IMPORTED"
    ARTIFACT_DUPLICATE = "ARTIFACT_DUPLICATE"
    ARTIFACT_PARSED = "ARTIFACT_PARSED"
    OBSERVATION_CREATED = "OBSERVATION_CREATED"
    ANALYSIS_COMPLETED = "ANALYSIS_COMPLETED"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"
    EVIDENCE_LINKED = "EVIDENCE_LINKED"


# ---------------------------------------------------------------------------
# Read-models (populated from database rows)
# ---------------------------------------------------------------------------


class ProjectScope(BaseModel):
    """Scope constraints for a research project."""

    id: int
    project_id: int
    in_scope_assets: List[str] = Field(default_factory=list)
    out_of_scope_assets: List[str] = Field(default_factory=list)
    allowed_testing_notes: Optional[str] = None
    prohibited_actions: Optional[str] = None
    authorization_notes: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @field_validator("in_scope_assets", "out_of_scope_assets", mode="before")
    @classmethod
    def parse_json_list(cls, v: Any) -> List[str]:
        if isinstance(v, list):
            return v
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                return parsed if isinstance(parsed, list) else []
            except (json.JSONDecodeError, ValueError):
                return []
        return []


class Asset(BaseModel):
    """A researcher-supplied asset within a project."""

    id: int
    project_id: int
    name: str
    asset_type: AssetType = AssetType.OTHER
    identifier: Optional[str] = None
    scope_status: ScopeStatus = ScopeStatus.UNKNOWN
    technology: Optional[str] = None
    notes: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class ResearchObjective(BaseModel):
    """A scoped research objective within a project."""

    id: int
    project_id: int
    title: str
    description: Optional[str] = None
    priority: ObjectivePriority = ObjectivePriority.MEDIUM
    status: ObjectiveStatus = ObjectiveStatus.OPEN
    notes: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class Hypothesis(BaseModel):
    """A testable hypothesis within a research project.

    A hypothesis is NOT a finding. It must NOT be marked CONFIRMED
    without sufficient researcher-supplied evidence and explicit validation.
    """

    id: int
    project_id: int
    objective_id: Optional[int] = None
    title: str
    description: Optional[str] = None
    rationale: Optional[str] = None
    status: HypothesisStatus = HypothesisStatus.UNTESTED
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class ResearchEvidence(BaseModel):
    """Researcher-supplied evidence associated with a hypothesis.

    The system must NEVER fabricate evidence. Only researcher-supplied
    data is stored here. Missing evidence remains missing.
    """

    id: int
    project_id: int
    hypothesis_id: Optional[int] = None
    evidence_type: EvidenceType = EvidenceType.OBSERVATION
    title: str
    description: Optional[str] = None
    content: Optional[str] = None
    source: Optional[str] = None
    timestamp: Optional[str] = None
    researcher_note: Optional[str] = None
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    created_at: Optional[str] = None

    @field_validator("evidence_type", mode="before")
    @classmethod
    def parse_evidence_type(cls, v: Any) -> EvidenceType:
        if isinstance(v, EvidenceType):
            return v
        if isinstance(v, str):
            v_upper = v.upper()
            for et in EvidenceType:
                if et.value == v_upper:
                    return et
            mapping = {
                "HTTP": EvidenceType.HTTP_RESPONSE,
                "HAR": EvidenceType.HTTP_RESPONSE,
                "JSON": EvidenceType.OBSERVATION,
                "CSV": EvidenceType.OBSERVATION,
                "TEXT": EvidenceType.OBSERVATION,
                "MARKDOWN": EvidenceType.DOCUMENT,
                "IMAGE": EvidenceType.SCREENSHOT,
            }
            if v_upper in mapping:
                return mapping[v_upper]
        return EvidenceType.OTHER


class ProjectActivity(BaseModel):
    """A timeline event in the research project activity log."""

    id: int
    project_id: int
    event_type: ActivityEventType
    description: Optional[str] = None
    timestamp: Optional[str] = None


# ---------------------------------------------------------------------------
# AI service output models
# ---------------------------------------------------------------------------


class ResearchPlan(BaseModel):
    """Structured output from the ResearchPlanner AI service.

    Represents a PLANNING AID only. None of these are findings.
    All hypotheses are UNTESTED. The researcher performs all active testing.
    """

    project_id: int
    objective_title: str
    relevant_concepts: List[str] = Field(default_factory=list)
    suggested_hypotheses: List[str] = Field(default_factory=list)
    evidence_needed: List[str] = Field(default_factory=list)
    validation_questions: List[str] = Field(default_factory=list)
    potential_finding_categories: List[str] = Field(default_factory=list)
    knowledge_sources: List[str] = Field(default_factory=list)
    warning: str = ""


class ValidationResult(BaseModel):
    """Output from the Finding Validation Engine.

    Based solely on researcher-supplied evidence and project state.
    The engine never fabricates evidence or assumes methodology proves a vulnerability.
    """

    hypothesis_id: Optional[int] = None
    finding_id: Optional[int] = None
    is_evidence_sufficient: bool = False
    evidence_strength: EvidenceStrength = EvidenceStrength.NONE
    classification: str = "UNCONFIRMED"
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    reasoning: str = ""
    supporting_observations: List[str] = Field(default_factory=list)
    supporting_observation_ids: List[int] = Field(default_factory=list)
    contradictory_observations: List[str] = Field(default_factory=list)
    contradictory_observation_ids: List[int] = Field(default_factory=list)
    alternative_explanations: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    observed_impact: Optional[str] = None
    potential_impact: Optional[str] = None
    unsupported_impact: Optional[str] = None
    impact_assessment: Optional[str] = None
    validation_questions: List[str] = Field(default_factory=list)
    relevant_sources: List[str] = Field(default_factory=list)
    scope_warning: Optional[str] = None
    warning: str = ""
    validation_id: Optional[int] = None

    # Backward-compatibility fields
    evidence_summary: str = ""
    assumptions_identified: List[str] = Field(default_factory=list)
    additional_evidence_needed: List[str] = Field(default_factory=list)
    impact_logical: bool = False
    suggested_classification: Optional[str] = None
    rationale: str = ""

    @field_validator("evidence_strength", mode="before")
    @classmethod
    def parse_strength(cls, v: Any) -> EvidenceStrength:
        if isinstance(v, EvidenceStrength):
            return v
        if isinstance(v, str):
            v_upper = v.strip().upper()
            for s in EvidenceStrength:
                if s.value == v_upper:
                    return s
            if "STRONG" in v_upper:
                return EvidenceStrength.STRONG
            if "MODERATE" in v_upper:
                return EvidenceStrength.MODERATE
            if "WEAK" in v_upper:
                return EvidenceStrength.WEAK
            if "CONCLUSIVE" in v_upper:
                return EvidenceStrength.CONCLUSIVE
            if "INSUFFICIENT" in v_upper or "NONE" in v_upper:
                return EvidenceStrength.NONE
        return EvidenceStrength.NONE

    @field_validator("confidence", mode="before")
    @classmethod
    def parse_confidence(cls, v: Any) -> ConfidenceLevel:
        if isinstance(v, ConfidenceLevel):
            return v
        if isinstance(v, str):
            v_upper = v.strip().upper()
            for c in ConfidenceLevel:
                if c.value == v_upper:
                    return c
        return ConfidenceLevel.LOW

    def model_post_init(self, __context: Any) -> None:
        # Synchronize backward-compatibility fields if not explicitly provided
        if not self.rationale and self.reasoning:
            self.rationale = self.reasoning
        elif not self.reasoning and self.rationale:
            self.reasoning = self.rationale

        if not self.suggested_classification:
            self.suggested_classification = self.classification
        elif not self.classification:
            self.classification = self.suggested_classification

        if not self.additional_evidence_needed and self.missing_evidence:
            self.additional_evidence_needed = list(self.missing_evidence)
        elif not self.missing_evidence and self.additional_evidence_needed:
            self.missing_evidence = list(self.additional_evidence_needed)

        if not self.evidence_summary and self.reasoning:
            self.evidence_summary = self.reasoning[:120]


# ---------------------------------------------------------------------------
# Phase 6: Research Orchestration & Project Context Models
# ---------------------------------------------------------------------------


class ProjectOverallState(str, Enum):
    """Workflow state of a research project."""
    INITIALIZING = "INITIALIZING"
    READY_FOR_RESEARCH = "READY_FOR_RESEARCH"
    RESEARCH_IN_PROGRESS = "RESEARCH_IN_PROGRESS"
    AWAITING_EVIDENCE = "AWAITING_EVIDENCE"
    VALIDATION_REQUIRED = "VALIDATION_REQUIRED"
    READY_FOR_REPORT = "READY_FOR_REPORT"
    BLOCKED = "BLOCKED"


class ProjectHealth(BaseModel):
    """Structured health assessment of a research project's workflow state.

    This represents WORKFLOW PROGRESSION, not an arbitrary numerical security score.
    """
    overall_state: ProjectOverallState
    scope_status: str
    objective_status: str
    hypothesis_status: str
    evidence_status: str
    finding_status: str
    blockers: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class TruncationInfo(BaseModel):
    """Metadata regarding context window limits and truncation."""
    truncated: bool = False
    truncated_categories: List[str] = Field(default_factory=list)
    total_items_counted: Dict[str, int] = Field(default_factory=dict)
    items_retained: Dict[str, int] = Field(default_factory=dict)


class ProjectRecord(BaseModel):
    """Metadata and core state of a research project."""
    id: int
    name: str
    description: Optional[str] = None
    status: str = "active"
    research_goal: Optional[str] = None
    scope_summary: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class FindingRecord(BaseModel):
    """Read-model for a finding record from the database."""
    id: int
    project_id: int
    title: str
    severity: str = "Unknown"
    classification: str = "UNCONFIRMED"
    affected_asset: Optional[str] = None
    summary: Optional[str] = None
    technical_details: Optional[str] = None
    impact: Optional[str] = None
    root_cause: Optional[str] = None
    remediation: Optional[str] = None
    evidence_ids: List[int] = Field(default_factory=list)
    validation_status: str = "UNCONFIRMED"
    confidence: str = "LOW"
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @field_validator("evidence_ids", mode="before")
    @classmethod
    def parse_evidence_ids(cls, v: Any) -> List[int]:
        if isinstance(v, list):
            return [int(x) for x in v if str(x).isdigit()]
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return [int(x) for x in parsed if str(x).isdigit()]
            except (json.JSONDecodeError, ValueError):
                return []
        return []


class ProjectContext(BaseModel):
    """Bounded, strongly typed, deterministic project context snapshot.

    Never contains system secrets, API keys, or raw credential dumps.
    """
    project: ProjectRecord
    scope: Optional[ProjectScope] = None
    assets: List[Asset] = Field(default_factory=list)
    in_scope_assets: List[Asset] = Field(default_factory=list)
    out_of_scope_assets: List[Asset] = Field(default_factory=list)
    unknown_scope_assets: List[Asset] = Field(default_factory=list)
    objectives: List[ResearchObjective] = Field(default_factory=list)
    open_objectives: List[ResearchObjective] = Field(default_factory=list)
    completed_objectives: List[ResearchObjective] = Field(default_factory=list)
    hypotheses: List[Hypothesis] = Field(default_factory=list)
    untested_hypotheses: List[Hypothesis] = Field(default_factory=list)
    evidence: List[ResearchEvidence] = Field(default_factory=list)
    findings: List[FindingRecord] = Field(default_factory=list)
    recent_activities: List[ProjectActivity] = Field(default_factory=list)
    knowledge_sources: List[str] = Field(default_factory=list)
    artifacts: List["EvidenceArtifact"] = Field(default_factory=list)
    observations: List["Observation"] = Field(default_factory=list)
    latest_validations: List["ValidationRecord"] = Field(default_factory=list)
    latest_reports: List["ReportRecord"] = Field(default_factory=list)
    reports_count: int = 0
    truncation: TruncationInfo = Field(default_factory=TruncationInfo)


class ResearchRecommendation(BaseModel):
    """A recommended research inquiry or evidence-collection direction.

    HUMAN-IN-THE-LOOP CHECKPOINT: This is an action recommendation for the
    researcher. It does NOT execute autonomous attacks or scans.
    """
    title: str
    objective_id: Optional[int] = None
    hypothesis_id: Optional[int] = None
    rationale: str
    relevant_knowledge: List[str] = Field(default_factory=list)
    evidence_needed: List[str] = Field(default_factory=list)
    validation_questions: List[str] = Field(default_factory=list)
    priority: str = "MEDIUM"  # "HIGH", "MEDIUM", "LOW"
    confidence: str = "LOW"   # "HIGH", "MEDIUM", "LOW"
    blockers: List[str] = Field(default_factory=list)


class ResearchOrchestrationResult(BaseModel):
    """Complete output from the Research Orchestrator."""
    project_state_summary: str
    health: ProjectHealth
    blockers: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    recommendations: List[ResearchRecommendation] = Field(default_factory=list)
    next_best_question: str
    relevant_sources: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Phase 7: Evidence Intelligence & Artifact Analysis Models
# ---------------------------------------------------------------------------


class ArtifactType(str, Enum):
    """Supported artifact format types."""
    TEXT = "TEXT"
    MARKDOWN = "MARKDOWN"
    JSON = "JSON"
    HTTP = "HTTP"
    HAR = "HAR"
    LOG = "LOG"
    SOURCE_CODE = "SOURCE_CODE"
    CONFIGURATION = "CONFIGURATION"
    CSV = "CSV"
    IMAGE = "IMAGE"
    UNKNOWN = "UNKNOWN"


class ObservationCategory(str, Enum):
    """Taxonomy of factual observations extracted from artifacts."""
    HTTP_REQUEST = "HTTP_REQUEST"
    HTTP_RESPONSE = "HTTP_RESPONSE"
    HEADER = "HEADER"
    JSON_FIELD = "JSON_FIELD"
    LOG_EVENT = "LOG_EVENT"
    CODE_PATTERN = "CODE_PATTERN"
    CONFIGURATION = "CONFIGURATION"
    TIMING = "TIMING"
    ERROR = "ERROR"
    METADATA = "METADATA"
    OTHER = "OTHER"


class EvidenceArtifact(BaseModel):
    """Metadata for an ingested raw evidence artifact."""
    id: int
    project_id: int
    filename: str
    artifact_type: ArtifactType = ArtifactType.UNKNOWN
    source_path: Optional[str] = None
    content_hash: str
    size_bytes: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[str] = None

    @field_validator("metadata", mode="before")
    @classmethod
    def parse_metadata(cls, v: Any) -> Dict[str, Any]:
        if isinstance(v, dict):
            return v
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                return parsed if isinstance(parsed, dict) else {}
            except (json.JSONDecodeError, ValueError):
                return {}
        return {}


class Observation(BaseModel):
    """An individual, factual observation extracted from an artifact.

    CRITICAL: An observation is a verified technical fact, NOT a vulnerability conclusion.
    """
    id: int
    artifact_id: int
    project_id: int
    category: ObservationCategory = ObservationCategory.OTHER
    statement: str
    source_location: Optional[str] = None
    confidence: str = "MEDIUM"
    hypothesis_id: Optional[int] = None
    created_at: Optional[str] = None


class NormalizedEvidence(BaseModel):
    """Normalized, redacted representation of an artifact ready for analysis."""
    artifact_id: Optional[int] = None
    artifact_type: ArtifactType = ArtifactType.UNKNOWN
    title: str
    summary: str
    sections: Dict[str, str] = Field(default_factory=dict)
    observations: List[Observation] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    source_reference: str = ""
    is_redacted: bool = False

    @field_validator("metadata", mode="before")
    @classmethod
    def parse_metadata(cls, v: Any) -> Dict[str, Any]:
        if isinstance(v, dict):
            return v
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                return parsed if isinstance(parsed, dict) else {}
            except (json.JSONDecodeError, ValueError):
                return {}
        return {}


# ---------------------------------------------------------------------------
# Phase 8: Finding Validation Engine Models
# ---------------------------------------------------------------------------


class ValidationAnalysis(BaseModel):
    """Structured model output from Gemini Finding Validation Engine."""
    classification: str = "UNCONFIRMED"
    evidence_strength: str = "NONE"
    confidence: str = "LOW"
    reasoning: str = ""
    supporting_observation_ids: List[int] = Field(default_factory=list)
    contradictory_observation_ids: List[int] = Field(default_factory=list)
    alternative_explanations: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    observed_impact: Optional[str] = None
    potential_impact: Optional[str] = None
    unsupported_impact: Optional[str] = None
    validation_questions: List[str] = Field(default_factory=list)
    knowledge_source_ids: List[str] = Field(default_factory=list)

    @field_validator(
        "supporting_observation_ids",
        "contradictory_observation_ids",
        mode="before",
    )
    @classmethod
    def parse_int_ids(cls, v: Any) -> List[int]:
        if isinstance(v, list):
            res = []
            for item in v:
                if isinstance(item, int):
                    res.append(item)
                elif isinstance(item, str):
                    digits = re.findall(r"\d+", item)
                    if digits:
                        res.append(int(digits[0]))
            return res
        return []


class ValidationRecord(BaseModel):
    """Database record of an immutable finding validation audit entry."""
    id: int
    project_id: int
    finding_id: Optional[int] = None
    hypothesis_id: Optional[int] = None
    classification: str = "UNCONFIRMED"
    evidence_strength: str = "NONE"
    confidence: str = "LOW"
    reasoning: Optional[str] = None
    supporting_observation_ids: List[int] = Field(default_factory=list)
    contradictory_observation_ids: List[int] = Field(default_factory=list)
    alternative_explanations: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    observed_impact: Optional[str] = None
    potential_impact: Optional[str] = None
    unsupported_impact: Optional[str] = None
    validation_questions: List[str] = Field(default_factory=list)
    knowledge_sources: List[str] = Field(default_factory=list)
    created_at: Optional[str] = None

    @field_validator(
        "supporting_observation_ids",
        "contradictory_observation_ids",
        "alternative_explanations",
        "missing_evidence",
        "validation_questions",
        "knowledge_sources",
        mode="before",
    )
    @classmethod
    def parse_json_lists(cls, v: Any) -> List[Any]:
        if isinstance(v, list):
            return v
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                return parsed if isinstance(parsed, list) else []
            except (json.JSONDecodeError, ValueError):
                return []
        return []


# ---------------------------------------------------------------------------
# Phase 9: Security Report Generation Engine Models
# ---------------------------------------------------------------------------


class ReportStatus(str, Enum):
    """Lifecycle status of a security report."""
    DRAFT = "DRAFT"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    APPROVED = "APPROVED"
    EXPORTED = "EXPORTED"


class ReportFormat(str, Enum):
    """Output format for security reports."""
    MARKDOWN = "MARKDOWN"
    JSON = "JSON"


class ReportTemplateType(str, Enum):
    """Template type governing layout, depth, and tone."""
    BUG_BOUNTY = "BUG_BOUNTY"
    INTERNAL = "INTERNAL"
    RESEARCH_VALIDATION = "RESEARCH_VALIDATION"


class ObservationCitation(BaseModel):
    """Citation linking a report statement directly to a verified observation."""
    observation_id: int
    artifact_name: str
    source_location: Optional[str] = None
    statement: str


class ReportAnalysis(BaseModel):
    """Structured report synthesis model output from AI or deterministic engine."""
    title: str = ""
    executive_summary: str = ""
    affected_asset: str = ""
    asset_scope_status: str = "UNKNOWN"
    classification: str = "UNCONFIRMED"
    severity: str = "Unknown"
    evidence_strength: str = "NONE"
    technical_details: str = ""
    steps_to_reproduce: List[str] = Field(default_factory=list)
    expected_behavior: str = ""
    observed_behavior: str = ""
    observed_impact: str = ""
    potential_impact: str = ""
    unsupported_impact_claims: List[str] = Field(default_factory=list)
    root_cause_analysis: str = ""
    remediation_guidance: str = ""
    alternative_explanations: List[str] = Field(default_factory=list)
    reproduction_gap_analysis: Optional[str] = None
    referenced_observation_ids: List[int] = Field(default_factory=list)
    knowledge_citations: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

    @field_validator(
        "title",
        "executive_summary",
        "affected_asset",
        "asset_scope_status",
        "classification",
        "severity",
        "evidence_strength",
        "technical_details",
        "expected_behavior",
        "observed_behavior",
        "observed_impact",
        "potential_impact",
        "root_cause_analysis",
        "remediation_guidance",
        mode="before",
    )
    @classmethod
    def ensure_str(cls, v: Any) -> str:
        return str(v) if v is not None else ""

    @field_validator("referenced_observation_ids", mode="before")
    @classmethod
    def parse_obs_ids(cls, v: Any) -> List[int]:
        if isinstance(v, list):
            res = []
            for item in v:
                if isinstance(item, int):
                    res.append(item)
                elif isinstance(item, str):
                    digits = re.findall(r"\d+", item)
                    if digits:
                        res.append(int(digits[0]))
            return res
        return []

    @field_validator(
        "steps_to_reproduce",
        "unsupported_impact_claims",
        "alternative_explanations",
        "knowledge_citations",
        "warnings",
        mode="before",
    )
    @classmethod
    def parse_str_lists(cls, v: Any) -> List[str]:
        if isinstance(v, list):
            return [str(x) for x in v]
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return [str(x) for x in parsed]
            except Exception:
                pass
            return [v] if v.strip() else []
        return []


class SecurityReport(BaseModel):
    """Complete, structured security report instance."""
    id: Optional[int] = None
    project_id: int
    finding_id: int
    validation_id: Optional[int] = None
    version: int = 1
    title: str
    template_type: ReportTemplateType = ReportTemplateType.BUG_BOUNTY
    status: ReportStatus = ReportStatus.DRAFT
    format: ReportFormat = ReportFormat.MARKDOWN
    content: str
    report_metadata: Dict[str, Any] = Field(default_factory=dict)
    content_hash: str = ""
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    analysis: Optional[ReportAnalysis] = None
    citations: List[ObservationCitation] = Field(default_factory=list)


class ReportRecord(BaseModel):
    """Read-model for a report entry stored in security_reports table."""
    id: int
    project_id: int
    finding_id: int
    validation_id: Optional[int] = None
    version: int = 1
    title: str
    template_type: str = "BUG_BOUNTY"
    status: str = "DRAFT"
    format: str = "MARKDOWN"
    content: str
    report_metadata: Dict[str, Any] = Field(default_factory=dict)
    content_hash: str
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @field_validator("report_metadata", mode="before")
    @classmethod
    def parse_metadata(cls, v: Any) -> Dict[str, Any]:
        if isinstance(v, dict):
            return v
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                return parsed if isinstance(parsed, dict) else {}
            except (json.JSONDecodeError, ValueError):
                return {}
        return {}


