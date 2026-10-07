"""Pydantic models for Phase 10 evaluation framework.

Ground truth is always defined statically before evaluation.
These models encode scenario data, ground-truth criteria, per-scenario
results, and final benchmark metrics.

IMPORTANT: Ground truth is NEVER generated or modified by an LLM.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ScenarioCategory(str, Enum):
    """Benchmark scenario category aligned with Phase 10 specification."""

    NO_FINDING = "A_NO_FINDING"
    WEAK_EVIDENCE = "B_WEAK_EVIDENCE"
    POSSIBLE_FINDING = "C_POSSIBLE_FINDING"
    STRONG_FINDING = "D_STRONG_FINDING"
    FALSE_POSITIVE = "E_FALSE_POSITIVE"
    CONTRADICTION = "F_CONTRADICTION"
    SECURITY_ROBUSTNESS = "G_SECURITY_ROBUSTNESS"


class EvalVerdict(str, Enum):
    """Overall evaluation verdict."""

    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


# ---------------------------------------------------------------------------
# Ground-Truth Criteria
# ---------------------------------------------------------------------------


class GroundTruth(BaseModel):
    """Static, immutable ground truth for a benchmark scenario.

    Must be defined before evaluation.  Never modified by an LLM.
    """

    expected_classification: str
    """Expected finding classification (CONFIRMED/LIKELY/POSSIBLE/UNCONFIRMED/FALSE_POSITIVE/NONE)."""

    expected_evidence_strength: str
    """Expected evidence strength (NONE/WEAK/MODERATE/STRONG/CONCLUSIVE)."""

    expected_confidence: str
    """Expected confidence level (LOW/MEDIUM/HIGH)."""

    expected_supporting_obs_ids: List[str] = Field(default_factory=list)
    """Observation IDs that should be cited as supporting."""

    expected_contradiction_present: bool = False
    """Whether at least one contradicting observation should be surfaced."""

    expected_missing_evidence: List[str] = Field(default_factory=list)
    """List of missing evidence types the system should surface."""

    expected_impact_grounded: bool = True
    """Whether the observed impact is empirically grounded (not theoretical)."""

    injection_should_be_blocked: bool = False
    """For security-robustness scenarios: injection must NOT alter outcome."""

    secret_must_be_redacted: bool = False
    """For secret-leakage scenarios: all raw secrets must be absent from output."""

    acceptable_classifications: List[str] = Field(default_factory=list)
    """Optional: wider set of acceptable classifications (besides exact match)."""


# ---------------------------------------------------------------------------
# Scenario definition
# ---------------------------------------------------------------------------


class SyntheticObservation(BaseModel):
    """A single synthetic researcher observation."""

    obs_id: str
    content: str
    is_supporting: bool = True
    is_contradicting: bool = False
    is_conclusive: bool = False
    """True when this observation alone constitutes irrefutable empirical proof
    of an authorization boundary violation (e.g., confirmed successful cross-user
    write with matching response body).  When all supporting observations in a
    scenario are conclusive, the deterministic classifier escalates 2-supporting
    cases from LIKELY to CONFIRMED / STRONG."""


class EvalScenario(BaseModel):
    """A single synthetic security research evaluation scenario."""

    scenario_id: str
    category: ScenarioCategory
    description: str
    scope: str = "IN_SCOPE"
    asset_name: str = "synthetic-target.local"
    asset_type: str = "web_application"
    objective: str
    hypothesis: str
    evidence_content: str
    """Raw artifact text the researcher supplies (may include injections or secrets)."""

    observations: List[SyntheticObservation] = Field(default_factory=list)
    """Pre-parsed observations from the evidence."""

    ground_truth: GroundTruth


# ---------------------------------------------------------------------------
# Per-scenario result
# ---------------------------------------------------------------------------


class ScenarioResult(BaseModel):
    """Captured result for a single evaluated scenario."""

    scenario_id: str
    category: ScenarioCategory
    passed: bool

    predicted_classification: Optional[str] = None
    predicted_evidence_strength: Optional[str] = None
    predicted_confidence: Optional[str] = None
    cited_obs_ids: List[str] = Field(default_factory=list)
    contradictions_found: bool = False
    missing_evidence_surfaced: List[str] = Field(default_factory=list)
    impact_grounded: bool = True

    injection_blocked: bool = True
    """True if no injection-induced policy change was detected."""

    secret_redacted: bool = True
    """True if no raw secret appeared in outputs."""

    is_false_confirmation: bool = False
    """True when system confirmed a ground-truth non-finding (critical failure)."""

    failure_reasons: List[str] = Field(default_factory=list)
    latency_ms: Optional[float] = None
    notes: str = ""


# ---------------------------------------------------------------------------
# Benchmark metrics
# ---------------------------------------------------------------------------


class RetrievalMetrics(BaseModel):
    """Retrieval quality metrics for the hybrid KnowledgeRetriever."""

    query_count: int = 0
    recall_at_5_lexical: float = 0.0
    recall_at_5_semantic: float = 0.0
    recall_at_5_hybrid: float = 0.0
    precision_at_5_lexical: float = 0.0
    precision_at_5_semantic: float = 0.0
    precision_at_5_hybrid: float = 0.0
    mrr_lexical: float = 0.0
    mrr_semantic: float = 0.0
    mrr_hybrid: float = 0.0
    notes: str = ""


class BenchmarkMetrics(BaseModel):
    """Aggregated metrics produced after a full benchmark run."""

    total_scenarios: int = 0
    passed_scenarios: int = 0
    failed_scenarios: int = 0

    # Classification
    classification_exact_match: float = 0.0
    classification_acceptable_range: float = 0.0

    # False confirmation (critical)
    false_confirmation_count: int = 0
    false_confirmation_rate: float = 0.0
    false_confirmation_scenario_ids: List[str] = Field(default_factory=list)

    # False negative
    false_negative_count: int = 0
    false_negative_rate: float = 0.0

    # Evidence strength
    evidence_strength_exact: float = 0.0

    # Citation accuracy
    citation_precision: float = 0.0
    citation_recall: float = 0.0

    # Contradiction detection
    contradiction_detection_rate: float = 0.0

    # Missing evidence surfacing
    missing_evidence_detection_rate: float = 0.0

    # Impact grounding
    impact_grounding_rate: float = 0.0

    # Security controls
    injection_blocked_count: int = 0
    injection_total_count: int = 0
    injection_resistance_rate: float = 0.0

    secret_redacted_count: int = 0
    secret_total_count: int = 0
    secret_redaction_rate: float = 0.0

    # Retrieval
    retrieval: Optional[RetrievalMetrics] = None

    # Performance
    total_runtime_ms: float = 0.0
    avg_scenario_latency_ms: float = 0.0


# ---------------------------------------------------------------------------
# Run configuration
# ---------------------------------------------------------------------------


class EvalRunConfig(BaseModel):
    """Configuration for an evaluation run."""

    benchmark_version: str = "1.0"
    offline_mode: bool = True
    ai_mode: bool = False
    scenario_ids: Optional[List[str]] = None
    category_filter: Optional[str] = None
    limit: Optional[int] = None
    verbose: bool = False
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Complete evaluation report
# ---------------------------------------------------------------------------


class EvaluationReport(BaseModel):
    """Full evaluation report combining config, metrics, scenario results, and verdict."""

    config: EvalRunConfig
    metrics: BenchmarkMetrics
    scenario_results: List[ScenarioResult] = Field(default_factory=list)

    verdict: EvalVerdict = EvalVerdict.PASS
    critical_failures: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)

    # Pass/Warn/Fail thresholds (documented, not hard-coded to expectations)
    pass_thresholds: Dict[str, Any] = Field(default_factory=dict)
