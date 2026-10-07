"""Finding Confidence State Machine for Pentrare.

Enforces explicit, deterministic state transitions for security research findings.
Prevents ungrounded confidence escalation and supports rigorous downgrade
behavior when contradictory or insufficient evidence appears.

State Hierarchy:
    FALSE_POSITIVE  <- Contradictory evidence proves intended security control
    UNCONFIRMED     <- Insufficient or missing evidence (baseline state)
    POSSIBLE        <- Weak, indirect, or ambiguous supporting evidence
    LIKELY          <- Multiple consistent supporting observations, but incomplete proof
    CONFIRMED       <- Conclusive empirical proof of unauthorized boundary violation
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class FindingState(str, Enum):
    """Formal finding validation states."""

    UNCONFIRMED = "UNCONFIRMED"
    POSSIBLE = "POSSIBLE"
    LIKELY = "LIKELY"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class EvidenceStrengthLevel(str, Enum):
    """Evidence strength levels supporting finding states."""

    NONE = "NONE"
    WEAK = "WEAK"
    MODERATE = "MODERATE"
    STRONG = "STRONG"
    CONCLUSIVE = "CONCLUSIVE"


class ConfidenceRating(str, Enum):
    """Confidence ratings calibrated to evidence strength."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class TransitionReason(str, Enum):
    """Auditable reasons for finding state transitions."""

    NO_EVIDENCE = "NO_EVIDENCE"
    INSUFFICIENT_OBSERVATIONS = "INSUFFICIENT_OBSERVATIONS"
    WEAK_SINGLE_OBSERVATION = "WEAK_SINGLE_OBSERVATION"
    MULTIPLE_CONSISTENT_OBSERVATIONS = "MULTIPLE_CONSISTENT_OBSERVATIONS"
    CONCLUSIVE_PROOF_ESTABLISHED = "CONCLUSIVE_PROOF_ESTABLISHED"
    CONTRADICTION_DETECTED = "CONTRADICTION_DETECTED"
    CONTROL_ACTIVELY_ENFORCED = "CONTROL_ACTIVELY_ENFORCED"
    SCOPE_UNAUTHORIZED = "SCOPE_UNAUTHORIZED"
    INJECTION_QUARANTINED = "INJECTION_QUARANTINED"
    EVIDENCE_DOWNGRADED = "EVIDENCE_DOWNGRADED"


class FindingConfidenceStateMachine:
    """Deterministic state machine governing finding validation and confidence."""

    # Explicit transition matrix: (from_state, to_state) -> allowed
    VALID_TRANSITIONS: Set[Tuple[FindingState, FindingState]] = {
        # Initial evaluations from UNCONFIRMED
        (FindingState.UNCONFIRMED, FindingState.UNCONFIRMED),
        (FindingState.UNCONFIRMED, FindingState.POSSIBLE),
        (FindingState.UNCONFIRMED, FindingState.LIKELY),
        (FindingState.UNCONFIRMED, FindingState.CONFIRMED),
        (FindingState.UNCONFIRMED, FindingState.FALSE_POSITIVE),

        # Upgrades / lateral transitions
        (FindingState.POSSIBLE, FindingState.LIKELY),
        (FindingState.POSSIBLE, FindingState.CONFIRMED),
        (FindingState.POSSIBLE, FindingState.FALSE_POSITIVE),
        (FindingState.POSSIBLE, FindingState.UNCONFIRMED),

        (FindingState.LIKELY, FindingState.CONFIRMED),
        (FindingState.LIKELY, FindingState.FALSE_POSITIVE),
        (FindingState.LIKELY, FindingState.POSSIBLE),
        (FindingState.LIKELY, FindingState.UNCONFIRMED),

        # Downgrades from CONFIRMED (rigorous falsification)
        (FindingState.CONFIRMED, FindingState.LIKELY),
        (FindingState.CONFIRMED, FindingState.POSSIBLE),
        (FindingState.CONFIRMED, FindingState.FALSE_POSITIVE),
        (FindingState.CONFIRMED, FindingState.UNCONFIRMED),

        # Transitions from FALSE_POSITIVE (if new counter-evidence proves false alarm was wrong)
        (FindingState.FALSE_POSITIVE, FindingState.UNCONFIRMED),
        (FindingState.FALSE_POSITIVE, FindingState.POSSIBLE),
    }

    @classmethod
    def evaluate(
        cls,
        current_state: FindingState = FindingState.UNCONFIRMED,
        supporting_count: int = 0,
        contradicting_count: int = 0,
        all_conclusive: bool = False,
        has_injection: bool = False,
        scope_authorized: bool = True,
    ) -> Tuple[FindingState, EvidenceStrengthLevel, ConfidenceRating, TransitionReason]:
        """Determine next finding state based on rigorous deterministic rules.

        Args:
            current_state: Current state of the finding.
            supporting_count: Number of valid, non-contradicting supporting observations.
            contradicting_count: Number of contradicting observations (e.g. 401/403/rejection).
            all_conclusive: True if supporting observations represent conclusive proof.
            has_injection: True if evidence contains prompt-injection directives (triggers quarantine).
            scope_authorized: True if asset has confirmed in-scope authorization.

        Returns:
            Tuple of (new_state, evidence_strength, confidence, reason)
        """
        # Rule 1: Prompt-Injection Quarantine (Security Defense)
        # Any hostile prompt injection directives in evidence freeze classification at UNCONFIRMED
        if has_injection:
            return (
                FindingState.UNCONFIRMED,
                EvidenceStrengthLevel.NONE,
                ConfidenceRating.LOW,
                TransitionReason.INJECTION_QUARANTINED,
            )

        # Rule 2: Scope Boundary Enforcement
        # Findings cannot be CONFIRMED if scope is unauthorized or unknown
        if not scope_authorized:
            if contradicting_count > 0 and supporting_count == 0:
                target_state = FindingState.FALSE_POSITIVE
            elif supporting_count > 0:
                # Cap at POSSIBLE due to scope uncertainty
                target_state = FindingState.POSSIBLE
            else:
                target_state = FindingState.UNCONFIRMED
            return (
                target_state,
                EvidenceStrengthLevel.WEAK if supporting_count > 0 else EvidenceStrengthLevel.NONE,
                ConfidenceRating.LOW,
                TransitionReason.SCOPE_UNAUTHORIZED,
            )

        # Rule 3: Contradiction Only -> False Positive
        # Observations prove the security control is actively enforced
        if supporting_count == 0 and contradicting_count > 0:
            return (
                FindingState.FALSE_POSITIVE,
                EvidenceStrengthLevel.STRONG,
                ConfidenceRating.HIGH,
                TransitionReason.CONTROL_ACTIVELY_ENFORCED,
            )

        # Rule 4: Zero Evidence -> Unconfirmed
        if supporting_count == 0 and contradicting_count == 0:
            return (
                FindingState.UNCONFIRMED,
                EvidenceStrengthLevel.NONE,
                ConfidenceRating.LOW,
                TransitionReason.NO_EVIDENCE,
            )

        # Rule 5: Conflicting Evidence (both supporting and contradicting) -> Downgrade to POSSIBLE
        if supporting_count > 0 and contradicting_count > 0:
            return (
                FindingState.POSSIBLE,
                EvidenceStrengthLevel.WEAK,
                ConfidenceRating.LOW,
                TransitionReason.CONTRADICTION_DETECTED,
            )

        # Rule 6: Single Supporting Observation
        if supporting_count == 1:
            if all_conclusive:
                return (
                    FindingState.LIKELY,
                    EvidenceStrengthLevel.MODERATE,
                    ConfidenceRating.MEDIUM,
                    TransitionReason.MULTIPLE_CONSISTENT_OBSERVATIONS,
                )
            return (
                FindingState.POSSIBLE,
                EvidenceStrengthLevel.WEAK,
                ConfidenceRating.LOW,
                TransitionReason.WEAK_SINGLE_OBSERVATION,
            )

        # Rule 7: Two Supporting Observations
        if supporting_count == 2:
            if all_conclusive:
                # Conclusive cross-user boundary violation demonstrated
                return (
                    FindingState.CONFIRMED,
                    EvidenceStrengthLevel.STRONG,
                    ConfidenceRating.HIGH,
                    TransitionReason.CONCLUSIVE_PROOF_ESTABLISHED,
                )
            return (
                FindingState.LIKELY,
                EvidenceStrengthLevel.MODERATE,
                ConfidenceRating.MEDIUM,
                TransitionReason.MULTIPLE_CONSISTENT_OBSERVATIONS,
            )

        # Rule 8: Three or More Supporting Observations
        if supporting_count >= 3:
            return (
                FindingState.CONFIRMED,
                EvidenceStrengthLevel.STRONG if not all_conclusive else EvidenceStrengthLevel.CONCLUSIVE,
                ConfidenceRating.HIGH,
                TransitionReason.CONCLUSIVE_PROOF_ESTABLISHED,
            )

        # Fallback safe default
        return (
            FindingState.UNCONFIRMED,
            EvidenceStrengthLevel.NONE,
            ConfidenceRating.LOW,
            TransitionReason.INSUFFICIENT_OBSERVATIONS,
        )

    @classmethod
    def can_transition(cls, from_state: FindingState, to_state: FindingState) -> bool:
        """Check if transition between states is permissible."""
        return (from_state, to_state) in cls.VALID_TRANSITIONS
