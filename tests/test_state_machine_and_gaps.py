"""Tests for Finding Confidence State Machine, Missing Evidence Gap Analyzer, and Backup Hardening."""

import json
from pathlib import Path
import pytest

from app.research.state_machine import (
    ConfidenceRating,
    EvidenceStrengthLevel,
    FindingConfidenceStateMachine,
    FindingState,
    TransitionReason,
)
from app.research.evidence.gap_analyzer import MissingEvidenceAnalyzer
from app.storage.backup import verify_backup


class TestFindingConfidenceStateMachine:
    """Rigorous tests for the finding confidence state machine."""

    def test_zero_evidence_yields_unconfirmed(self):
        state, strength, conf, reason = FindingConfidenceStateMachine.evaluate(
            supporting_count=0, contradicting_count=0
        )
        assert state == FindingState.UNCONFIRMED
        assert strength == EvidenceStrengthLevel.NONE
        assert conf == ConfidenceRating.LOW
        assert reason == TransitionReason.NO_EVIDENCE

    def test_single_supporting_observation_yields_possible(self):
        state, strength, conf, reason = FindingConfidenceStateMachine.evaluate(
            supporting_count=1, contradicting_count=0, all_conclusive=False
        )
        assert state == FindingState.POSSIBLE
        assert strength == EvidenceStrengthLevel.WEAK
        assert conf == ConfidenceRating.LOW
        assert reason == TransitionReason.WEAK_SINGLE_OBSERVATION

    def test_two_conclusive_observations_yields_confirmed(self):
        state, strength, conf, reason = FindingConfidenceStateMachine.evaluate(
            supporting_count=2, contradicting_count=0, all_conclusive=True
        )
        assert state == FindingState.CONFIRMED
        assert strength == EvidenceStrengthLevel.STRONG
        assert conf == ConfidenceRating.HIGH
        assert reason == TransitionReason.CONCLUSIVE_PROOF_ESTABLISHED

    def test_two_non_conclusive_observations_yields_likely(self):
        state, strength, conf, reason = FindingConfidenceStateMachine.evaluate(
            supporting_count=2, contradicting_count=0, all_conclusive=False
        )
        assert state == FindingState.LIKELY
        assert strength == EvidenceStrengthLevel.MODERATE
        assert conf == ConfidenceRating.MEDIUM
        assert reason == TransitionReason.MULTIPLE_CONSISTENT_OBSERVATIONS

    def test_three_supporting_observations_yields_confirmed(self):
        state, strength, conf, reason = FindingConfidenceStateMachine.evaluate(
            supporting_count=3, contradicting_count=0
        )
        assert state == FindingState.CONFIRMED
        assert strength == EvidenceStrengthLevel.STRONG
        assert conf == ConfidenceRating.HIGH

    def test_contradiction_downgrades_to_false_positive(self):
        state, strength, conf, reason = FindingConfidenceStateMachine.evaluate(
            supporting_count=0, contradicting_count=1
        )
        assert state == FindingState.FALSE_POSITIVE
        assert conf == ConfidenceRating.HIGH
        assert reason == TransitionReason.CONTROL_ACTIVELY_ENFORCED

    def test_mixed_evidence_downgrades_to_possible(self):
        state, strength, conf, reason = FindingConfidenceStateMachine.evaluate(
            supporting_count=3, contradicting_count=1
        )
        assert state == FindingState.POSSIBLE
        assert strength == EvidenceStrengthLevel.WEAK
        assert conf == ConfidenceRating.LOW
        assert reason == TransitionReason.CONTRADICTION_DETECTED

    def test_prompt_injection_freezes_state_at_unconfirmed(self):
        state, strength, conf, reason = FindingConfidenceStateMachine.evaluate(
            supporting_count=5, contradicting_count=0, all_conclusive=True, has_injection=True
        )
        assert state == FindingState.UNCONFIRMED
        assert strength == EvidenceStrengthLevel.NONE
        assert conf == ConfidenceRating.LOW
        assert reason == TransitionReason.INJECTION_QUARANTINED

    def test_unauthorized_scope_prevents_confirmed(self):
        state, strength, conf, reason = FindingConfidenceStateMachine.evaluate(
            supporting_count=3, contradicting_count=0, scope_authorized=False
        )
        assert state == FindingState.POSSIBLE
        assert conf == ConfidenceRating.LOW
        assert reason == TransitionReason.SCOPE_UNAUTHORIZED

    def test_state_transitions_permissible(self):
        assert FindingConfidenceStateMachine.can_transition(FindingState.UNCONFIRMED, FindingState.LIKELY)
        assert FindingConfidenceStateMachine.can_transition(FindingState.CONFIRMED, FindingState.POSSIBLE)
        assert FindingConfidenceStateMachine.can_transition(FindingState.CONFIRMED, FindingState.FALSE_POSITIVE)


class TestMissingEvidenceGapAnalyzer:
    """Tests for algorithmic missing evidence gap analysis."""

    def test_detects_idor_gaps(self):
        gaps = MissingEvidenceAnalyzer.analyze_gaps(
            hypothesis="The user profile IDOR allows accessing other accounts.",
            observations=[{"statement": "Observed request to /user/1001", "is_supporting": True}],
        )
        assert len(gaps) > 0
        assert any("cross-user" in g.lower() or "independent" in g.lower() for g in gaps)

    def test_detects_auth_bypass_gaps(self):
        gaps = MissingEvidenceAnalyzer.analyze_gaps(
            hypothesis="Authentication bypass on /admin dashboard.",
            observations=[{"statement": "Access granted with token", "is_supporting": True}],
        )
        assert len(gaps) > 0
        assert any("baseline" in g.lower() or "without authentication" in g.lower() for g in gaps)

    def test_detects_contradiction_gaps(self):
        gaps = MissingEvidenceAnalyzer.analyze_gaps(
            hypothesis="Endpoint bypass.",
            observations=[
                {"statement": "Worked initially", "is_supporting": True},
                {"statement": "403 Forbidden returned subsequently", "is_contradicting": True},
            ],
        )
        assert len(gaps) > 0
        assert any("contradict" in g.lower() or "401" in g.lower() or "403" in g.lower() for g in gaps)


class TestBackupSecurityHardening:
    """Tests for path traversal protection in backup verification."""

    def test_rejects_manifest_with_directory_traversal(self, tmp_path):
        manifest = {
            "backup_version": "1.0",
            "database": {
                "filename": "../../etc/shadow",
                "sha256": "fake",
            },
            "vector_store": {"exists": False},
        }
        (tmp_path / "backup_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        result = verify_backup(tmp_path)
        assert not result["valid"]
        assert any("path traversal" in err for err in result["errors"])

    def test_rejects_manifest_with_vector_traversal(self, tmp_path):
        manifest = {
            "backup_version": "1.0",
            "database": {
                "filename": "researcher.db",
                "sha256": "fake",
            },
            "vector_store": {
                "exists": True,
                "filename": "../../../evil.npz",
            },
        }
        (tmp_path / "backup_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        result = verify_backup(tmp_path)
        assert not result["valid"]
        assert any("path traversal" in err for err in result["errors"])
