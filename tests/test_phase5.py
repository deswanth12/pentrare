"""Phase 5 comprehensive test suite.

All tests:
- Use isolated temporary databases (never touch storage/researcher.db)
- Run offline (no Gemini API, no internet, no real targets)
- Mock all Gemini calls
- Verify safety boundaries (UNTESTED hypothesis, UNKNOWN default scope, no evidence fabrication)
"""

import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# Ensure project root on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.storage.database import DatabaseManager
from app.research.models import (
    Asset,
    AssetType,
    ConfidenceLevel,
    EvidenceType,
    Hypothesis,
    HypothesisStatus,
    ObjectivePriority,
    ObjectiveStatus,
    ProjectScope,
    ResearchEvidence,
    ResearchObjective,
    ResearchPlan,
    ScopeStatus,
    ValidationResult,
)


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """Isolated database in a temp directory — never touches researcher.db."""
    db_path = tmp_path / "test_phase5.db"
    monkeypatch.setenv("DATABASE_PATH", str(db_path))
    from app.config import get_settings
    get_settings(reload=True)

    db = DatabaseManager(db_path)
    db.init_db()

    yield db

    try:
        get_settings(reload=True)
    except Exception:
        pass


@pytest.fixture
def project(tmp_db):
    """Create a single test project."""
    return tmp_db.create_project("Audit-2025", "Synthetic test project")


@pytest.fixture
def project_with_scope(tmp_db, project):
    """Project with scope already set."""
    tmp_db.set_project_scope(
        project["id"],
        in_scope_assets=["example.com", "api.example.com"],
        out_of_scope_assets=["admin.example.com"],
        authorization_notes="Synthetic bug bounty program — test only",
    )
    return project


# ===========================================================================
# 1. Project Operations
# ===========================================================================


class TestProjectOperations:
    def test_create_project(self, tmp_db):
        p = tmp_db.create_project("TestProj", "A test project")
        assert p["id"] is not None
        assert p["name"] == "TestProj"
        assert p["status"] == "active"

    def test_get_project_by_id(self, tmp_db, project):
        fetched = tmp_db.get_project_by_id(project["id"])
        assert fetched is not None
        assert fetched["name"] == "Audit-2025"

    def test_get_project_by_id_missing(self, tmp_db):
        assert tmp_db.get_project_by_id(99999) is None

    def test_update_project_research_goal(self, tmp_db, project):
        updated = tmp_db.update_project(project["id"], research_goal="Find auth weaknesses")
        assert updated["research_goal"] == "Find auth weaknesses"

    def test_update_project_ignores_unknown_columns(self, tmp_db, project):
        """Only whitelisted columns should be updatable (SQL injection prevention)."""
        result = tmp_db.update_project(project["id"], injected_col="evil")
        # Should not raise — just silently skip unknown columns
        assert result is not None

    def test_list_projects(self, tmp_db):
        tmp_db.create_project("Alpha", "")
        tmp_db.create_project("Beta", "")
        projects = tmp_db.list_projects()
        names = [p["name"] for p in projects]
        assert "Alpha" in names
        assert "Beta" in names


# ===========================================================================
# 2. Scope Operations
# ===========================================================================


class TestScopeOperations:
    def test_set_and_get_scope(self, tmp_db, project):
        pid = project["id"]
        scope_row = tmp_db.set_project_scope(
            pid,
            in_scope_assets=["example.com"],
            out_of_scope_assets=["admin.example.com"],
            authorization_notes="Synthetic program",
        )
        assert scope_row["project_id"] == pid

        scope = tmp_db.get_project_scope(pid)
        in_scope = json.loads(scope["in_scope_assets"])
        out_scope = json.loads(scope["out_of_scope_assets"])
        assert "example.com" in in_scope
        assert "admin.example.com" in out_scope
        assert scope["authorization_notes"] == "Synthetic program"

    def test_scope_upsert(self, tmp_db, project):
        """Calling set_project_scope twice should update, not duplicate."""
        pid = project["id"]
        tmp_db.set_project_scope(pid, in_scope_assets=["a.com"])
        tmp_db.set_project_scope(pid, in_scope_assets=["b.com"])
        scope = tmp_db.get_project_scope(pid)
        in_scope = json.loads(scope["in_scope_assets"])
        assert "b.com" in in_scope
        assert "a.com" not in in_scope

    def test_scope_none_when_not_set(self, tmp_db, project):
        scope = tmp_db.get_project_scope(project["id"])
        assert scope is None

    def test_scope_status_enum_values(self):
        assert ScopeStatus.IN_SCOPE.value == "IN_SCOPE"
        assert ScopeStatus.OUT_OF_SCOPE.value == "OUT_OF_SCOPE"
        assert ScopeStatus.UNKNOWN.value == "UNKNOWN"

    def test_scope_presence_is_not_authorization(self, tmp_db, project):
        """An asset being added to a project does NOT authorize testing it.
        The scope_status must be explicitly set to IN_SCOPE.
        """
        pid = project["id"]
        asset = tmp_db.add_asset(pid, "some-host.com", scope_status="UNKNOWN")
        assert asset["scope_status"] == "UNKNOWN", (
            "Asset presence in a project does NOT grant authorization. "
            "scope_status must be explicitly set to IN_SCOPE."
        )


# ===========================================================================
# 3. Asset Operations
# ===========================================================================


class TestAssetOperations:
    def test_add_asset_default_scope_unknown(self, tmp_db, project):
        """Assets must default to UNKNOWN scope — never auto-authorized."""
        asset = tmp_db.add_asset(project["id"], "example.com", "domain")
        assert asset["scope_status"] == "UNKNOWN"

    def test_add_asset_explicit_in_scope(self, tmp_db, project):
        asset = tmp_db.add_asset(project["id"], "example.com", scope_status="IN_SCOPE")
        assert asset["scope_status"] == "IN_SCOPE"

    def test_add_asset_explicit_out_of_scope(self, tmp_db, project):
        asset = tmp_db.add_asset(project["id"], "secret.example.com", scope_status="OUT_OF_SCOPE")
        assert asset["scope_status"] == "OUT_OF_SCOPE"

    def test_list_assets_by_project(self, tmp_db, project):
        pid = project["id"]
        tmp_db.add_asset(pid, "a.com", "domain")
        tmp_db.add_asset(pid, "b.com", "subdomain")
        assets = tmp_db.list_assets(pid)
        assert len(assets) == 2

    def test_assets_isolated_by_project(self, tmp_db):
        p1 = tmp_db.create_project("P1", "")
        p2 = tmp_db.create_project("P2", "")
        tmp_db.add_asset(p1["id"], "p1-asset.com")
        p2_assets = tmp_db.list_assets(p2["id"])
        assert len(p2_assets) == 0

    def test_asset_type_enum_values(self):
        assert AssetType.DOMAIN.value == "domain"
        assert AssetType.WEB_APPLICATION.value == "web_application"
        assert AssetType.API.value == "api"


# ===========================================================================
# 4. Objective Operations
# ===========================================================================


class TestObjectiveOperations:
    def test_objective_starts_open(self, tmp_db, project):
        obj = tmp_db.add_objective(project["id"], "Assess JWT", priority="HIGH")
        assert obj["status"] == "OPEN"
        assert obj["priority"] == "HIGH"

    def test_objective_status_lifecycle(self, tmp_db, project):
        obj = tmp_db.add_objective(project["id"], "Check auth")
        assert obj["status"] == "OPEN"
        updated = tmp_db.update_objective_status(obj["id"], "IN_PROGRESS")
        assert updated["status"] == "IN_PROGRESS"
        completed = tmp_db.update_objective_status(obj["id"], "COMPLETED")
        assert completed["status"] == "COMPLETED"

    def test_objective_priority_enum(self):
        assert ObjectivePriority.CRITICAL.value == "CRITICAL"
        assert ObjectivePriority.LOW.value == "LOW"

    def test_objectives_isolated_by_project(self, tmp_db):
        p1 = tmp_db.create_project("X1", "")
        p2 = tmp_db.create_project("X2", "")
        tmp_db.add_objective(p1["id"], "P1 objective")
        assert len(tmp_db.list_objectives(p2["id"])) == 0


# ===========================================================================
# 5. Hypothesis Operations — CRITICAL SAFETY
# ===========================================================================


class TestHypothesisOperations:
    def test_hypothesis_starts_untested(self, tmp_db, project):
        """A hypothesis MUST start as UNTESTED — it is not a finding."""
        hyp = tmp_db.add_hypothesis(project["id"], "Auth may be weak")
        assert hyp["status"] == "UNTESTED", (
            "SAFETY: Hypotheses must start UNTESTED. "
            "They require evidence + validation to become findings."
        )

    def test_hypothesis_default_confidence_low(self, tmp_db, project):
        hyp = tmp_db.add_hypothesis(project["id"], "Test hypothesis")
        assert hyp["confidence"] == "LOW"

    def test_hypothesis_is_not_a_finding(self, tmp_db, project):
        """Verify hypothesis does NOT auto-escalate to CONFIRMED."""
        hyp = tmp_db.add_hypothesis(project["id"], "Possible IDOR")
        # Without researcher evidence, status stays UNTESTED
        assert hyp["status"] == "UNTESTED"
        assert hyp["status"] != "CONFIRMED", (
            "A hypothesis must NEVER auto-confirm. "
            "Only researcher-supplied evidence can support a finding."
        )

    def test_hypothesis_status_update(self, tmp_db, project):
        hyp = tmp_db.add_hypothesis(project["id"], "XSS possible")
        updated = tmp_db.update_hypothesis_status(hyp["id"], "SUPPORTED", "MEDIUM")
        assert updated["status"] == "SUPPORTED"
        assert updated["confidence"] == "MEDIUM"

    def test_hypothesis_status_enum(self):
        assert HypothesisStatus.UNTESTED.value == "UNTESTED"
        assert HypothesisStatus.SUPPORTED.value == "SUPPORTED"
        assert HypothesisStatus.REFUTED.value == "REFUTED"
        assert HypothesisStatus.INCONCLUSIVE.value == "INCONCLUSIVE"

    def test_hypothesis_link_to_objective(self, tmp_db, project):
        obj = tmp_db.add_objective(project["id"], "Test auth")
        hyp = tmp_db.add_hypothesis(project["id"], "JWT bypass", objective_id=obj["id"])
        assert hyp["objective_id"] == obj["id"]


# ===========================================================================
# 6. Evidence Operations — CRITICAL INTEGRITY
# ===========================================================================


class TestEvidenceOperations:
    def test_evidence_stores_only_researcher_content(self, tmp_db, project):
        """Evidence content must ONLY be what the researcher supplies."""
        ev = tmp_db.add_research_evidence(
            project["id"],
            title="Login response",
            evidence_type="HTTP_RESPONSE",
            content="HTTP/1.1 200 OK\nSet-Cookie: session=abc123",
            source="Researcher manual capture",
        )
        assert ev["content"] == "HTTP/1.1 200 OK\nSet-Cookie: session=abc123"
        assert ev["source"] == "Researcher manual capture"

    def test_evidence_none_content_stays_none(self, tmp_db, project):
        """Missing evidence remains missing — never fabricated."""
        ev = tmp_db.add_research_evidence(project["id"], title="Observation", content=None)
        assert ev["content"] is None, (
            "SAFETY: Missing evidence must remain None. "
            "The system must not invent content."
        )

    def test_evidence_type_enum(self):
        assert EvidenceType.HTTP_REQUEST.value == "HTTP_REQUEST"
        assert EvidenceType.OBSERVATION.value == "OBSERVATION"
        assert EvidenceType.SOURCE_CODE.value == "SOURCE_CODE"
        assert EvidenceType.SCREENSHOT.value == "SCREENSHOT"

    def test_evidence_list_by_project(self, tmp_db, project):
        pid = project["id"]
        tmp_db.add_research_evidence(pid, "e1")
        tmp_db.add_research_evidence(pid, "e2")
        assert len(tmp_db.list_research_evidence(pid)) == 2

    def test_evidence_by_ids(self, tmp_db, project):
        ev1 = tmp_db.add_research_evidence(project["id"], "Evidence A")
        ev2 = tmp_db.add_research_evidence(project["id"], "Evidence B")
        fetched = tmp_db.get_research_evidence_by_ids([ev1["id"], ev2["id"]])
        assert len(fetched) == 2

    def test_evidence_isolated_by_project(self, tmp_db):
        p1 = tmp_db.create_project("EP1", "")
        p2 = tmp_db.create_project("EP2", "")
        tmp_db.add_research_evidence(p1["id"], "P1 evidence")
        assert len(tmp_db.list_research_evidence(p2["id"])) == 0


# ===========================================================================
# 7. Finding Operations — CRITICAL VALIDATION
# ===========================================================================


class TestFindingOperations:
    def test_finding_starts_unconfirmed(self, tmp_db, project):
        """Findings must default to UNCONFIRMED classification."""
        f = tmp_db.create_finding(project["id"], "Potential IDOR")
        assert f["classification"] == "UNCONFIRMED"
        assert f["validation_status"] == "UNCONFIRMED"

    def test_finding_update_classification(self, tmp_db, project):
        f = tmp_db.create_finding(project["id"], "Weak auth")
        updated = tmp_db.update_finding(f["id"], classification="LIKELY",
                                        validation_status="LIKELY")
        assert updated["classification"] == "LIKELY"

    def test_finding_evidence_association(self, tmp_db, project):
        ev = tmp_db.add_research_evidence(project["id"], "HTTP capture")
        f = tmp_db.create_finding(project["id"], "Auth bypass",
                                   evidence_ids=[ev["id"]])
        import json as _j
        stored_ids = _j.loads(f["evidence_ids"])
        assert ev["id"] in stored_ids

    def test_finding_cannot_auto_confirm(self, tmp_db, project):
        """A finding should not auto-escalate to CONFIRMED."""
        f = tmp_db.create_finding(project["id"], "Suspected SQLi")
        assert f["classification"] != "CONFIRMED", (
            "SAFETY: Findings must not auto-confirm. "
            "CONFIRMED requires researcher validation with evidence."
        )

    def test_finding_update_whitelist(self, tmp_db, project):
        """update_finding should silently ignore non-whitelisted columns."""
        f = tmp_db.create_finding(project["id"], "Test finding")
        result = tmp_db.update_finding(f["id"], malicious_column="evil")
        assert result is not None  # Should not crash

    def test_list_findings_by_project(self, tmp_db, project):
        pid = project["id"]
        tmp_db.create_finding(pid, "F1")
        tmp_db.create_finding(pid, "F2")
        assert len(tmp_db.list_findings(pid)) == 2


# ===========================================================================
# 8. Activity Log Operations
# ===========================================================================


class TestActivityLog:
    def test_activity_logged(self, tmp_db, project):
        act = tmp_db.log_activity(project["id"], "PROJECT_CREATED", "Initial")
        assert act["event_type"] == "PROJECT_CREATED"

    def test_activities_chronological(self, tmp_db, project):
        pid = project["id"]
        tmp_db.log_activity(pid, "ASSET_ADDED", "First")
        tmp_db.log_activity(pid, "OBJECTIVE_CREATED", "Second")
        tmp_db.log_activity(pid, "HYPOTHESIS_CREATED", "Third")
        activities = tmp_db.list_activities(pid)
        assert len(activities) == 3
        event_types = [a["event_type"] for a in activities]
        assert event_types == ["ASSET_ADDED", "OBJECTIVE_CREATED", "HYPOTHESIS_CREATED"]

    def test_activities_isolated_by_project(self, tmp_db):
        p1 = tmp_db.create_project("AP1", "")
        p2 = tmp_db.create_project("AP2", "")
        tmp_db.log_activity(p1["id"], "PROJECT_CREATED", "p1 only")
        assert len(tmp_db.list_activities(p2["id"])) == 0


# ===========================================================================
# 9. Summary Counts
# ===========================================================================


class TestSummaryCounts:
    def test_summary_counts_all_entities(self, tmp_db, project):
        pid = project["id"]
        tmp_db.add_asset(pid, "a.com")
        tmp_db.add_asset(pid, "b.com")
        obj = tmp_db.add_objective(pid, "Obj 1")
        tmp_db.add_hypothesis(pid, "Hyp 1", objective_id=obj["id"])
        ev = tmp_db.add_research_evidence(pid, "Ev 1")
        tmp_db.create_finding(pid, "Finding 1", evidence_ids=[ev["id"]])
        tmp_db.log_activity(pid, "PROJECT_CREATED", "setup")

        counts = tmp_db.get_project_summary_counts(pid)
        assert counts["assets"] == 2
        assert counts["objectives"] == 1
        assert counts["hypotheses"] == 1
        assert counts["evidence"] == 1
        assert counts["findings"] == 1
        assert counts["activities"] == 1


# ===========================================================================
# 10. ResearchPlanner (mocked Gemini)
# ===========================================================================


class TestResearchPlanner:
    def _make_mock_response(self, data: dict) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.text = json.dumps(data)
        return mock_resp

    def test_planner_without_gemini_key(self, tmp_db, project):
        """Without Gemini key, planner should return knowledge sources + warning."""
        from app.research.planner import ResearchPlanner
        from app.knowledge.retriever import KnowledgeRetriever

        retriever = KnowledgeRetriever(db=tmp_db, auto_load_vectors=False)
        planner = ResearchPlanner(db=tmp_db, retriever=retriever, genai_client=None)
        # Patch gemini_api_key to None so has_gemini_key returns False
        object.__setattr__(planner.settings, "gemini_api_key", None)

        plan = planner.plan(project["id"], "Test authentication bypass")

        assert isinstance(plan, ResearchPlan)
        assert plan.warning != ""
        assert "GEMINI_API_KEY" in plan.warning

    def test_planner_with_mocked_gemini(self, tmp_db, project):
        """Planner should parse Gemini JSON response into ResearchPlan."""
        from app.research.planner import ResearchPlanner
        from app.knowledge.retriever import KnowledgeRetriever

        mock_response = self._make_mock_response({
            "relevant_concepts": ["JWT", "token validation"],
            "suggested_hypotheses": ["JWT signature may not be validated"],
            "evidence_needed": ["HTTP requests to auth endpoints"],
            "validation_questions": ["Is the JWT signature checked server-side?"],
            "potential_finding_categories": ["Authentication Bypass"],
        })

        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_response

        retriever = KnowledgeRetriever(db=tmp_db, auto_load_vectors=False)
        planner = ResearchPlanner(db=tmp_db, retriever=retriever, genai_client=mock_client)
        # Make has_gemini_key True by providing a fake key
        object.__setattr__(planner.settings, "gemini_api_key", "fake-test-key")

        plan = planner.plan(project["id"], "Assess JWT authentication")

        assert isinstance(plan, ResearchPlan)
        assert len(plan.suggested_hypotheses) >= 1
        assert len(plan.evidence_needed) >= 1
        assert plan.warning == ""

    def test_planner_output_is_not_a_finding(self, tmp_db, project):
        """ResearchPlan output is a planning aid, not a confirmed finding."""
        from app.research.planner import ResearchPlanner
        from app.knowledge.retriever import KnowledgeRetriever

        retriever = KnowledgeRetriever(db=tmp_db, auto_load_vectors=False)
        planner = ResearchPlanner(db=tmp_db, retriever=retriever, genai_client=None)
        object.__setattr__(planner.settings, "gemini_api_key", None)

        plan = planner.plan(project["id"], "Check for SSRF")

        # A plan has no findings attribute — it only has hypotheses (untested)
        assert hasattr(plan, "suggested_hypotheses")
        assert not hasattr(plan, "confirmed_vulnerabilities"), (
            "ResearchPlan must not have a 'confirmed_vulnerabilities' field. "
            "Plans contain only untested hypotheses."
        )

    def test_planner_empty_objective_raises(self, tmp_db, project):
        from app.research.planner import ResearchPlanner
        from app.knowledge.retriever import KnowledgeRetriever

        retriever = KnowledgeRetriever(db=tmp_db, auto_load_vectors=False)
        planner = ResearchPlanner(db=tmp_db, retriever=retriever, genai_client=None)

        with pytest.raises(ValueError, match="empty"):
            planner.plan(project["id"], "   ")


# ===========================================================================
# 11. ValidationAssistant (mocked Gemini)
# ===========================================================================


class TestValidationAssistant:
    def _make_mock_response(self, data: dict) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.text = json.dumps(data)
        return mock_resp

    def test_validation_without_evidence_returns_insufficient(self, tmp_db, project):
        """If no evidence is supplied, validation must return insufficient — not fabricate."""
        from app.research.validation_assistant import ValidationAssistant
        from app.knowledge.retriever import KnowledgeRetriever

        hyp = tmp_db.add_hypothesis(project["id"], "Auth bypass possible")
        retriever = KnowledgeRetriever(db=tmp_db, auto_load_vectors=False)
        assistant = ValidationAssistant(db=tmp_db, retriever=retriever, genai_client=None)

        result = assistant.validate(project["id"], hyp["id"], evidence_ids=[])

        assert isinstance(result, ValidationResult)
        assert result.is_evidence_sufficient is False
        assert result.suggested_classification == "UNCONFIRMED"
        assert "No evidence supplied" in result.warning, (
            "SAFETY: When no evidence is supplied, the system must clearly "
            "state that and must not fabricate evidence."
        )

    def test_validation_no_fabrication(self, tmp_db, project):
        """Validation must not invent HTTP requests, responses, or observations."""
        from app.research.validation_assistant import ValidationAssistant
        from app.knowledge.retriever import KnowledgeRetriever

        hyp = tmp_db.add_hypothesis(project["id"], "SSRF in image upload")
        retriever = KnowledgeRetriever(db=tmp_db, auto_load_vectors=False)
        assistant = ValidationAssistant(db=tmp_db, retriever=retriever, genai_client=None)

        result = assistant.validate(project["id"], hyp["id"], evidence_ids=[])

        # The evidence_summary must say no evidence was supplied
        assert "No evidence" in result.evidence_summary or "no evidence" in result.evidence_summary.lower()
        assert result.is_evidence_sufficient is False

    def test_validation_with_evidence_and_mocked_gemini(self, tmp_db, project):
        """Validation with evidence should call Gemini and parse the structured response."""
        from app.research.validation_assistant import ValidationAssistant
        from app.knowledge.retriever import KnowledgeRetriever

        hyp = tmp_db.add_hypothesis(project["id"], "Possible IDOR on /api/users")
        ev = tmp_db.add_research_evidence(
            project["id"],
            title="API response shows other user data",
            evidence_type="HTTP_RESPONSE",
            content="HTTP/1.1 200 OK\n{\"id\":2, \"email\":\"other@example.com\"}",
            hypothesis_id=hyp["id"],
        )

        mock_response = self._make_mock_response({
            "evidence_summary": "Researcher observed /api/users/2 returning data for another user.",
            "evidence_strength": "Moderate",
            "assumptions_identified": ["Assumed /api/users/2 belongs to a different user"],
            "alternative_explanations": ["Test account may be the same user"],
            "is_evidence_sufficient": False,
            "additional_evidence_needed": ["Confirm user IDs belong to different accounts"],
            "impact_logical": True,
            "suggested_classification": "POSSIBLE",
            "rationale": "[PROJECT EVIDENCE] HTTP response shows cross-user data. "
                         "[AI ANALYSIS] This is consistent with IDOR patterns per [KNOWLEDGE BASE].",
        })

        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_response

        retriever = KnowledgeRetriever(db=tmp_db, auto_load_vectors=False)
        assistant = ValidationAssistant(db=tmp_db, retriever=retriever, genai_client=mock_client)
        object.__setattr__(assistant.settings, "gemini_api_key", "fake-test-key")

        result = assistant.validate(project["id"], hyp["id"], [ev["id"]])

        assert result.suggested_classification == "POSSIBLE"
        assert result.evidence_strength == "Moderate"
        assert result.is_evidence_sufficient is False
        assert len(result.additional_evidence_needed) > 0
        assert "[PROJECT EVIDENCE]" in result.rationale or "PROJECT" in result.rationale

    def test_validation_false_positive_path(self, tmp_db, project):
        """Validation should be able to return FALSE_POSITIVE for benign findings."""
        from app.research.validation_assistant import ValidationAssistant
        from app.knowledge.retriever import KnowledgeRetriever

        hyp = tmp_db.add_hypothesis(project["id"], "404 page leaks internal paths")
        ev = tmp_db.add_research_evidence(
            project["id"], title="404 response", evidence_type="HTTP_RESPONSE",
            content="404 Not Found\n/var/www/html not found",
        )

        mock_response = self._make_mock_response({
            "evidence_summary": "404 page shows a standard path.",
            "evidence_strength": "Weak",
            "assumptions_identified": ["Assumed path is sensitive"],
            "alternative_explanations": ["This is a standard web server message"],
            "is_evidence_sufficient": True,
            "additional_evidence_needed": [],
            "impact_logical": False,
            "suggested_classification": "FALSE_POSITIVE",
            "rationale": "[AI ANALYSIS] Standard 404 message, not a meaningful information leak.",
        })

        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_response

        retriever = KnowledgeRetriever(db=tmp_db, auto_load_vectors=False)
        assistant = ValidationAssistant(db=tmp_db, retriever=retriever, genai_client=mock_client)
        object.__setattr__(assistant.settings, "gemini_api_key", "fake-test-key")

        result = assistant.validate(project["id"], hyp["id"], [ev["id"]])

        assert result.suggested_classification == "FALSE_POSITIVE"
        assert result.impact_logical is False

    def test_validation_missing_hypothesis(self, tmp_db, project):
        from app.research.validation_assistant import ValidationAssistant
        from app.knowledge.retriever import KnowledgeRetriever

        retriever = KnowledgeRetriever(db=tmp_db, auto_load_vectors=False)
        assistant = ValidationAssistant(db=tmp_db, retriever=retriever, genai_client=None)

        with pytest.raises(ValueError, match="not found"):
            assistant.validate(project["id"], 99999, [])


# ===========================================================================
# 12. Pydantic Model Validation
# ===========================================================================


class TestPydanticModels:
    def test_project_scope_parses_json_strings(self):
        scope = ProjectScope(
            id=1,
            project_id=1,
            in_scope_assets='["a.com", "b.com"]',
            out_of_scope_assets="[]",
        )
        assert scope.in_scope_assets == ["a.com", "b.com"]
        assert scope.out_of_scope_assets == []

    def test_project_scope_handles_list_directly(self):
        scope = ProjectScope(
            id=1,
            project_id=1,
            in_scope_assets=["x.com"],
            out_of_scope_assets=["y.com"],
        )
        assert "x.com" in scope.in_scope_assets

    def test_hypothesis_default_status_untested(self):
        hyp = Hypothesis(id=1, project_id=1, title="Test")
        assert hyp.status == HypothesisStatus.UNTESTED

    def test_hypothesis_default_confidence_low(self):
        hyp = Hypothesis(id=1, project_id=1, title="Test")
        assert hyp.confidence == ConfidenceLevel.LOW

    def test_asset_default_scope_unknown(self):
        asset = Asset(id=1, project_id=1, name="example.com")
        assert asset.scope_status == ScopeStatus.UNKNOWN

    def test_research_plan_no_confirmed_vulnerabilities_field(self):
        plan = ResearchPlan(project_id=1, objective_title="Test")
        assert not hasattr(plan, "confirmed_vulnerabilities")

    def test_validation_result_defaults(self):
        result = ValidationResult(
            evidence_summary="None",
            evidence_strength="Insufficient",
            is_evidence_sufficient=False,
            impact_logical=False,
            suggested_classification="UNCONFIRMED",
            rationale="No evidence.",
        )
        assert result.is_evidence_sufficient is False
        assert result.suggested_classification == "UNCONFIRMED"


# ===========================================================================
# 13. CLI Integration Tests
# ===========================================================================


class TestCLIPhase5:
    @pytest.fixture
    def cli_db(self, tmp_path, monkeypatch):
        db_path = tmp_path / "cli_test.db"
        monkeypatch.setenv("DATABASE_PATH", str(db_path))
        from app.config import get_settings
        get_settings(reload=True)
        db = DatabaseManager(db_path)
        db.init_db()
        yield db
        try:
            get_settings(reload=True)
        except Exception:
            pass

    def _run(self, args: list, db_path: str) -> tuple:
        from click.testing import CliRunner
        from app.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, args, catch_exceptions=False)
        return result.exit_code, result.output

    def test_cli_project_create(self, cli_db, tmp_path, monkeypatch):
        monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "cli_test.db"))
        exit_code, output = self._run(
            ["project", "create", "CLI-Phase5-Test"], str(tmp_path / "cli_test.db")
        )
        assert exit_code == 0
        assert "CLI-Phase5-Test" in output

    def test_cli_project_list(self, cli_db, tmp_path, monkeypatch):
        monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "cli_test.db"))
        cli_db.create_project("ListTest", "Test")
        exit_code, output = self._run(
            ["project", "list"], str(tmp_path / "cli_test.db")
        )
        assert exit_code == 0
        assert "ListTest" in output

    def test_cli_project_show(self, cli_db, tmp_path, monkeypatch):
        monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "cli_test.db"))
        p = cli_db.create_project("ShowTest", "For show")
        exit_code, output = self._run(
            ["project", "show", str(p["id"])], str(tmp_path / "cli_test.db")
        )
        assert exit_code == 0
        assert "ShowTest" in output

    def test_cli_project_show_invalid_id(self, cli_db, tmp_path, monkeypatch):
        monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "cli_test.db"))
        from click.testing import CliRunner
        from app.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["project", "show", "99999"])
        assert result.exit_code != 0 or "not found" in result.output.lower()

    def test_cli_project_assets(self, cli_db, tmp_path, monkeypatch):
        monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "cli_test.db"))
        p = cli_db.create_project("AssetsTest", "")
        cli_db.add_asset(p["id"], "test.example.com", scope_status="IN_SCOPE")
        exit_code, output = self._run(
            ["project", "assets", str(p["id"])], str(tmp_path / "cli_test.db")
        )
        assert exit_code == 0
        assert "test.example.com" in output

    def test_cli_project_hypotheses_empty(self, cli_db, tmp_path, monkeypatch):
        monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "cli_test.db"))
        p = cli_db.create_project("HypTest", "")
        exit_code, output = self._run(
            ["project", "hypotheses", str(p["id"])], str(tmp_path / "cli_test.db")
        )
        assert exit_code == 0
        assert "No hypotheses" in output

    def test_cli_project_evidence_empty(self, cli_db, tmp_path, monkeypatch):
        monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "cli_test.db"))
        p = cli_db.create_project("EvTest", "")
        exit_code, output = self._run(
            ["project", "evidence", str(p["id"])], str(tmp_path / "cli_test.db")
        )
        assert exit_code == 0
        assert "No evidence" in output

    def test_cli_project_findings_empty(self, cli_db, tmp_path, monkeypatch):
        monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "cli_test.db"))
        p = cli_db.create_project("FindTest", "")
        exit_code, output = self._run(
            ["project", "findings", str(p["id"])], str(tmp_path / "cli_test.db")
        )
        assert exit_code == 0
        assert "No findings" in output


# ===========================================================================
# 14. Knowledge DB Regression Guard
# ===========================================================================


class TestKnowledgeDBIntegrity:
    def test_phase5_schema_does_not_alter_knowledge_tables(self, tmp_db):
        """Phase 5 init_db must not drop or reset documents/chunks tables."""
        # Simulate: insert a fake document, run init_db again, verify it persists
        with tmp_db.get_connection() as conn:
            conn.execute(
                "INSERT INTO documents (source_path, filename, file_type, content_hash, status) "
                "VALUES ('test/doc.md', 'doc.md', 'md', 'abc123', 'active')"
            )

        # Re-run init_db (should be idempotent and NOT drop data)
        tmp_db.init_db()

        with tmp_db.get_connection() as conn:
            count = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
        assert count == 1, "Phase 5 init_db must not wipe the documents table"

    def test_chunks_table_preserved_after_phase5_init(self, tmp_db):
        """Phase 5 schema migration must not delete existing chunks."""
        with tmp_db.get_connection() as conn:
            conn.execute(
                "INSERT INTO documents (source_path, filename, file_type, content_hash, status) "
                "VALUES ('test/x.md', 'x.md', 'md', 'hash1', 'active')"
            )
            doc_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.execute(
                "INSERT INTO chunks (document_id, chunk_id, content, content_hash) "
                "VALUES (?, 'ck1', 'chunk content', 'chash1')", (doc_id,)
            )

        tmp_db.init_db()  # Must be idempotent

        with tmp_db.get_connection() as conn:
            chunk_count = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        assert chunk_count == 1, "Phase 5 init_db must not wipe the chunks table"
