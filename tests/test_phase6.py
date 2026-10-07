"""Phase 6 comprehensive test suite: Research Orchestrator & Project Context.

All tests:
- Run 100% offline (no Gemini API calls, no network requests, no target interaction)
- Use isolated temporary SQLite databases
- Mock all Gemini interactions
- Verify safety boundaries: no autonomous testing, unknown scope safety, evidence integrity
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure project root is on Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.knowledge.retriever import KnowledgeRetriever
from app.research.context import (
    ContextLimits,
    ProjectContextBuilder,
    evaluate_project_health,
    format_context_summary,
)
from app.research.models import (
    AssetType,
    HypothesisStatus,
    ObjectivePriority,
    ObjectiveStatus,
    ProjectContext,
    ProjectHealth,
    ProjectOverallState,
    ResearchOrchestrationResult,
    ResearchRecommendation,
    ScopeStatus,
)
from app.research.orchestrator import ResearchOrchestrator
from app.storage.database import DatabaseManager


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """Isolated database in a temp directory — never touches researcher.db."""
    db_path = tmp_path / "test_phase6.db"
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
    """Create a basic test project."""
    return tmp_db.create_project("Phase6-Audit", "Synthetic project for orchestration testing")


@pytest.fixture
def populated_project(tmp_db, project):
    """Create a fully populated project with scope, assets, objectives, hypotheses, evidence, and findings."""
    pid = project["id"]
    # 1. Update goal
    tmp_db.update_project(pid, research_goal="Assess API authorization boundaries")

    # 2. Scope
    tmp_db.set_project_scope(
        pid,
        in_scope_assets=["api.target.com"],
        out_of_scope_assets=["admin.target.com"],
        authorization_notes="Authorized bug bounty scope - synthetic testing",
    )

    # 3. Assets
    a1 = tmp_db.add_asset(pid, "api.target.com", asset_type="api", scope_status="IN_SCOPE", technology="FastAPI")
    a2 = tmp_db.add_asset(pid, "admin.target.com", asset_type="web_application", scope_status="OUT_OF_SCOPE")
    a3 = tmp_db.add_asset(pid, "internal-service.local", asset_type="service", scope_status="UNKNOWN")

    # 4. Objectives
    obj1 = tmp_db.add_objective(pid, "Test BOLA / IDOR on user endpoints", priority="HIGH")
    obj2 = tmp_db.add_objective(pid, "Inspect token expiration", priority="LOW")
    tmp_db.update_objective_status(obj2["id"], "COMPLETED")

    # 5. Hypotheses
    h1 = tmp_db.add_hypothesis(
        pid,
        title="User profile endpoint /api/user/{id} may lack object-level authorization",
        objective_id=obj1["id"],
        confidence="LOW",
    )
    h2 = tmp_db.add_hypothesis(
        pid,
        title="Refresh tokens can be reused after rotation",
        objective_id=obj2["id"],
        confidence="MEDIUM",
    )
    tmp_db.update_hypothesis_status(h2["id"], status="SUPPORTED", confidence="MEDIUM")

    # 6. Evidence
    ev1 = tmp_db.add_research_evidence(
        pid,
        title="HTTP 200 on /api/user/2 while authenticated as user 1",
        evidence_type="HTTP_RESPONSE",
        content="HTTP/1.1 200 OK\n{\"id\": 2, \"email\": \"victim@target.com\"}",
        hypothesis_id=h1["id"],
        source="Researcher manual testing",
        confidence="HIGH",
    )

    # 7. Finding
    f1 = tmp_db.create_finding(
        pid,
        title="Broken Object Level Authorization on /api/user/{id}",
        severity="High",
        classification="POSSIBLE",
        affected_asset="api.target.com/api/user/{id}",
        evidence_ids=[ev1["id"]],
        validation_status="UNCONFIRMED",
    )

    # 8. Activity
    tmp_db.log_activity(pid, "PROJECT_CREATED", "Initialized populated project")
    tmp_db.log_activity(pid, "EVIDENCE_ADDED", "Added IDOR evidence")

    return project


# ===========================================================================
# 1. ProjectContextBuilder Tests
# ===========================================================================


class TestProjectContextBuilder:
    def test_build_context_empty_project(self, tmp_db, project):
        """Empty project should build cleanly with empty collections."""
        builder = ProjectContextBuilder(db=tmp_db)
        ctx = builder.build_context(project["id"], include_knowledge=False)

        assert isinstance(ctx, ProjectContext)
        assert ctx.project.id == project["id"]
        assert ctx.project.name == project["name"]
        assert ctx.scope is None
        assert len(ctx.assets) == 0
        assert len(ctx.objectives) == 0
        assert len(ctx.hypotheses) == 0
        assert len(ctx.evidence) == 0
        assert len(ctx.findings) == 0
        assert ctx.truncation.truncated is False

    def test_build_context_populated_project(self, tmp_db, populated_project):
        """Populated project correctly partitions assets, objectives, and hypotheses."""
        builder = ProjectContextBuilder(db=tmp_db)
        ctx = builder.build_context(populated_project["id"], include_knowledge=False)

        assert ctx.project.research_goal == "Assess API authorization boundaries"
        assert ctx.scope is not None
        assert "api.target.com" in ctx.scope.in_scope_assets
        assert "admin.target.com" in ctx.scope.out_of_scope_assets

        # Asset partitions
        assert len(ctx.assets) == 3
        assert len(ctx.in_scope_assets) == 1
        assert ctx.in_scope_assets[0].name == "api.target.com"
        assert len(ctx.out_of_scope_assets) == 1
        assert len(ctx.unknown_scope_assets) == 1
        assert ctx.unknown_scope_assets[0].name == "internal-service.local"

        # Objective partitions
        assert len(ctx.objectives) == 2
        assert len(ctx.open_objectives) == 1
        assert ctx.open_objectives[0].title == "Test BOLA / IDOR on user endpoints"
        assert len(ctx.completed_objectives) == 1

        # Hypothesis partitions
        assert len(ctx.hypotheses) == 2
        assert len(ctx.untested_hypotheses) == 1
        assert "User profile" in ctx.untested_hypotheses[0].title

        # Evidence & Findings
        assert len(ctx.evidence) == 1
        assert len(ctx.findings) == 1
        assert ctx.findings[0].validation_status == "UNCONFIRMED"

    def test_build_context_invalid_project_raises(self, tmp_db):
        builder = ProjectContextBuilder(db=tmp_db)
        with pytest.raises(ValueError, match="not found"):
            builder.build_context(99999)

    def test_truncation_limits(self, tmp_db, project):
        """Verify that items exceeding ContextLimits are truncated and recorded."""
        pid = project["id"]
        # Add 10 assets
        for i in range(10):
            tmp_db.add_asset(pid, f"host{i}.com", scope_status="IN_SCOPE")

        # Set limit to 3 assets
        limits = ContextLimits(max_assets=3)
        builder = ProjectContextBuilder(db=tmp_db, limits=limits)
        ctx = builder.build_context(pid, include_knowledge=False)

        assert ctx.truncation.truncated is True
        assert "assets" in ctx.truncation.truncated_categories
        assert len(ctx.assets) == 3
        assert ctx.truncation.total_items_counted["assets"] == 10
        assert ctx.truncation.items_retained["assets"] == 3

    def test_secret_scrubbing(self, tmp_db, project):
        """Verify that API keys or passwords in descriptions/notes are scrubbed."""
        pid = project["id"]
        tmp_db.update_project(pid, description="Test with key AIzaSyD9FakeKey35CharactersLongSafeNow12")
        tmp_db.add_asset(pid, "secret-api.com", notes="Authorization: Bearer mySecretToken1234567890abcdef")

        builder = ProjectContextBuilder(db=tmp_db)
        ctx = builder.build_context(pid, include_knowledge=False)

        assert "AIzaSyD9" not in str(ctx.project.description)
        assert "[REDACTED_API_KEY]" in str(ctx.project.description)
        assert "mySecretToken" not in str(ctx.assets[0].notes)
        assert "[REDACTED_TOKEN]" in str(ctx.assets[0].notes)

    def test_format_context_summary(self, tmp_db, populated_project):
        """Summary formatter outputs clean, human-readable markdown text."""
        builder = ProjectContextBuilder(db=tmp_db)
        ctx = builder.build_context(populated_project["id"], include_knowledge=False)
        summary = format_context_summary(ctx)

        assert "PROJECT CONTEXT" in summary
        assert "Assess API authorization boundaries" in summary
        assert "SCOPE & AUTHORIZATION" in summary
        assert "api.target.com" in summary
        assert "RESEARCH OBJECTIVES" in summary


# ===========================================================================
# 2. ProjectHealth Evaluation Tests
# ===========================================================================


class TestProjectHealth:
    def test_health_no_scope_blocked(self, tmp_db, project):
        """Project with no scope defined should be INITIALIZING or BLOCKED."""
        builder = ProjectContextBuilder(db=tmp_db)
        ctx = builder.build_context(project["id"], include_knowledge=False)
        health = evaluate_project_health(ctx)

        assert health.scope_status == "NO_SCOPE"
        assert health.overall_state in (ProjectOverallState.INITIALIZING, ProjectOverallState.BLOCKED)
        assert len(health.blockers) > 0

    def test_health_unknown_assets_warning(self, tmp_db, project):
        """Assets with UNKNOWN scope trigger a warning and state check."""
        pid = project["id"]
        tmp_db.set_project_scope(pid, in_scope_assets=["a.com"])
        tmp_db.add_asset(pid, "a.com", scope_status="IN_SCOPE")
        tmp_db.add_asset(pid, "unknown.com", scope_status="UNKNOWN")
        tmp_db.add_objective(pid, "Assess auth")

        builder = ProjectContextBuilder(db=tmp_db)
        ctx = builder.build_context(pid, include_knowledge=False)
        health = evaluate_project_health(ctx)

        assert health.scope_status == "HAS_UNKNOWN_ASSETS"
        assert any("UNKNOWN scope" in w for w in health.warnings)

    def test_health_all_unknown_assets_blocked(self, tmp_db, project):
        """When all assets are UNKNOWN, scope_status is ALL_UNKNOWN_ASSETS and research is blocked."""
        pid = project["id"]
        tmp_db.set_project_scope(pid, in_scope_assets=["a.com"])
        tmp_db.add_asset(pid, "unknown.com", scope_status="UNKNOWN")
        tmp_db.add_objective(pid, "Assess auth")

        builder = ProjectContextBuilder(db=tmp_db)
        ctx = builder.build_context(pid, include_knowledge=False)
        health = evaluate_project_health(ctx)

        assert health.scope_status == "ALL_UNKNOWN_ASSETS"
        assert health.overall_state == ProjectOverallState.BLOCKED
        assert any("UNKNOWN scope" in b for b in health.blockers)

    def test_health_ready_for_research(self, tmp_db, project):
        """Scope defined, in-scope asset, objective defined, but no hypotheses -> READY_FOR_RESEARCH."""
        pid = project["id"]
        tmp_db.set_project_scope(pid, in_scope_assets=["app.target.com"])
        tmp_db.add_asset(pid, "app.target.com", scope_status="IN_SCOPE")
        tmp_db.add_objective(pid, "Assess session security")

        builder = ProjectContextBuilder(db=tmp_db)
        ctx = builder.build_context(pid, include_knowledge=False)
        health = evaluate_project_health(ctx)

        assert health.overall_state == ProjectOverallState.READY_FOR_RESEARCH
        assert health.hypothesis_status == "NO_HYPOTHESES"

    def test_health_awaiting_evidence(self, tmp_db, project):
        """Hypotheses exist with zero evidence -> AWAITING_EVIDENCE."""
        pid = project["id"]
        tmp_db.set_project_scope(pid, in_scope_assets=["app.target.com"])
        tmp_db.add_asset(pid, "app.target.com", scope_status="IN_SCOPE")
        tmp_db.add_objective(pid, "Assess auth")
        tmp_db.add_hypothesis(pid, "Session token predictable")

        builder = ProjectContextBuilder(db=tmp_db)
        ctx = builder.build_context(pid, include_knowledge=False)
        health = evaluate_project_health(ctx)

        assert health.overall_state == ProjectOverallState.AWAITING_EVIDENCE
        assert health.hypothesis_status == "UNTESTED_PRESENT"
        assert health.evidence_status == "NO_EVIDENCE"

    def test_health_validation_required(self, tmp_db, project):
        """Unconfirmed findings present -> VALIDATION_REQUIRED."""
        pid = project["id"]
        tmp_db.set_project_scope(pid, in_scope_assets=["app.target.com"])
        tmp_db.add_asset(pid, "app.target.com", scope_status="IN_SCOPE")
        tmp_db.add_objective(pid, "Assess auth")
        h = tmp_db.add_hypothesis(pid, "Session predictable")
        ev = tmp_db.add_research_evidence(pid, "Tokens", content="seq", hypothesis_id=h["id"])
        tmp_db.create_finding(pid, "Predictable Tokens", evidence_ids=[ev["id"]], validation_status="UNCONFIRMED")

        builder = ProjectContextBuilder(db=tmp_db)
        ctx = builder.build_context(pid, include_knowledge=False)
        health = evaluate_project_health(ctx)

        assert health.overall_state == ProjectOverallState.VALIDATION_REQUIRED
        assert health.finding_status == "UNVALIDATED_FINDINGS"

    def test_health_ready_for_report(self, tmp_db, project):
        """Objectives completed, hypotheses tested, findings confirmed -> READY_FOR_REPORT."""
        pid = project["id"]
        tmp_db.set_project_scope(pid, in_scope_assets=["app.target.com"])
        tmp_db.add_asset(pid, "app.target.com", scope_status="IN_SCOPE")
        obj = tmp_db.add_objective(pid, "Assess auth")
        tmp_db.update_objective_status(obj["id"], "COMPLETED")
        h = tmp_db.add_hypothesis(pid, "Session predictable")
        tmp_db.update_hypothesis_status(h["id"], "SUPPORTED", "HIGH")
        ev = tmp_db.add_research_evidence(pid, "Tokens", content="seq", hypothesis_id=h["id"])
        tmp_db.create_finding(pid, "Predictable Tokens", evidence_ids=[ev["id"]], classification="CONFIRMED", validation_status="CONFIRMED")

        builder = ProjectContextBuilder(db=tmp_db)
        ctx = builder.build_context(pid, include_knowledge=False)
        health = evaluate_project_health(ctx)

        assert health.overall_state == ProjectOverallState.READY_FOR_REPORT


# ===========================================================================
# 3. ResearchOrchestrator Tests
# ===========================================================================


class TestResearchOrchestrator:
    def test_orchestrator_sources_only_mode(self, tmp_db, populated_project):
        """Sources-only mode uses deterministic heuristics without calling Gemini."""
        retriever = KnowledgeRetriever(db=tmp_db, auto_load_vectors=False)
        orchestrator = ResearchOrchestrator(db=tmp_db, retriever=retriever, genai_client=None)

        result = orchestrator.orchestrate(populated_project["id"], limit=2, sources_only=True)

        assert isinstance(result, ResearchOrchestrationResult)
        assert result.health.overall_state in (ProjectOverallState.VALIDATION_REQUIRED, ProjectOverallState.RESEARCH_IN_PROGRESS)
        assert len(result.recommendations) > 0
        assert len(result.recommendations) <= 2
        assert len(result.next_best_question) > 0
        assert isinstance(result.recommendations[0], ResearchRecommendation)

    def test_orchestrator_no_gemini_key_fallback(self, tmp_db, populated_project):
        """When GEMINI_API_KEY is not configured, orchestrator falls back to deterministic recommendations."""
        retriever = KnowledgeRetriever(db=tmp_db, auto_load_vectors=False)
        orchestrator = ResearchOrchestrator(db=tmp_db, retriever=retriever, genai_client=None)
        object.__setattr__(orchestrator.settings, "gemini_api_key", None)

        result = orchestrator.orchestrate(populated_project["id"], limit=3, sources_only=False)

        assert isinstance(result, ResearchOrchestrationResult)
        assert len(result.recommendations) > 0
        assert result.next_best_question != ""

    def test_orchestrator_mocked_gemini(self, tmp_db, populated_project):
        """When Gemini is available, structured AI recommendations are generated and parsed."""
        retriever = KnowledgeRetriever(db=tmp_db, auto_load_vectors=False)

        mock_payload = {
            "project_state_summary": "Project has 1 open objective and 1 unconfirmed IDOR finding.",
            "blockers": [],
            "warnings": ["Finding awaiting falsification"],
            "recommendations": [
                {
                    "title": "Validate IDOR with multi-tenant role testing",
                    "objective_id": 1,
                    "hypothesis_id": 1,
                    "rationale": "Verify whether access is restricted across different organizational boundaries.",
                    "relevant_knowledge": ["BOLA testing methodology"],
                    "evidence_needed": ["Cross-tenant HTTP response captures"],
                    "validation_questions": ["Does user 2 belong to a different account?"],
                    "priority": "HIGH",
                    "confidence": "HIGH",
                    "blockers": [],
                }
            ],
            "next_best_question": "Does user 2 belong to a separate organizational tenant?",
            "relevant_sources": ["PentestingEverything/API Security/BOLA.md"],
        }

        mock_response = MagicMock()
        mock_response.text = json.dumps(mock_payload)
        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_response

        orchestrator = ResearchOrchestrator(db=tmp_db, retriever=retriever, genai_client=mock_client)
        object.__setattr__(orchestrator.settings, "gemini_api_key", "fake-test-key")

        result = orchestrator.orchestrate(populated_project["id"], limit=3, sources_only=False)

        assert isinstance(result, ResearchOrchestrationResult)
        assert "IDOR" in result.project_state_summary
        assert len(result.recommendations) == 1
        assert result.recommendations[0].title == "Validate IDOR with multi-tenant role testing"
        assert result.recommendations[0].priority == "HIGH"
        assert result.next_best_question == "Does user 2 belong to a separate organizational tenant?"

    def test_orchestrator_gemini_json_failure_fallback(self, tmp_db, populated_project):
        """If Gemini returns invalid JSON, orchestrator gracefully falls back to deterministic engine."""
        retriever = KnowledgeRetriever(db=tmp_db, auto_load_vectors=False)

        mock_response = MagicMock()
        mock_response.text = "This is not valid JSON at all."
        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_response

        orchestrator = ResearchOrchestrator(db=tmp_db, retriever=retriever, genai_client=mock_client)
        object.__setattr__(orchestrator.settings, "gemini_api_key", "fake-test-key")

        result = orchestrator.orchestrate(populated_project["id"], limit=2, sources_only=False)

        assert isinstance(result, ResearchOrchestrationResult)
        assert len(result.recommendations) > 0
        assert any("fallback" in w.lower() or "deterministic" in w.lower() for w in result.warnings)

    def test_orchestrator_limit_respected(self, tmp_db, project):
        """Recommendations respect the requested limit."""
        pid = project["id"]
        tmp_db.set_project_scope(pid, in_scope_assets=["a.com"])
        tmp_db.add_asset(pid, "a.com", scope_status="IN_SCOPE")
        obj = tmp_db.add_objective(pid, "Obj 1")
        for i in range(5):
            tmp_db.add_hypothesis(pid, f"Hypothesis {i}", objective_id=obj["id"])

        retriever = KnowledgeRetriever(db=tmp_db, auto_load_vectors=False)
        orchestrator = ResearchOrchestrator(db=tmp_db, retriever=retriever, genai_client=None)

        result = orchestrator.orchestrate(pid, limit=2, sources_only=True)
        assert len(result.recommendations) <= 2


# ===========================================================================
# 4. Safety & Boundary Tests
# ===========================================================================


class TestSafetyBoundaries:
    def test_no_autonomous_attack_steps_in_recommendations(self, tmp_db, populated_project):
        """Recommendations must guide human evidence collection, not generate attack steps."""
        retriever = KnowledgeRetriever(db=tmp_db, auto_load_vectors=False)
        orchestrator = ResearchOrchestrator(db=tmp_db, retriever=retriever, genai_client=None)

        result = orchestrator.orchestrate(populated_project["id"], sources_only=True)

        for rec in result.recommendations:
            rec_text = (rec.title + " " + rec.rationale).lower()
            assert "exploit" not in rec_text
            assert "brute force" not in rec_text
            assert "metasploit" not in rec_text
            assert "sqlmap" not in rec_text

    def test_unknown_scope_prevents_active_testing_recommendations(self, tmp_db, project):
        """If all assets are UNKNOWN, recommendations focus strictly on scope verification."""
        pid = project["id"]
        tmp_db.set_project_scope(pid, in_scope_assets=[])
        tmp_db.add_asset(pid, "mystery-server.com", scope_status="UNKNOWN")

        retriever = KnowledgeRetriever(db=tmp_db, auto_load_vectors=False)
        orchestrator = ResearchOrchestrator(db=tmp_db, retriever=retriever, genai_client=None)

        result = orchestrator.orchestrate(pid, sources_only=True)

        assert result.health.overall_state in (ProjectOverallState.BLOCKED, ProjectOverallState.INITIALIZING)
        assert any("scope" in r.title.lower() or "authorize" in r.title.lower() for r in result.recommendations)


# ===========================================================================
# 5. CLI Tests
# ===========================================================================


class TestCLIPhase6:
    def _run(self, args: list) -> tuple:
        from click.testing import CliRunner
        from app.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, args, catch_exceptions=False)
        return result.exit_code, result.output

    def test_cli_project_context(self, tmp_db, populated_project):
        exit_code, output = self._run(["project", "context", str(populated_project["id"])])
        assert exit_code == 0
        assert "PROJECT CONTEXT" in output
        assert "api.target.com" in output

    def test_cli_project_health(self, tmp_db, populated_project):
        exit_code, output = self._run(["project", "health", str(populated_project["id"])])
        assert exit_code == 0
        assert "Project Health" in output
        assert "Overall State:" in output

    def test_cli_project_next_sources_only(self, tmp_db, populated_project):
        exit_code, output = self._run(["project", "next", str(populated_project["id"]), "--sources-only"])
        assert exit_code == 0
        assert "Research Orchestrator: Next Steps" in output
        assert "Next Best Research Question:" in output
        assert "HUMAN-IN-THE-LOOP CHECKPOINT" in output

    def test_cli_project_next_invalid_id(self, tmp_db):
        from click.testing import CliRunner
        from app.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["project", "next", "99999"])
        assert result.exit_code != 0 or "not found" in result.output.lower()
