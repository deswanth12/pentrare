import uuid
import pytest
from click.testing import CliRunner
from app.main import cli
from app.config import get_settings


@pytest.fixture(autouse=True)
def isolate_cli_database(tmp_path, monkeypatch):
    """Ensure all CLI tests run against an isolated temporary SQLite database."""
    test_db_path = tmp_path / "cli_test_researcher.db"
    monkeypatch.setenv("DATABASE_PATH", str(test_db_path))
    get_settings(reload=True)
    yield
    get_settings(reload=True)


def test_cli_help():
    """Verify CLI help executes cleanly and shows command list."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Agentic Security Research Assistant" in result.output
    assert "init" in result.output
    assert "status" in result.output
    assert "project" in result.output
    assert "ingest" in result.output
    assert "search" in result.output
    assert "knowledge" in result.output


def test_cli_init():
    """Verify init command runs and initializes environment."""
    runner = CliRunner()
    result = runner.invoke(cli, ["init"])
    assert result.exit_code == 0
    assert "SQLite database initialized" in result.output
    assert "System successfully initialized" in result.output


def test_cli_status():
    """Verify status command displays system metrics and safety guard."""
    runner = CliRunner()
    result = runner.invoke(cli, ["status"])
    assert result.exit_code == 0
    assert "Safety Mode:" in result.output
    assert "HUMAN-IN-THE-LOOP" in result.output
    assert "Database:" in result.output


def test_cli_project_create_and_list():
    """Verify project creation and listing via CLI."""
    runner = CliRunner()
    proj_name = f"test-lab-{uuid.uuid4().hex[:8]}"
    create_result = runner.invoke(
        cli, ["project", "create", proj_name, "--desc", "Test Lab Target"]
    )
    assert create_result.exit_code == 0
    assert "successfully created" in create_result.output

    list_result = runner.invoke(cli, ["project", "list"])
    assert list_result.exit_code == 0
    assert proj_name in list_result.output


def test_cli_knowledge_ingest_and_search(tmp_path):
    """Verify CLI ingest and search commands using a temporary knowledge folder."""
    # Create small mock knowledge repository
    sample_kb = tmp_path / "mock_kb"
    sample_kb.mkdir()
    sample_doc = sample_kb / "custom_test_security.md"
    sample_doc.write_text(
        "# CustomMockSecurityAudit\n\nInspect specialized-mock-token authorization boundaries and tool permissions.",
        encoding="utf-8",
    )

    runner = CliRunner()

    # 1. Test ingest with custom path
    ingest_result = runner.invoke(cli, ["ingest", "--path", str(sample_kb)])
    assert ingest_result.exit_code == 0
    assert "Knowledge Ingestion" in ingest_result.output
    assert "Status:" in ingest_result.output

    # 2. Test knowledge status
    status_result = runner.invoke(cli, ["knowledge", "status"])
    assert status_result.exit_code == 0
    assert "Knowledge Base Status" in status_result.output
    assert "Active Documents:" in status_result.output

    # 3. Test search
    search_result = runner.invoke(cli, ["search", "specialized-mock-token"])
    assert search_result.exit_code == 0
    assert "Knowledge Search Results" in search_result.output
    assert "custom_test_security.md" in search_result.output


def test_cli_placeholder_commands(tmp_path):
    """Verify future phase commands give informative phase messages."""
    runner = CliRunner()

    dummy_file = tmp_path / "dummy.txt"
    dummy_file.write_text("dummy test content", encoding="utf-8")

    scope_res = runner.invoke(cli, ["scope", "analyze", str(dummy_file)])
    assert scope_res.exit_code == 0
    assert "Phase 6" in scope_res.output

    analyze_res = runner.invoke(cli, ["analyze", str(dummy_file)])
    assert analyze_res.exit_code == 0
    assert "Phase 8" in analyze_res.output

    finding_res = runner.invoke(cli, ["finding", "validate", str(dummy_file)])
    assert finding_res.exit_code == 0
    assert "Phase 9" in finding_res.output

    report_res = runner.invoke(cli, ["report", "FINDING-001"])
    assert report_res.exit_code == 0
    assert "Phase 10" in report_res.output


def test_cli_ask_sources_only(tmp_path):
    """Verify ask --sources-only displays retrieved sources without requiring Gemini."""
    sample_kb = tmp_path / "ask_kb"
    sample_kb.mkdir()
    (sample_kb / "test_doc.md").write_text("# Test Title\n\nPrompt injection defense methodology.", encoding="utf-8")

    runner = CliRunner()
    # Ingest document into test db
    runner.invoke(cli, ["ingest", "--path", str(sample_kb)])

    # Ask with --sources-only
    result = runner.invoke(cli, ["ask", "--sources-only", "prompt injection"])
    assert result.exit_code == 0
    assert "Grounded Security Research QA" in result.output
    assert "Retrieved Knowledge Sources" in result.output
    assert "--sources-only was specified. Gemini was not contacted." in result.output


def test_cli_ask_without_api_key(tmp_path, monkeypatch):
    """Verify ask without GEMINI_API_KEY displays clean guidance instead of crash."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    get_settings(reload=True)

    runner = CliRunner()
    result = runner.invoke(cli, ["ask", "Explain prompt injection."])
    assert result.exit_code == 1
    assert "GEMINI_API_KEY is not configured" in result.output
