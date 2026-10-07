"""Tests for Pydantic data models and enums."""

from app.agent.state import (
    FindingClassification,
    ResearchItemStatus,
    Finding,
    EvidenceItem,
    ResearchItem,
    ProjectState,
)


def test_finding_classifications():
    """Verify finding classification levels adhere to security requirements."""
    expected = {"CONFIRMED", "LIKELY", "POSSIBLE", "UNCONFIRMED", "FALSE POSITIVE"}
    actual = {c.value for c in FindingClassification}
    assert actual == expected


def test_research_item_status():
    """Verify research checklist states."""
    expected = {"Not Tested", "In Progress", "Tested - No Issue", "Finding Identified"}
    actual = {s.value for s in ResearchItemStatus}
    assert actual == expected


def test_finding_model_instantiation():
    """Verify finding model instantiation and field assignment."""
    finding = Finding(
        title="Unauthorized Tool Execution in Agent Assistant",
        severity="High",
        classification=FindingClassification.CONFIRMED,
        affected_asset="api.example.com/v1/agent/tools",
        summary="Agent tools execute without verifying caller session permissions.",
        technical_details="POST /tools/execute accepts arbitrary caller parameters without auth headers.",
        steps_to_reproduce="1. Send POST request with empty cookie. 2. Observe 200 OK.",
        evidence="HTTP/1.1 200 OK\nContent-Type: application/json\n{'executed': true}",
        expected_behavior="401 Unauthorized or 403 Forbidden.",
        observed_behavior="200 OK tool execution succeeded.",
        security_impact="Attackers can execute privileged internal actions.",
        root_cause="Missing authorization middleware on agent tool router.",
        remediation="Enforce server-side session checks before invoking tool handlers.",
        validation_notes="Confirmed via manual curl test; unaffected by prompt variations.",
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    )

    assert finding.title == "Unauthorized Tool Execution in Agent Assistant"
    assert finding.classification == FindingClassification.CONFIRMED
    assert len(finding.references) == 1


def test_project_state_model():
    """Verify ProjectState container."""
    state = ProjectState(
        name="test-engagement",
        description="Authorized audit",
    )
    assert state.name == "test-engagement"
    assert state.status == "active"
    assert len(state.research_items) == 0
    assert len(state.findings) == 0
