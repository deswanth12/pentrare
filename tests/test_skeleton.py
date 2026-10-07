"""Tests verifying architecture contracts, module exports, and minimal interfaces."""

import pytest
from pathlib import Path

# Knowledge interfaces
from app.knowledge import (
    IngestionPipeline,
    DocumentParser,
    DocumentChunker,
    EmbeddingGenerator,
    VectorStore,
    KnowledgeRetriever,
)

# Research interfaces
from app.research import (
    ScopeAnalyzer,
    ArchitectureAnalyzer,
    ResearchPlanner,
    EvidenceAnalyzer,
)

# Validation interfaces
from app.validation import (
    FindingValidator,
    FalsePositiveAnalyzer,
    ImpactAnalyzer,
)

# Reporting interfaces
from app.reporting import (
    REPORT_TEMPLATE,
    ReportGenerator,
)

# Agent interfaces
from app.agent import (
    SecurityOrchestrator,
    SYSTEM_INSTRUCTIONS,
    Finding,
    FindingClassification,
    ScopeItem,
)


def test_knowledge_interfaces(tmp_path):
    """Verify vector module interfaces are implemented and operational in Phase 4."""
    import numpy as np

    emb = EmbeddingGenerator(mock=True, dimension=128)
    vectors = emb.embed_texts(["hello world"])
    assert isinstance(vectors, np.ndarray)
    assert vectors.shape == (1, 128)

    vstore_path = tmp_path / "test_store.npz"
    vstore = VectorStore(vstore_path, dimension=128)
    vstore.add_chunks(["c1"], vectors, ["h1"])
    assert vstore.size() == 1
    hits = vstore.search(vectors[0], top_k=1)
    assert len(hits) == 1
    assert hits[0][0] == "c1"


def test_research_interfaces():
    """Verify research module interfaces raise NotImplementedError in Phase 1."""
    scope_analyzer = ScopeAnalyzer()
    with pytest.raises(NotImplementedError):
        scope_analyzer.analyze("Scope text")

    arch_analyzer = ArchitectureAnalyzer()
    with pytest.raises(NotImplementedError):
        arch_analyzer.analyze("Architecture text")

    planner = ResearchPlanner()
    with pytest.raises(NotImplementedError):
        planner.generate_plan(ScopeItem(), [])

    evidence_analyzer = EvidenceAnalyzer()
    with pytest.raises(NotImplementedError):
        evidence_analyzer.analyze("HTTP response")


def test_validation_interfaces():
    """Verify validation module interfaces raise NotImplementedError in Phase 1."""
    validator = FindingValidator()
    finding = Finding(
        title="Test Finding",
        affected_asset="api.example.com",
        summary="Test",
        technical_details="Details",
        steps_to_reproduce="Steps",
        evidence="Evidence",
        expected_behavior="Expected",
        observed_behavior="Observed",
        security_impact="Impact",
        root_cause="Cause",
        remediation="Fix",
        validation_notes="Notes",
    )
    with pytest.raises(NotImplementedError):
        validator.validate(finding)

    fp = FalsePositiveAnalyzer()
    with pytest.raises(NotImplementedError):
        fp.check_false_positive(finding)

    impact = ImpactAnalyzer()
    with pytest.raises(NotImplementedError):
        impact.assess_impact(finding)


def test_orchestrator_interface():
    """Verify orchestrator interface raises NotImplementedError in Phase 1."""
    orchestrator = SecurityOrchestrator()
    with pytest.raises(NotImplementedError):
        orchestrator.analyze_scope("policy")


def test_report_generator_formatting():
    """Verify base report generator formats finding correctly."""
    finding = Finding(
        title="Server-Side Request Forgery",
        severity="High",
        classification=FindingClassification.CONFIRMED,
        affected_asset="api.example.com/webhook",
        summary="Webhook endpoint accesses internal cloud metadata.",
        technical_details="POST /webhook accepts internal IP addresses without filtering.",
        steps_to_reproduce="Submit metadata IP in webhook URL.",
        evidence="Metadata response with IAM role.",
        expected_behavior="Private IPs blocked.",
        observed_behavior="Access granted to 169.254.169.254.",
        security_impact="Cloud credential extraction.",
        root_cause="Missing SSRF validation filter.",
        remediation="Implement strict IP allowlisting and reject RFC1918/link-local IPs.",
        validation_notes="Confirmed in lab environment.",
        references=["https://cwe.mitre.org/data/definitions/918.html"],
    )
    generator = ReportGenerator()
    report_md = generator.generate(finding)

    assert "# Server-Side Request Forgery" in report_md
    assert "## Severity\nHigh" in report_md
    assert "## Affected Asset\napi.example.com/webhook" in report_md
    assert "## Steps to Reproduce" in report_md
    assert "https://cwe.mitre.org/data/definitions/918.html" in report_md
