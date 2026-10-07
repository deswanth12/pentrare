"""Standard markdown templates for security research reports and project workspaces."""

import json
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from app.research.models import SecurityReport

REPORT_TEMPLATE = """# {title}

## Severity
{severity}

## Affected Asset
{affected_asset}

## Summary
{summary}

## Technical Details
{technical_details}

## Preconditions
{preconditions}

## Steps to Reproduce
{steps_to_reproduce}

## Evidence
{evidence}

## Expected Behavior
{expected_behavior}

## Observed Behavior
{observed_behavior}

## Security Impact
{security_impact}

## Root Cause
{root_cause}

## Remediation
{remediation}

## Validation
{validation}

## References
{references}
"""

SCOPE_TEMPLATE = """# Bug Bounty & Engagement Scope

## In Scope
- (List authorized domains, endpoints, repositories, or assets)

## Out of Scope
- (List excluded domains, subdomains, third-party services)

## Restrictions
- No automated volume scanning / DoS
- No social engineering or phishing
- Maintain testing rates within agreed limits

## Rate Limits
- Max requests/sec:

## Required Testing Conditions
- Custom headers: (e.g. X-Bug-Bounty: researcher-id)
- Test account email pattern:

## Reporting Requirements
- SLA / Disclosure terms:
"""

ARCHITECTURE_TEMPLATE = """# Target Architecture & Trust Boundaries

## Overview
(Brief overview of target application and purpose)

## Components
- Web Frontends:
- API Gateways / Backend Services:
- Databases & Storage:
- AI / LLM Components:
- MCP Servers / Tools:
- Third-Party Integrations:

## Trust Boundaries
1. Client -> API Gateway
2. API Gateway -> Internal Services
3. AI Agent -> Tool Execution Layer

## Authentication & Authorization Model
- Authentication mechanism (JWT, Session Cookie, OAuth):
- Role-based Access Control (RBAC):
"""

RESEARCH_PLAN_TEMPLATE = """# Research Plan & Checklist

## Objective
Structured testing checklist based on scope and architecture.

## Checklist
- [ ] ITEM-001: Tool Authorization Check
  - **Security Area**: Tool Authorization
  - **Reason**: Inspect if agent tools enforce server-side validation independently of LLM prompt decisions.
  - **Evidence Required**: HTTP requests showing tool execution with modified arguments.
  - **Status**: Not Tested
"""

OBSERVATIONS_TEMPLATE = """# Testing Observations & Raw Notes

## Session Notes
- Record observations during testing here.
"""


# ---------------------------------------------------------------------------
# Phase 9: Security Report Renderers
# ---------------------------------------------------------------------------


def _extract_report_data(report: "SecurityReport") -> Dict[str, Any]:
    """Helper to extract normalized fields from a SecurityReport."""
    if hasattr(report, "analysis") and report.analysis:
        data = report.analysis.model_dump()
    elif isinstance(getattr(report, "report_metadata", None), dict) and "analysis" in report.report_metadata:
        data = dict(report.report_metadata["analysis"])
    else:
        data = {}

    return {
        "title": report.title or data.get("title", "Security Finding"),
        "executive_summary": data.get("executive_summary", ""),
        "affected_asset": data.get("affected_asset") or (report.report_metadata.get("affected_asset") if isinstance(report.report_metadata, dict) else "Target Asset"),
        "asset_scope_status": data.get("asset_scope_status") or (report.report_metadata.get("asset_scope_status") if isinstance(report.report_metadata, dict) else "UNKNOWN"),
        "classification": data.get("classification") or (report.report_metadata.get("classification") if isinstance(report.report_metadata, dict) else "UNCONFIRMED"),
        "severity": data.get("severity") or (report.report_metadata.get("severity") if isinstance(report.report_metadata, dict) else "Unknown"),
        "evidence_strength": data.get("evidence_strength") or (report.report_metadata.get("evidence_strength") if isinstance(report.report_metadata, dict) else "NONE"),
        "technical_details": data.get("technical_details", ""),
        "steps_to_reproduce": data.get("steps_to_reproduce", []),
        "expected_behavior": data.get("expected_behavior", ""),
        "observed_behavior": data.get("observed_behavior", ""),
        "observed_impact": data.get("observed_impact", ""),
        "potential_impact": data.get("potential_impact", ""),
        "unsupported_impact_claims": data.get("unsupported_impact_claims", []),
        "root_cause_analysis": data.get("root_cause_analysis", ""),
        "remediation_guidance": data.get("remediation_guidance", ""),
        "alternative_explanations": data.get("alternative_explanations", []),
        "reproduction_gap_analysis": data.get("reproduction_gap_analysis"),
        "referenced_observation_ids": data.get("referenced_observation_ids", []),
        "knowledge_citations": data.get("knowledge_citations", []),
        "warnings": data.get("warnings", []),
    }


def _render_citations_appendix(citations: List[Any]) -> str:
    """Format observation citations into a Markdown traceability table."""
    if not citations:
        return "No specific evidence observations cited.\n"
    lines = [
        "| Citation | Artifact | Location | Observed Statement |",
        "| :--- | :--- | :--- | :--- |",
    ]
    for c in citations:
        obs_id = getattr(c, "observation_id", None) or (c.get("observation_id") if isinstance(c, dict) else "?")
        art = getattr(c, "artifact_name", None) or (c.get("artifact_name") if isinstance(c, dict) else "-")
        loc = getattr(c, "source_location", None) or (c.get("source_location") if isinstance(c, dict) else "-")
        stmt = getattr(c, "statement", None) or (c.get("statement") if isinstance(c, dict) else "")
        clean_stmt = str(stmt).replace("|", "\\|")
        lines.append(f"| [OBS-{obs_id}] | `{art}` | `{loc}` | {clean_stmt} |")
    return "\n".join(lines) + "\n"


def render_bug_bounty_report(report: "SecurityReport") -> str:
    """Render a professional bug bounty submission report conforming to strict evidence standards."""
    d = _extract_report_data(report)
    doc: List[str] = []

    # Title
    doc.append(f"# Bug Bounty Report: {d['title']}")
    doc.append("")

    # Metadata Summary
    doc.append(f"- **Target Asset**: `{d['affected_asset']}`")
    doc.append(f"- **Scope Status**: `{d['asset_scope_status']}`")
    doc.append(f"- **Vulnerability Classification**: **{d['classification']}**")
    doc.append(f"- **Severity**: **{d['severity']}**")
    doc.append(f"- **Evidence Strength**: `{d['evidence_strength']}`")
    status_str = getattr(report.status, "value", str(report.status))
    doc.append(f"- **Report Lifecycle Status**: `{status_str}` (Revision v{report.version})")
    doc.append("")

    # Alert Banners
    if d["asset_scope_status"] in ("UNKNOWN", "OUT_OF_SCOPE"):
        doc.append(f"> [!WARNING]\n> **Scope Authorization Warning**: Target asset scope is `{d['asset_scope_status']}`. All active verification must adhere to explicit program policy.")
        doc.append("")
    if d["classification"] == "FALSE_POSITIVE":
        doc.append("> [!NOTE]\n> **False Positive Notice**: This finding has been evaluated and determined to be a false positive or intended application behavior. It does not represent an exploitable vulnerability.")
        doc.append("")
    elif d["classification"] == "UNCONFIRMED":
        doc.append("> [!CAUTION]\n> **Unconfirmed Finding Warning**: This finding lacks conclusive empirical evidence. Further research and validation are required before considering it confirmed.")
        doc.append("")
    for w in d["warnings"]:
        doc.append(f"> [!WARNING]\n> {w}")
        doc.append("")

    # Executive Summary
    doc.append("## Executive Summary")
    doc.append(d["executive_summary"].strip() or "No executive summary provided.")
    doc.append("")

    # Technical Details
    doc.append("## Technical Details")
    doc.append(d["technical_details"].strip() or "No technical details provided.")
    doc.append("")

    # Steps to Reproduce
    doc.append("## Proof of Concept / Steps to Reproduce")
    if d["steps_to_reproduce"]:
        for idx, step in enumerate(d["steps_to_reproduce"], 1):
            doc.append(f"{idx}. {step}")
    else:
        doc.append("A complete reproduction sequence was not captured in the supplied evidence.")
    if d["reproduction_gap_analysis"]:
        doc.append("")
        doc.append(f"**Reproduction Gap Analysis**: {d['reproduction_gap_analysis']}")
    doc.append("")

    # Expected vs Observed Behavior
    doc.append("## Expected vs. Observed Behavior")
    doc.append(f"### Expected Behavior\n{d['expected_behavior'].strip() or 'System enforces intended security controls and boundary restrictions.'}\n")
    doc.append(f"### Observed Behavior\n{d['observed_behavior'].strip() or 'Behavior documented under technical details and evidence observations.'}\n")

    # Impact Analysis (Separation of observed vs potential vs unsupported)
    doc.append("## Impact Analysis")
    doc.append("### Observed Impact (Empirically Demonstrated)")
    doc.append(d["observed_impact"].strip() or "No direct empirical impact was observed beyond initial detection.")
    doc.append("")
    doc.append("### Potential Impact (Theoretical Escalation)")
    doc.append(d["potential_impact"].strip() or "No further theoretical escalation demonstrated.")
    doc.append("")
    if d["unsupported_impact_claims"]:
        doc.append("### Unsupported / Speculative Impact Claims")
        doc.append("> [!NOTE]\n> The following claims lack empirical proof in the supplied evidence and are considered theoretical speculation:")
        for claim in d["unsupported_impact_claims"]:
            doc.append(f"- {claim}")
        doc.append("")

    # Root Cause Analysis
    doc.append("## Root Cause Analysis")
    doc.append(d["root_cause_analysis"].strip() or "Root cause was not established from the supplied evidence.")
    doc.append("")

    # Remediation Guidance
    doc.append("## Remediation Guidance")
    doc.append(d["remediation_guidance"].strip() or "Review affected asset configuration and implement principle of least privilege.")
    doc.append("")

    # Alternative Explanations Evaluated
    if d["alternative_explanations"]:
        doc.append("## Alternative Explanations Evaluated")
        for alt in d["alternative_explanations"]:
            doc.append(f"- {alt}")
        doc.append("")

    # Traceability Appendix
    doc.append("## Evidence & Observation Traceability")
    doc.append(_render_citations_appendix(report.citations))

    # Knowledge Base References
    doc.append("## Knowledge Base References")
    if d["knowledge_citations"]:
        for ref in d["knowledge_citations"]:
            doc.append(f"- `{ref}`")
    else:
        doc.append("None cited.")
    doc.append("")

    return "\n".join(doc)


def render_internal_security_report(report: "SecurityReport") -> str:
    """Render an internal security engineering report with remediation and architectural details."""
    d = _extract_report_data(report)
    doc: List[str] = []

    # Title & Header
    doc.append(f"# Internal Security Finding: {d['title']}")
    doc.append("")

    doc.append("### Tracking & Governance")
    doc.append(f"- **Finding ID**: `#{report.finding_id}`")
    doc.append(f"- **Project ID**: `#{report.project_id}`")
    doc.append(f"- **Validation ID**: `#{report.validation_id or 'N/A'}`")
    status_str = getattr(report.status, "value", str(report.status))
    doc.append(f"- **Lifecycle Status**: `{status_str}` (v{report.version})")
    doc.append(f"- **Approved / Reviewed By**: `{report.approved_by or 'Pending Human Review'}`")
    if report.approved_at:
        doc.append(f"- **Approved At**: `{report.approved_at}`")
    doc.append(f"- **Affected Component**: `{d['affected_asset']}` ({d['asset_scope_status']})")
    doc.append(f"- **Risk Classification**: **{d['classification']}**")
    doc.append(f"- **Assessed Severity**: **{d['severity']}**")
    doc.append(f"- **Evidence Strength**: `{d['evidence_strength']}`")
    doc.append("")

    # Warnings
    if d["classification"] == "FALSE_POSITIVE":
        doc.append("> [!NOTE]\n> **Closed - False Positive**: Analysis verified that this issue does not constitute a security boundary failure.")
        doc.append("")
    elif d["classification"] == "UNCONFIRMED":
        doc.append("> [!CAUTION]\n> **Action Required - Unconfirmed Finding**: Engineering retest needed before acceptance.")
        doc.append("")
    for w in d["warnings"]:
        doc.append(f"> [!WARNING]\n> {w}")
        doc.append("")

    doc.append("## 1. Executive Summary & Risk Overview")
    doc.append(d["executive_summary"].strip() or "No executive summary provided.")
    doc.append("")

    doc.append("## 2. Technical Vulnerability Details")
    doc.append(d["technical_details"].strip() or "No technical details provided.")
    doc.append("")

    doc.append("## 3. Reproduction Sequence & Proof of Concept")
    if d["steps_to_reproduce"]:
        for idx, step in enumerate(d["steps_to_reproduce"], 1):
            doc.append(f"{idx}. {step}")
    else:
        doc.append("A complete reproduction sequence was not captured in the supplied evidence.")
    if d["reproduction_gap_analysis"]:
        doc.append("")
        doc.append(f"**Engineering Reproduction Gap**: {d['reproduction_gap_analysis']}")
    doc.append("")

    doc.append("## 4. Impact Assessment")
    doc.append(f"**Observed Impact**: {d['observed_impact'].strip() or 'None beyond initial detection.'}")
    doc.append("")
    doc.append(f"**Potential Blast Radius**: {d['potential_impact'].strip() or 'No further theoretical escalation demonstrated.'}")
    doc.append("")
    if d["unsupported_impact_claims"]:
        doc.append("**Unsupported Claims Excluded from Severity Rating**:")
        for c in d["unsupported_impact_claims"]:
            doc.append(f"- {c}")
        doc.append("")

    doc.append("## 5. Root Cause & Architecture Analysis")
    doc.append(d["root_cause_analysis"].strip() or "Root cause was not established from the supplied evidence.")
    doc.append("")

    doc.append("## 6. Engineering Remediation & Defense-in-Depth")
    doc.append(d["remediation_guidance"].strip() or "Implement defense-in-depth controls and input validation.")
    doc.append("")

    doc.append("## 7. Retesting & Verification Checklist")
    doc.append("- [ ] Verify fix in staging environment with non-privileged credentials.")
    doc.append("- [ ] Confirm differential authorization checks return expected status codes.")
    doc.append("- [ ] Add regression test vector to automated CI test suite.")
    doc.append("")

    doc.append("## 8. Evidence Traceability")
    doc.append(_render_citations_appendix(report.citations))

    doc.append("## 9. References & Standards")
    if d["knowledge_citations"]:
        for ref in d["knowledge_citations"]:
            doc.append(f"- `{ref}`")
    else:
        doc.append("None cited.")
    doc.append("")

    return "\n".join(doc)


def render_research_validation_report(report: "SecurityReport") -> str:
    """Render a research validation report focusing on empirical hypotheses and falsification."""
    d = _extract_report_data(report)
    doc: List[str] = []

    # Title & Metadata
    doc.append(f"# Research Validation Report: {d['title']}")
    doc.append("")

    doc.append("### Validation Metadata")
    doc.append(f"- **Project ID**: `#{report.project_id}`")
    doc.append(f"- **Finding ID**: `#{report.finding_id}`")
    doc.append(f"- **Validation Audit Record**: `#{report.validation_id or 'N/A'}`")
    doc.append(f"- **Target Asset**: `{d['affected_asset']}` ({d['asset_scope_status']})")
    doc.append(f"- **Validation Classification**: **{d['classification']}**")
    doc.append(f"- **Empirical Evidence Strength**: `{d['evidence_strength']}`")
    status_str = getattr(report.status, "value", str(report.status))
    doc.append(f"- **Report Status**: `{status_str}` (v{report.version})")
    doc.append("")

    if d["classification"] == "FALSE_POSITIVE":
        doc.append("> [!NOTE]\n> **Hypothesis Refuted**: The security hypothesis was disproven by contradictory evidence or benign behavior.")
        doc.append("")
    elif d["classification"] == "UNCONFIRMED":
        doc.append("> [!CAUTION]\n> **Hypothesis Inconclusive**: Available evidence is insufficient to confirm the hypothesis.")
        doc.append("")
    for w in d["warnings"]:
        doc.append(f"> [!WARNING]\n> {w}")
        doc.append("")

    doc.append("## 1. Research Objective & Synthesis")
    doc.append(d["executive_summary"].strip() or "No synthesis available.")
    doc.append("")

    doc.append("## 2. Technical Findings & Empirical Analysis")
    doc.append(d["technical_details"].strip() or "No technical details recorded.")
    doc.append("")

    doc.append("## 3. Reproduction Sequence & Methodology")
    if d["steps_to_reproduce"]:
        for idx, step in enumerate(d["steps_to_reproduce"], 1):
            doc.append(f"{idx}. {step}")
    else:
        doc.append("A complete reproduction sequence was not captured in the supplied evidence.")
    if d["reproduction_gap_analysis"]:
        doc.append("")
        doc.append(f"**Methodological Reproduction Gap**: {d['reproduction_gap_analysis']}")
    doc.append("")

    doc.append("## 4. Alternative Explanations Evaluated")
    if d["alternative_explanations"]:
        for alt in d["alternative_explanations"]:
            doc.append(f"- {alt}")
    else:
        doc.append("No alternative benign explanations identified.")
    doc.append("")

    doc.append("## 5. Impact Differentiation")
    doc.append(f"- **Observed Impact**: {d['observed_impact'].strip() or 'None beyond initial detection.'}")
    doc.append(f"- **Potential Impact**: {d['potential_impact'].strip() or 'No escalation demonstrated.'}")
    if d["unsupported_impact_claims"]:
        doc.append("- **Unsupported Claims**:")
        for c in d["unsupported_impact_claims"]:
            doc.append(f"  * {c}")
    doc.append("")

    doc.append("## 6. Root Cause Hypothesis")
    doc.append(d["root_cause_analysis"].strip() or "Root cause was not established from the supplied evidence.")
    doc.append("")

    doc.append("## 7. Remediation & Retesting Recommendations")
    doc.append(d["remediation_guidance"].strip() or "Verify findings with structured differential testing.")
    doc.append("")

    doc.append("## 8. Traceable Evidence Observations")
    doc.append(_render_citations_appendix(report.citations))

    doc.append("## 9. Knowledge Grounding")
    if d["knowledge_citations"]:
        for ref in d["knowledge_citations"]:
            doc.append(f"- `{ref}`")
    else:
        doc.append("None cited.")
    doc.append("")

    return "\n".join(doc)


def render_json_report(report: "SecurityReport") -> str:
    """Serialize the full SecurityReport model into formatted JSON."""
    return json.dumps(report.model_dump(mode="json"), indent=2)

