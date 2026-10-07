"""Report generator interface for Phase 9 Security Report Generation Engine.

Synthesizes validated finding records, project scope, asset inventory,
evidence artifacts, observations, and validation history into structured
Bug Bounty, Internal Engineering, and Research Validation reports.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.agent.prompts import (
    SECURITY_REPORT_SYSTEM_PROMPT,
    build_security_report_prompt,
)
from app.agent.state import Finding
from app.config import get_settings
from app.knowledge.retriever import KnowledgeRetriever
from app.reporting.templates import (
    REPORT_TEMPLATE,
    render_bug_bounty_report,
    render_internal_security_report,
    render_json_report,
    render_research_validation_report,
)
from app.research.evidence.normalizer import redact_secrets
from app.research.models import (
    ObservationCitation,
    ReportAnalysis,
    ReportFormat,
    ReportStatus,
    ReportTemplateType,
    SecurityReport,
)
from app.storage.database import DatabaseManager

logger = logging.getLogger(__name__)

INJECTION_PATTERNS = [
    r"(?i)ignore\s+previous\s+instructions",
    r"(?i)system\s*prompt",
    r"(?i)override\s+system",
    r"(?i)disregard\s+all\s+prior",
    r"(?i)declare\s+high\s+severity",
    r"(?i)you\s+are\s+now\s+in\s+developer\s+mode",
]


class ReportGenerator:
    """Generates evidence-grounded security reports conforming to strict empirical standards."""

    def __init__(
        self,
        db: Optional[DatabaseManager] = None,
        retriever: Optional[KnowledgeRetriever] = None,
        settings=None,
        genai_client=None,
    ):
        self.db = db
        self.retriever = retriever
        self.settings = settings or get_settings()
        self.genai_client = genai_client

    # ------------------------------------------------------------------
    # Legacy Phase 1 Compatibility
    # ------------------------------------------------------------------

    def generate(self, finding: Finding) -> str:
        """Render markdown report from legacy Finding object (Phase 1 compatibility)."""
        references_text = (
            "\n".join(f"- {ref}" for ref in finding.references)
            if finding.references
            else "None provided."
        )
        return REPORT_TEMPLATE.format(
            title=finding.title,
            severity=finding.severity,
            affected_asset=finding.affected_asset,
            summary=finding.summary,
            technical_details=finding.technical_details,
            preconditions="Valid authorized researcher account.",
            steps_to_reproduce=finding.steps_to_reproduce,
            evidence=finding.evidence,
            expected_behavior=finding.expected_behavior,
            observed_behavior=finding.observed_behavior,
            security_impact=finding.security_impact,
            root_cause=finding.root_cause,
            remediation=finding.remediation,
            validation=finding.validation_notes,
            references=references_text,
        )

    # ------------------------------------------------------------------
    # Phase 9: Core Report Generation Engine
    # ------------------------------------------------------------------

    def generate_report(
        self,
        finding_id: int,
        template_type: ReportTemplateType = ReportTemplateType.BUG_BOUNTY,
        format: ReportFormat = ReportFormat.MARKDOWN,
        validation_id: Optional[int] = None,
        use_ai: bool = True,
    ) -> SecurityReport:
        """Synthesize and persist a structured security report for a finding."""
        if not self.db:
            raise ValueError("DatabaseManager is required for Phase 9 report generation.")

        # 1. Fetch Finding and Project State
        finding = self.db.get_finding(finding_id)
        if not finding:
            raise ValueError(f"Finding with ID {finding_id} not found.")

        project_id = finding["project_id"]
        project = self.db.get_project_by_id(project_id)
        if not project:
            raise ValueError(f"Project with ID {project_id} not found.")

        scope = self.db.get_project_scope(project_id)
        assets = self.db.list_assets(project_id)

        # Determine asset and its scope status
        affected_asset_name = finding.get("affected_asset") or "Target Asset"
        asset_scope_status = "UNKNOWN"
        for a in assets:
            if a["name"].lower() == affected_asset_name.lower() or (
                a.get("identifier") and a["identifier"].lower() == affected_asset_name.lower()
            ):
                asset_scope_status = a.get("scope_status", "UNKNOWN")
                break
        if asset_scope_status == "UNKNOWN" and scope:
            in_s = scope.get("in_scope_assets", [])
            out_s = scope.get("out_of_scope_assets", [])
            if any(affected_asset_name.lower() in str(x).lower() for x in in_s):
                asset_scope_status = "IN_SCOPE"
            elif any(affected_asset_name.lower() in str(x).lower() for x in out_s):
                asset_scope_status = "OUT_OF_SCOPE"

        # 2. Fetch Validation History & Observations
        val: Optional[Dict[str, Any]] = None
        if validation_id is not None:
            val = self.db.get_validation(validation_id)
        else:
            val = self.db.get_latest_validation(finding_id=finding_id)
            if not val:
                val = self.db.get_latest_validation(project_id=project_id)

        all_obs = self.db.list_observations(project_id)
        obs_map = {o["id"]: o for o in all_obs}
        artifacts = self.db.list_evidence_artifacts(project_id)
        artifacts_map = {a["id"]: a["filename"] for a in artifacts}
        raw_evidence = self.db.list_research_evidence(project_id)

        # 3. Quality & Security Scans
        warnings: List[str] = []
        has_injection = False
        raw_texts = [
            finding.get("summary"),
            finding.get("technical_details"),
            finding.get("observed_behavior"),
        ] + [o.get("statement") for o in all_obs] + [e.get("content") for e in raw_evidence]
        all_text_to_scan = [t for t in raw_texts if t and isinstance(t, str)]

        for text in all_text_to_scan:
            for pat in INJECTION_PATTERNS:
                if re.search(pat, text):
                    has_injection = True
                    break
            if has_injection:
                break

        if has_injection:
            warnings.append(
                "Potential prompt injection directives detected in evidence or notes. "
                "Adversarial directives were quarantined and processed strictly as inert data."
            )

        # Check for secrets and redact
        any_secrets_redacted = False
        secret_types_found: List[str] = []
        for text in all_text_to_scan:
            _, is_redacted, types = redact_secrets(text)
            if is_redacted:
                any_secrets_redacted = True
                secret_types_found.extend(types)

        if any_secrets_redacted:
            warnings.append(
                f"Sensitive credentials or tokens detected in evidence ({', '.join(sorted(set(secret_types_found)))}). "
                "Secrets have been automatically redacted from the report."
            )

        # 4. Knowledge Retrieval for References
        knowledge_chunks: List[str] = []
        if self.retriever:
            try:
                query = f"{finding['title']} {finding.get('root_cause') or ''}".strip()
                res = self.retriever.search(query, limit=3, mode="hybrid")
                for r in res:
                    knowledge_chunks.append(f"{r.source_path} § {r.section}")
            except Exception as e:
                logger.warning(f"Knowledge retrieval error during report generation: {e}")

        # 5. Report Synthesis (AI vs Deterministic)
        analysis: Optional[ReportAnalysis] = None
        if use_ai and (self.settings.gemini_api_key or self.genai_client):
            try:
                analysis = self._ai_generate(
                    finding=finding,
                    val=val,
                    all_obs=all_obs,
                    raw_evidence=raw_evidence,
                    scope=scope,
                    affected_asset_name=affected_asset_name,
                    asset_scope_status=asset_scope_status,
                    knowledge_chunks=knowledge_chunks,
                    template_type=template_type,
                    warnings=warnings,
                )
            except Exception as e:
                logger.warning(f"Gemini report generation failed: {e}. Falling back to deterministic synthesis.")
                warnings.append(f"AI generation unavailable ({e}). Report was synthesized using deterministic analysis.")
                analysis = self._deterministic_generate(
                    finding=finding,
                    val=val,
                    all_obs=all_obs,
                    affected_asset_name=affected_asset_name,
                    asset_scope_status=asset_scope_status,
                    knowledge_chunks=knowledge_chunks,
                    warnings=warnings,
                )
        else:
            analysis = self._deterministic_generate(
                finding=finding,
                val=val,
                all_obs=all_obs,
                affected_asset_name=affected_asset_name,
                asset_scope_status=asset_scope_status,
                knowledge_chunks=knowledge_chunks,
                warnings=warnings,
            )

        # 6. Quality Checks & Guardrail Enforcements
        # Ensure zero fabrication on reproduction steps
        if not analysis.steps_to_reproduce:
            analysis.steps_to_reproduce = [
                "A complete reproduction sequence was not captured in the supplied evidence."
            ]

        # Ensure zero fabrication on root cause
        if not analysis.root_cause_analysis or not analysis.root_cause_analysis.strip():
            analysis.root_cause_analysis = "Root cause was not established from the supplied evidence."

        # Fidelity with validation outcome
        val_classification = val.get("classification") if val else finding.get("classification", "UNCONFIRMED")
        if val_classification == "FALSE_POSITIVE":
            analysis.classification = "FALSE_POSITIVE"
            analysis.severity = "None"
            if not any("false positive" in w.lower() for w in analysis.warnings):
                analysis.warnings.append("Validated as FALSE_POSITIVE. Does not constitute an active vulnerability.")
        elif val_classification == "UNCONFIRMED":
            analysis.classification = "UNCONFIRMED"
            if not any("unconfirmed" in w.lower() for w in analysis.warnings):
                analysis.warnings.append("Finding lacks sufficient empirical evidence to confirm a boundary failure.")

        # Filter and validate observation citations
        verified_citations: List[ObservationCitation] = []
        valid_obs_ids = []
        for oid in analysis.referenced_observation_ids:
            if oid in obs_map:
                valid_obs_ids.append(oid)
                o = obs_map[oid]
                art_name = artifacts_map.get(o.get("artifact_id"), f"Artifact #{o.get('artifact_id')}")
                # Redact statement if any secrets
                stmt_clean, _, _ = redact_secrets(o.get("statement", ""))
                verified_citations.append(
                    ObservationCitation(
                        observation_id=oid,
                        artifact_name=art_name,
                        source_location=o.get("source_location"),
                        statement=stmt_clean,
                    )
                )

        # Fallback: if no citations referenced, pull supporting observations from val or all_obs
        if not verified_citations:
            sup_ids = []
            if val and val.get("supporting_observation_ids"):
                raw_sup = val["supporting_observation_ids"]
                sup_ids = json.loads(raw_sup) if isinstance(raw_sup, str) else list(raw_sup)
            if not sup_ids:
                sup_ids = [o["id"] for o in all_obs[:4]]
            for oid in sup_ids:
                if oid in obs_map:
                    valid_obs_ids.append(oid)
                    o = obs_map[oid]
                    art_name = artifacts_map.get(o.get("artifact_id"), f"Artifact #{o.get('artifact_id')}")
                    stmt_clean, _, _ = redact_secrets(o.get("statement", ""))
                    verified_citations.append(
                        ObservationCitation(
                            observation_id=oid,
                            artifact_name=art_name,
                            source_location=o.get("source_location"),
                            statement=stmt_clean,
                        )
                    )

        analysis.referenced_observation_ids = valid_obs_ids

        # Redact any leftover secrets in generated text fields
        analysis.executive_summary, _, _ = redact_secrets(analysis.executive_summary)
        analysis.technical_details, _, _ = redact_secrets(analysis.technical_details)
        analysis.observed_impact, _, _ = redact_secrets(analysis.observed_impact)
        analysis.potential_impact, _, _ = redact_secrets(analysis.potential_impact)
        analysis.root_cause_analysis, _, _ = redact_secrets(analysis.root_cause_analysis)
        analysis.remediation_guidance, _, _ = redact_secrets(analysis.remediation_guidance)
        cleaned_steps = []
        for step in analysis.steps_to_reproduce:
            c_step, _, _ = redact_secrets(step)
            cleaned_steps.append(c_step)
        analysis.steps_to_reproduce = cleaned_steps

        # 7. Construct SecurityReport Model
        initial_title = analysis.title or finding.get("title", "Security Finding")
        initial_title, _, _ = redact_secrets(initial_title)

        report_meta = {
            "finding_id": finding_id,
            "project_id": project_id,
            "validation_id": val.get("id") if val else None,
            "affected_asset": affected_asset_name,
            "asset_scope_status": asset_scope_status,
            "classification": analysis.classification,
            "severity": analysis.severity,
            "evidence_strength": analysis.evidence_strength,
            "analysis": analysis.model_dump(),
        }

        report = SecurityReport(
            project_id=project_id,
            finding_id=finding_id,
            validation_id=val.get("id") if val else None,
            version=1,
            title=initial_title,
            template_type=template_type,
            status=ReportStatus.DRAFT,
            format=format,
            content="",
            report_metadata=report_meta,
            content_hash="",
            analysis=analysis,
            citations=verified_citations,
        )

        # 8. Render Report Content
        if format == ReportFormat.JSON:
            content = render_json_report(report)
        else:
            if template_type == ReportTemplateType.INTERNAL:
                content = render_internal_security_report(report)
            elif template_type == ReportTemplateType.RESEARCH_VALIDATION:
                content = render_research_validation_report(report)
            else:
                content = render_bug_bounty_report(report)

        report.content = content

        # 9. Persist to Database with version auto-increment and status=DRAFT
        val_id = val.get("id") if val else None
        saved = self.db.save_report(
            project_id=project_id,
            finding_id=finding_id,
            validation_id=val_id,
            title=initial_title,
            content=content,
            template_type=template_type.value,
            status=ReportStatus.DRAFT.value,
            format=format.value,
            report_metadata=report_meta,
        )

        report.id = saved["id"]
        report.version = saved["version"]
        report.content_hash = saved["content_hash"]
        report.created_at = saved.get("created_at")
        report.updated_at = saved.get("updated_at")

        # If format was markdown, re-render with updated version number
        if format == ReportFormat.MARKDOWN:
            if template_type == ReportTemplateType.INTERNAL:
                content = render_internal_security_report(report)
            elif template_type == ReportTemplateType.RESEARCH_VALIDATION:
                content = render_research_validation_report(report)
            else:
                content = render_bug_bounty_report(report)
            report.content = content

        # 10. Log Activity
        self.db.log_activity(
            project_id,
            "REPORT_GENERATED",
            f"Generated {template_type.value} report #{report.id} v{report.version} for finding #{finding_id} [Status: DRAFT]",
        )

        return report

    # ------------------------------------------------------------------
    # AI Report Generation
    # ------------------------------------------------------------------

    def _ai_generate(
        self,
        finding: Dict[str, Any],
        val: Optional[Dict[str, Any]],
        all_obs: List[Dict[str, Any]],
        raw_evidence: List[Dict[str, Any]],
        scope: Optional[Dict[str, Any]],
        affected_asset_name: str,
        asset_scope_status: str,
        knowledge_chunks: List[str],
        template_type: ReportTemplateType,
        warnings: List[str],
    ) -> ReportAnalysis:
        """Call Gemini to synthesize finding data into structured ReportAnalysis."""
        # Format Scope
        scope_text = ""
        if scope:
            in_s = scope.get("in_scope_assets", [])
            out_s = scope.get("out_of_scope_assets", [])
            notes = scope.get("authorization_notes", "")
            scope_text = f"In-Scope: {in_s}\nOut-Of-Scope: {out_s}\nAuthorization Notes: {notes}"

        # Format Asset
        asset_text = f"Asset: {affected_asset_name}\nScope Status: {asset_scope_status}"

        # Format Finding
        finding_text = (
            f"Title: {finding.get('title')}\n"
            f"Classification: {finding.get('classification')}\n"
            f"Severity: {finding.get('severity')}\n"
            f"Summary: {finding.get('summary')}\n"
            f"Technical Details: {finding.get('technical_details')}\n"
            f"Observed Impact: {finding.get('observed_impact') or finding.get('impact')}\n"
            f"Potential Impact: {finding.get('potential_impact')}\n"
            f"Root Cause: {finding.get('root_cause')}\n"
            f"Remediation: {finding.get('remediation')}"
        )

        # Format Validation Record
        val_text = ""
        if val:
            val_text = (
                f"Validation ID: #{val.get('id')}\n"
                f"Classification: {val.get('classification')}\n"
                f"Evidence Strength: {val.get('evidence_strength')}\n"
                f"Reasoning: {val.get('reasoning')}\n"
                f"Supporting Observations: {val.get('supporting_observation_ids')}\n"
                f"Contradictory Observations: {val.get('contradictory_observation_ids')}\n"
                f"Alternative Explanations: {val.get('alternative_explanations')}\n"
                f"Missing Evidence: {val.get('missing_evidence')}\n"
                f"Observed Impact: {val.get('observed_impact')}\n"
                f"Potential Impact: {val.get('potential_impact')}\n"
                f"Unsupported Impact Claims: {val.get('unsupported_impact')}"
            )

        # Format Observations
        obs_lines = []
        for o in all_obs:
            obs_lines.append(
                f"[OBS-{o['id']}] ({o.get('category', 'OTHER')}): {o.get('statement')} (Loc: {o.get('source_location', 'N/A')})"
            )
        obs_text = "\n".join(obs_lines)

        # Format Evidence Content
        ev_lines = []
        for e in raw_evidence[:5]:
            snippet = str(e.get("content", ""))[:300]
            ev_lines.append(f"Evidence #{e['id']} [{e.get('evidence_type')}]: {snippet}")
        ev_text = "\n".join(ev_lines)

        # Format Knowledge
        knowledge_text = "\n".join(knowledge_chunks)

        user_prompt = build_security_report_prompt(
            project_scope_text=scope_text,
            asset_text=asset_text,
            finding_text=finding_text,
            validation_text=val_text,
            observations_text=obs_text,
            evidence_text=ev_text,
            knowledge_text=knowledge_text,
            template_type=template_type.value,
        )

        # Gemini Call
        client = self.genai_client
        if not client:
            from google import genai
            client = genai.Client(api_key=self.settings.gemini_api_key)

        from google.genai import types

        response = client.models.generate_content(
            model=self.settings.gemini_model,
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=SECURITY_REPORT_SYSTEM_PROMPT,
                temperature=0.2,
            ),
        )

        raw_text = response.text if hasattr(response, "text") and response.text else "{}"
        data = _extract_json(raw_text)

        # Combine warnings
        all_warn = list(set(warnings + data.get("warnings", [])))

        return ReportAnalysis(
            title=str(data.get("title", finding.get("title", "Security Finding"))),
            executive_summary=str(data.get("executive_summary", "")),
            affected_asset=affected_asset_name,
            asset_scope_status=asset_scope_status,
            classification=str(data.get("classification", finding.get("classification", "UNCONFIRMED"))),
            severity=str(data.get("severity", finding.get("severity", "Unknown"))),
            evidence_strength=str(data.get("evidence_strength", "NONE")),
            technical_details=str(data.get("technical_details", "")),
            steps_to_reproduce=data.get("steps_to_reproduce", []),
            expected_behavior=str(data.get("expected_behavior", "")),
            observed_behavior=str(data.get("observed_behavior", "")),
            observed_impact=str(data.get("observed_impact", "")),
            potential_impact=str(data.get("potential_impact", "")),
            unsupported_impact_claims=data.get("unsupported_impact_claims", []),
            root_cause_analysis=str(data.get("root_cause_analysis", "")),
            remediation_guidance=str(data.get("remediation_guidance", "")),
            alternative_explanations=data.get("alternative_explanations", []),
            reproduction_gap_analysis=data.get("reproduction_gap_analysis"),
            referenced_observation_ids=data.get("referenced_observation_ids", []),
            knowledge_citations=data.get("knowledge_citations", []),
            warnings=all_warn,
        )

    # ------------------------------------------------------------------
    # Deterministic Report Generation Fallback
    # ------------------------------------------------------------------

    def _deterministic_generate(
        self,
        finding: Dict[str, Any],
        val: Optional[Dict[str, Any]],
        all_obs: List[Dict[str, Any]],
        affected_asset_name: str,
        asset_scope_status: str,
        knowledge_chunks: List[str],
        warnings: List[str],
    ) -> ReportAnalysis:
        """Deterministic synthesis of project finding data without LLM invocation."""
        classification = val.get("classification") if val else finding.get("classification", "UNCONFIRMED")
        evidence_strength = val.get("evidence_strength") if val else ("STRONG" if all_obs else "NONE")
        severity = finding.get("severity", "Unknown")

        # Executive Summary
        if classification == "FALSE_POSITIVE":
            exec_summary = (
                f"Security testing evaluated a potential vulnerability in {affected_asset_name}. "
                f"Empirical validation demonstrated that the observed behavior is either intended functionality "
                f"or that security controls effectively prevent boundary bypass."
            )
        elif classification == "UNCONFIRMED":
            exec_summary = (
                f"An initial anomaly was recorded for {affected_asset_name}, but current researcher-supplied "
                f"evidence is insufficient to confirm a security boundary failure."
            )
        else:
            exec_summary = (
                finding.get("summary")
                or f"A validated security vulnerability was confirmed on {affected_asset_name} with {evidence_strength.lower()} empirical evidence."
            )

        # Technical Details
        tech_details = finding.get("technical_details") or ""
        if not tech_details and all_obs:
            tech_details = "\n".join(f"- [OBS-{o['id']}]: {o['statement']}" for o in all_obs[:4])
        elif not tech_details:
            tech_details = "Technical details were not provided in the finding record."

        # Reproduction Steps
        steps: List[str] = []
        raw_steps = finding.get("steps_to_reproduce")
        if raw_steps:
            if isinstance(raw_steps, list):
                steps = [str(s) for s in raw_steps]
            elif isinstance(raw_steps, str):
                lines = [line.strip() for line in raw_steps.splitlines() if line.strip()]
                steps = [re.sub(r"^\d+[\.\)]\s*", "", line) for line in lines]

        # Alternative Explanations
        alts: List[str] = []
        if val and val.get("alternative_explanations"):
            raw_alts = val["alternative_explanations"]
            alts = json.loads(raw_alts) if isinstance(raw_alts, str) else list(raw_alts)

        # Impact fields
        obs_impact = ""
        if val and val.get("observed_impact"):
            obs_impact = val["observed_impact"]
        elif finding.get("observed_impact"):
            obs_impact = finding["observed_impact"]
        elif finding.get("impact"):
            obs_impact = finding["impact"]

        pot_impact = ""
        if val and val.get("potential_impact"):
            pot_impact = val["potential_impact"]
        elif finding.get("potential_impact"):
            pot_impact = finding["potential_impact"]

        unsupported_claims: List[str] = []
        if val and val.get("unsupported_impact"):
            raw_unsup = val["unsupported_impact"]
            if isinstance(raw_unsup, str) and raw_unsup.strip():
                unsupported_claims = [raw_unsup.strip()]

        # Referenced Observation IDs
        ref_ids: List[int] = []
        if val and val.get("supporting_observation_ids"):
            raw_s = val["supporting_observation_ids"]
            parsed = json.loads(raw_s) if isinstance(raw_s, str) else list(raw_s)
            ref_ids = [int(x) for x in parsed if str(x).isdigit()]
        if not ref_ids and all_obs:
            ref_ids = [o["id"] for o in all_obs[:5]]

        return ReportAnalysis(
            title=finding.get("title") or "Security Finding",
            executive_summary=exec_summary,
            affected_asset=affected_asset_name,
            asset_scope_status=asset_scope_status,
            classification=classification,
            severity=severity,
            evidence_strength=evidence_strength,
            technical_details=tech_details,
            steps_to_reproduce=steps,
            expected_behavior=finding.get("expected_behavior") or "Application enforces intended authorization boundaries.",
            observed_behavior=finding.get("observed_behavior") or (all_obs[0]["statement"] if all_obs else "Observed behavior documented in observations."),
            observed_impact=obs_impact,
            potential_impact=pot_impact,
            unsupported_impact_claims=unsupported_claims,
            root_cause_analysis=finding.get("root_cause") or "",
            remediation_guidance=finding.get("remediation") or "Implement strict server-side validation and boundary enforcement.",
            alternative_explanations=alts,
            reproduction_gap_analysis=val.get("reasoning") if val and not steps else None,
            referenced_observation_ids=ref_ids,
            knowledge_citations=knowledge_chunks,
            warnings=list(warnings),
        )

    # ------------------------------------------------------------------
    # Approval & Lifecycle Management
    # ------------------------------------------------------------------

    def approve_report(
        self,
        report_id: int,
        reviewer: str = "Lead Security Researcher",
    ) -> Dict[str, Any]:
        """Human approval gate: transitions report from DRAFT/READY_FOR_REVIEW to APPROVED."""
        if not self.db:
            raise ValueError("DatabaseManager required.")

        report = self.db.get_report(report_id)
        if not report:
            raise ValueError(f"Report #{report_id} not found.")

        updated = self.db.update_report_status(
            report_id=report_id,
            status=ReportStatus.APPROVED.value,
            approved_by=reviewer,
        )

        self.db.log_activity(
            report["project_id"],
            "REPORT_APPROVED",
            f"Security report #{report_id} v{report.get('version', 1)} was approved by '{reviewer}'",
        )
        return updated or {}

    def export_report(
        self,
        report_id: int,
        format: str = "markdown",
        output_path: Optional[str] = None,
    ) -> str:
        """Export report content to file or string, updating lifecycle status to EXPORTED."""
        if not self.db:
            raise ValueError("DatabaseManager required.")

        report_dict = self.db.get_report(report_id)
        if not report_dict:
            raise ValueError(f"Report #{report_id} not found.")

        content = report_dict.get("content", "")

        # Write to file if requested
        if output_path:
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")

        # If currently APPROVED, transition status to EXPORTED
        if report_dict.get("status") == ReportStatus.APPROVED.value:
            self.db.update_report_status(report_id, ReportStatus.EXPORTED.value)

        self.db.log_activity(
            report_dict["project_id"],
            "REPORT_EXPORTED",
            f"Security report #{report_id} exported as {format.upper()}" + (f" to '{output_path}'" if output_path else ""),
        )

        return content


def _extract_json(text: str) -> dict:
    """Extract and parse JSON object from text with optional markdown code blocks."""
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        text = match.group(1)
    else:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1:
            text = text[start : end + 1]
    try:
        return json.loads(text)
    except Exception:
        return {}
