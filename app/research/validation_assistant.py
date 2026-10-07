"""Finding Validation Engine for Phase 8.

Analyzes researcher-supplied evidence, structured observations, project scope,
and local security knowledge against hypotheses and findings.

Safety constraints:
- NEVER fabricates evidence, requests, responses, screenshots, or tool outputs.
- Retrieved knowledge is reference DATA ONLY (prompt injection defense).
- Strictly maintains: Observation != Finding.
- Does not autonomously interact with targets, scan, or exploit.
- Respects scope boundaries and surfaces authorization warnings when scope is UNKNOWN.
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from app.agent.prompts import (
    FINDING_VALIDATION_SYSTEM_PROMPT,
    VALIDATION_SYSTEM_PROMPT,
    build_finding_validation_prompt,
    build_validation_prompt,
)
from app.config import get_settings, Settings
from app.knowledge.context import ContextBuilder
from app.knowledge.retriever import KnowledgeRetriever
from app.research.models import (
    ConfidenceLevel,
    EvidenceStrength,
    ValidationAnalysis,
    ValidationResult,
)
from app.storage.database import DatabaseManager


class ValidationAssistant:
    """Rigorous Finding Validation Engine.

    Evaluates whether available researcher evidence and observations
    sufficiently support a security hypothesis or finding.
    """

    def __init__(
        self,
        db: DatabaseManager,
        retriever: Optional[KnowledgeRetriever] = None,
        settings: Optional[Settings] = None,
        genai_client: Optional[Any] = None,
    ):
        self.db = db
        self.settings = settings or get_settings()
        self.retriever = retriever or KnowledgeRetriever(db)
        self._genai_client = genai_client
        self._context_builder = ContextBuilder(
            max_sources=self.settings.rag_max_sources,
            max_chars=self.settings.rag_max_chars,
        )

    def _get_client(self) -> Optional[Any]:
        if self._genai_client is not None:
            return self._genai_client
        if not self.settings.has_gemini_key:
            return None
        from google import genai
        return genai.Client(api_key=self.settings.gemini_api_key)

    def validate(
        self,
        project_id: int,
        hypothesis_id: Optional[int] = None,
        finding_id: Optional[int] = None,
        evidence_ids: Optional[List[int]] = None,
        no_ai: bool = False,
        sources_only: bool = False,
    ) -> ValidationResult:
        """Analyze whether researcher-supplied evidence supports a hypothesis or finding.

        Pipeline:
        1. Verify project & scope authorization.
        2. Load hypothesis and/or finding record.
        3. Load researcher evidence and structured observations.
        4. Retrieve relevant reference knowledge (hybrid RAG).
        5. Execute deterministic pre-checks and heuristic classification.
        6. If AI enabled, prompt Gemini with strict untrusted data isolation.
        7. Record validation audit history in database.
        8. Return structured ValidationResult.
        """
        # Backward-compatibility: if 3rd positional argument is a list, it is evidence_ids
        if isinstance(finding_id, (list, tuple)):
            evidence_ids = list(finding_id)
            finding_id = None

        evidence_ids = evidence_ids or []

        # Step 1: Verify project
        project = self.db.get_project_by_id(project_id) if hasattr(self.db, "get_project_by_id") else None
        if not project:
            # Fallback to list_projects check
            all_projs = self.db.list_projects()
            proj_dict = next((p for p in all_projs if p["id"] == project_id), None)
            if not proj_dict:
                raise ValueError(f"Project ID {project_id} not found.")

        # Step 2: Load hypothesis and/or finding
        hypothesis = None
        finding = None

        if hypothesis_id is not None:
            hypothesis = self.db.get_hypothesis(hypothesis_id)
            if hypothesis is None:
                raise ValueError(f"Hypothesis ID {hypothesis_id} not found.")

        if finding_id is not None:
            finding = self.db.get_finding(finding_id)
            if finding is None:
                raise ValueError(f"Finding ID {finding_id} not found.")
            if hypothesis is None and finding.get("hypothesis_id"):
                hypothesis = self.db.get_hypothesis(finding["hypothesis_id"])

        if hypothesis is None and finding is None:
            raise ValueError("Must provide at least hypothesis_id or finding_id for validation.")

        # Synthesize a reference hypothesis if only finding is provided
        if hypothesis is None and finding is not None:
            hypothesis = {
                "id": None,
                "project_id": project_id,
                "title": finding["title"],
                "description": finding.get("summary", ""),
                "rationale": finding.get("technical_details", ""),
                "status": finding.get("validation_status", "UNCONFIRMED"),
            }

        # Step 3: Check Project Scope (Rule 8)
        scope_record = self.db.get_project_scope(project_id)
        assets = self.db.list_assets(project_id)
        scope_warning = None
        scope_summary_text = ""

        if not scope_record:
            scope_warning = "TARGET AUTHORIZATION WARNING: Scope has not been defined for this project. Target authorization status is UNKNOWN."
            scope_summary_text = "Scope Status: UNKNOWN (No scope definition recorded)"
        else:
            in_scope = scope_record.get("in_scope_assets", [])
            out_scope = scope_record.get("out_of_scope_assets", [])
            scope_summary_text = (
                f"In-Scope: {', '.join(in_scope) if in_scope else 'None specified'}\n"
                f"Out-of-Scope: {', '.join(out_scope) if out_scope else 'None specified'}\n"
                f"Authorization Notes: {scope_record.get('authorization_notes') or 'None'}"
            )
            target_asset_name = finding.get("affected_asset") if finding else None
            if target_asset_name:
                matching_asset = next((a for a in assets if a.get("name") == target_asset_name), None)
                if matching_asset and matching_asset.get("scope_status") == "UNKNOWN":
                    scope_warning = f"TARGET AUTHORIZATION WARNING: Affected asset '{target_asset_name}' scope status is UNKNOWN."
            elif all(a.get("scope_status") == "UNKNOWN" for a in assets) and assets:
                scope_warning = "TARGET AUTHORIZATION WARNING: All project assets are currently classified with UNKNOWN scope status."

        # Step 4: Load Evidence & Observations
        evidence_items = self.db.get_research_evidence_by_ids(evidence_ids) if evidence_ids else []

        # Load linked structured observations
        if hypothesis.get("id"):
            linked_obs = self.db.list_observations(project_id, hypothesis_id=hypothesis["id"])
        else:
            linked_obs = self.db.list_observations(project_id)

        # Step 5: Retrieve relevant reference knowledge (hybrid RAG)
        query = hypothesis.get("title", "")
        if finding and finding.get("title"):
            query += " " + finding["title"]
        search_results = self.retriever.search(query.strip(), limit=6, mode="hybrid")
        context_text, _ = self._context_builder.build_context(
            results=search_results,
            max_sources=6,
            max_chars=self.settings.rag_max_chars,
        )
        sources_list = [f"[{r.source_path} - {r.title or 'Doc'} (score: {r.score:.2f})]" for r in search_results]

        # Step 6: Deterministic Pre-Check & Heuristics (Rules 1-7)
        supp_ids, supp_stmts, contra_ids, contra_stmts = self._detect_contradictions_and_support(
            linked_obs, hypothesis.get("title", "")
        )
        alt_explanations = self._detect_alternative_explanations(linked_obs, evidence_items)
        missing_ev = self._detect_missing_evidence(linked_obs, bool(contra_ids))
        obs_impact, pot_impact, unsup_impact = self._assess_impact_separation(
            linked_obs, hypothesis.get("title", "")
        )

        # Rule 1 & 2: Zero evidence supplied
        if not evidence_items and not linked_obs:
            reasoning = (
                "[PROJECT EVIDENCE] No researcher-supplied evidence or observations were provided. "
                "A hypothesis cannot be validated without empirical evidence. "
                "[KNOWLEDGE BASE] Retrieved security methodologies are reference material only and do not prove target vulnerabilities."
            )
            val_record = self.db.record_validation(
                project_id=project_id,
                finding_id=finding_id,
                hypothesis_id=hypothesis.get("id"),
                classification="UNCONFIRMED",
                evidence_strength=EvidenceStrength.NONE.value,
                confidence=ConfidenceLevel.LOW.value,
                reasoning=reasoning,
                supporting_observation_ids=[],
                contradictory_observation_ids=[],
                alternative_explanations=[],
                missing_evidence=["Researcher must supply concrete evidence (HTTP traffic, logs, configuration, source code)..."],
                observed_impact=None,
                potential_impact=pot_impact,
                unsupported_impact=unsup_impact,
                validation_questions=["What specific endpoint or parameter was tested?", "What observed behavior indicates a security boundary failure?"],
                knowledge_sources=sources_list,
            )
            return ValidationResult(
                hypothesis_id=hypothesis.get("id"),
                finding_id=finding_id,
                is_evidence_sufficient=False,
                evidence_strength=EvidenceStrength.NONE,
                classification="UNCONFIRMED",
                confidence=ConfidenceLevel.LOW,
                reasoning=reasoning,
                evidence_summary="No evidence supplied. Cannot validate hypothesis without researcher-provided evidence.",
                supporting_observations=[],
                supporting_observation_ids=[],
                contradictory_observations=[],
                contradictory_observation_ids=[],
                alternative_explanations=[],
                missing_evidence=["Researcher must supply concrete evidence (HTTP traffic, logs, configuration, source code)..."],
                observed_impact=None,
                potential_impact=pot_impact,
                unsupported_impact=unsup_impact,
                validation_questions=["What specific endpoint or parameter was tested?", "What observed behavior indicates a security boundary failure?"],
                relevant_sources=sources_list,
                scope_warning=scope_warning,
                warning="No evidence supplied. Cannot validate hypothesis without researcher-provided evidence.",
                validation_id=val_record["id"],
            )

        # Step 7: Decide AI vs. Deterministic
        client = self._get_client()
        run_ai = (client is not None) and (not no_ai) and (not sources_only)

        if not run_ai:
            return self._build_deterministic_result(
                project_id=project_id,
                hypothesis=hypothesis,
                finding_id=finding_id,
                supp_ids=supp_ids,
                supp_stmts=supp_stmts,
                contra_ids=contra_ids,
                contra_stmts=contra_stmts,
                alt_explanations=alt_explanations,
                missing_ev=missing_ev,
                obs_impact=obs_impact,
                pot_impact=pot_impact,
                unsup_impact=unsup_impact,
                sources_list=sources_list,
                scope_warning=scope_warning,
                fallback_reason="Offline mode or GEMINI_API_KEY not configured." if client is None else "CLI flag requested deterministic analysis.",
            )

        # Step 8: Call Gemini with Prompt Injection Defense
        user_prompt = build_finding_validation_prompt(
            hypothesis=hypothesis,
            evidence_items=evidence_items,
            observations=linked_obs,
            context_text=context_text,
            scope_summary=scope_summary_text,
            finding=finding,
        )

        from google.genai import types

        try:
            response = client.models.generate_content(
                model=self.settings.gemini_model,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=FINDING_VALIDATION_SYSTEM_PROMPT,
                    temperature=0.1,
                ),
            )
            raw_text = response.text if hasattr(response, "text") and response.text else "{}"
            data = _extract_json(raw_text)
            if data:
                if "suggested_classification" in data and "classification" not in data:
                    data["classification"] = data["suggested_classification"]
                if "reasoning" not in data:
                    if "rationale" in data:
                        data["reasoning"] = data["rationale"]
                    elif "evidence_summary" in data:
                        data["reasoning"] = data["evidence_summary"]

            if not data or "classification" not in data:
                return self._build_deterministic_result(
                    project_id=project_id,
                    hypothesis=hypothesis,
                    finding_id=finding_id,
                    supp_ids=supp_ids,
                    supp_stmts=supp_stmts,
                    contra_ids=contra_ids,
                    contra_stmts=contra_stmts,
                    alt_explanations=alt_explanations,
                    missing_ev=missing_ev,
                    obs_impact=obs_impact,
                    pot_impact=pot_impact,
                    unsup_impact=unsup_impact,
                    sources_list=sources_list,
                    scope_warning=scope_warning,
                    fallback_reason="Gemini returned unstructured output. Using deterministic validation engine.",
                )

            analysis = ValidationAnalysis(**data)

            # Prompt injection defense check: Ensure AI didn't claim CONFIRMED if there are no supporting observations or if contradictory evidence refutes it
            final_class = analysis.classification.upper()
            final_strength = analysis.evidence_strength.upper()
            final_conf = analysis.confidence.upper()

            if contra_ids and not supp_ids:
                final_class = "FALSE_POSITIVE"
                final_strength = "STRONG"
            elif not supp_ids and final_class in ("CONFIRMED", "LIKELY"):
                final_class = "UNCONFIRMED"
                final_strength = "NONE"
                final_conf = "LOW"

            # Reconcile observation citations with actual data
            valid_obs_ids = {o["id"] for o in linked_obs}
            final_supp_ids = [i for i in analysis.supporting_observation_ids if i in valid_obs_ids] or supp_ids
            final_contra_ids = [i for i in analysis.contradictory_observation_ids if i in valid_obs_ids] or contra_ids

            final_supp_stmts = [f"[OBS-{o['id']}] {o.get('statement', '')}" for o in linked_obs if o["id"] in final_supp_ids]
            final_contra_stmts = [f"[OBS-{o['id']}] {o.get('statement', '')}" for o in linked_obs if o["id"] in final_contra_ids]

            val_record = self.db.record_validation(
                project_id=project_id,
                finding_id=finding_id,
                hypothesis_id=hypothesis.get("id"),
                classification=final_class,
                evidence_strength=final_strength,
                confidence=final_conf,
                reasoning=analysis.reasoning,
                supporting_observation_ids=final_supp_ids,
                contradictory_observation_ids=final_contra_ids,
                alternative_explanations=analysis.alternative_explanations or alt_explanations,
                missing_evidence=analysis.missing_evidence or missing_ev,
                observed_impact=analysis.observed_impact or obs_impact,
                potential_impact=analysis.potential_impact or pot_impact,
                unsupported_impact=analysis.unsupported_impact or unsup_impact,
                validation_questions=analysis.validation_questions,
                knowledge_sources=sources_list,
            )

            self.db.log_activity(
                project_id,
                "VALIDATION_COMPLETED",
                f"Finding validation #{val_record['id']} for Hypothesis {hypothesis.get('id') or 'N/A'}: {final_class} [{final_strength}]",
            )

            return ValidationResult(
                hypothesis_id=hypothesis.get("id"),
                finding_id=finding_id,
                is_evidence_sufficient=final_class in ("CONFIRMED", "LIKELY"),
                evidence_strength=EvidenceStrength(final_strength) if final_strength in EvidenceStrength.__members__ else EvidenceStrength.NONE,
                classification=final_class,
                confidence=ConfidenceLevel(final_conf) if final_conf in ConfidenceLevel.__members__ else ConfidenceLevel.LOW,
                reasoning=analysis.reasoning,
                supporting_observations=final_supp_stmts,
                supporting_observation_ids=final_supp_ids,
                contradictory_observations=final_contra_stmts,
                contradictory_observation_ids=final_contra_ids,
                alternative_explanations=analysis.alternative_explanations or alt_explanations,
                missing_evidence=analysis.missing_evidence or missing_ev,
                observed_impact=analysis.observed_impact or obs_impact,
                potential_impact=analysis.potential_impact or pot_impact,
                unsupported_impact=analysis.unsupported_impact or unsup_impact,
                validation_questions=analysis.validation_questions,
                relevant_sources=sources_list,
                scope_warning=scope_warning,
                validation_id=val_record["id"],
            )

        except Exception as e:
            return self._build_deterministic_result(
                project_id=project_id,
                hypothesis=hypothesis,
                finding_id=finding_id,
                supp_ids=supp_ids,
                supp_stmts=supp_stmts,
                contra_ids=contra_ids,
                contra_stmts=contra_stmts,
                alt_explanations=alt_explanations,
                missing_ev=missing_ev,
                obs_impact=obs_impact,
                pot_impact=pot_impact,
                unsup_impact=unsup_impact,
                sources_list=sources_list,
                scope_warning=scope_warning,
                fallback_reason=f"Gemini API error ({e}). Using deterministic validation engine.",
            )

    def _build_deterministic_result(
        self,
        project_id: int,
        hypothesis: dict,
        finding_id: Optional[int],
        supp_ids: List[int],
        supp_stmts: List[str],
        contra_ids: List[int],
        contra_stmts: List[str],
        alt_explanations: List[str],
        missing_ev: List[str],
        obs_impact: Optional[str],
        pot_impact: Optional[str],
        unsup_impact: Optional[str],
        sources_list: List[str],
        scope_warning: Optional[str],
        fallback_reason: str,
    ) -> ValidationResult:
        """Deterministic rule-based validation engine when offline or Gemini is unavailable."""
        if contra_ids and not supp_ids:
            classification = "FALSE_POSITIVE"
            strength = EvidenceStrength.STRONG
            confidence = ConfidenceLevel.HIGH
            is_sufficient = True
            reasoning = (
                f"[PROJECT EVIDENCE] Observed data directly contradicts the hypothesis: "
                f"{'; '.join(contra_stmts[:2])}. Technical controls are actively enforced."
            )
        elif contra_ids and supp_ids:
            classification = "POSSIBLE"
            strength = EvidenceStrength.WEAK
            confidence = ConfidenceLevel.LOW
            is_sufficient = False
            reasoning = (
                f"[PROJECT EVIDENCE] Conflicting evidence detected. Supporting observations exist ({len(supp_ids)}), "
                f"but contradictory observations ({'; '.join(contra_stmts[:2])}) indicate access control is active. "
                "Requires further differential investigation."
            )
        elif supp_ids:
            if len(supp_ids) >= 3:
                classification = "LIKELY"
                strength = EvidenceStrength.STRONG
                confidence = ConfidenceLevel.MEDIUM
                is_sufficient = True
                reasoning = (
                    f"[PROJECT EVIDENCE] Multiple consistent observations support the hypothesis: "
                    f"{'; '.join(supp_stmts[:3])}. Demonstrated behavior is consistent with an authorization flaw."
                )
            else:
                classification = "POSSIBLE"
                strength = EvidenceStrength.MODERATE if len(supp_ids) == 2 else EvidenceStrength.WEAK
                confidence = ConfidenceLevel.LOW
                is_sufficient = False
                reasoning = (
                    f"[PROJECT EVIDENCE] Observation(s) {', '.join(f'OBS-{i}' for i in supp_ids)} "
                    "are consistent with the hypothesis, but additional multi-role comparison evidence is required."
                )
        else:
            classification = "UNCONFIRMED"
            strength = EvidenceStrength.NONE
            confidence = ConfidenceLevel.LOW
            is_sufficient = False
            reasoning = "[PROJECT EVIDENCE] Evidence was provided, but no relevant observations directly supported the hypothesis."

        # Add scope warning to reasoning if applicable
        if scope_warning:
            reasoning = f"{scope_warning}\n\n{reasoning}"

        val_record = self.db.record_validation(
            project_id=project_id,
            finding_id=finding_id,
            hypothesis_id=hypothesis.get("id"),
            classification=classification,
            evidence_strength=strength.value,
            confidence=confidence.value,
            reasoning=reasoning,
            supporting_observation_ids=supp_ids,
            contradictory_observation_ids=contra_ids,
            alternative_explanations=alt_explanations,
            missing_evidence=missing_ev,
            observed_impact=obs_impact,
            potential_impact=pot_impact,
            unsupported_impact=unsup_impact,
            validation_questions=[
                "Does the observed behavior persist across multiple independent sessions?",
                "Can this behavior be reproduced using an unauthenticated or alternate role?",
            ],
            knowledge_sources=sources_list,
        )

        self.db.log_activity(
            project_id,
            "VALIDATION_COMPLETED",
            f"Validation #{val_record['id']} for Hypothesis {hypothesis.get('id') or 'N/A'}: {classification} [{strength.value}] (Deterministic)",
        )

        return ValidationResult(
            hypothesis_id=hypothesis.get("id"),
            finding_id=finding_id,
            is_evidence_sufficient=is_sufficient,
            evidence_strength=strength,
            classification=classification,
            confidence=confidence,
            reasoning=reasoning,
            supporting_observations=supp_stmts,
            supporting_observation_ids=supp_ids,
            contradictory_observations=contra_stmts,
            contradictory_observation_ids=contra_ids,
            alternative_explanations=alt_explanations,
            missing_evidence=missing_ev,
            observed_impact=obs_impact,
            potential_impact=pot_impact,
            unsupported_impact=unsup_impact,
            validation_questions=[
                "Does the observed behavior persist across multiple independent sessions?",
                "Can this behavior be reproduced using an unauthenticated or alternate role?",
            ],
            relevant_sources=sources_list,
            scope_warning=scope_warning,
            warning=fallback_reason,
            validation_id=val_record["id"],
        )

    def apply_validation_to_finding(
        self,
        project_id: int,
        finding_id: int,
        validation_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Explicitly apply a validation result to update a finding's state in the database."""
        finding = self.db.get_finding(finding_id)
        if not finding:
            raise ValueError(f"Finding ID {finding_id} not found.")

        if validation_id is not None:
            val = self.db.get_validation(validation_id)
        else:
            val = self.db.get_latest_validation(project_id, finding_id=finding_id)
            if not val and finding.get("hypothesis_id"):
                val = self.db.get_latest_validation(project_id, hypothesis_id=finding["hypothesis_id"])
            if not val:
                val = self.db.get_latest_validation(project_id)

        if not val:
            raise ValueError(f"No validation record found for finding ID {finding_id}.")

        supp_ids = val.get("supporting_observation_ids", [])
        if isinstance(supp_ids, str):
            try:
                supp_ids = json.loads(supp_ids)
            except Exception:
                supp_ids = []

        impact_text = val.get("observed_impact") or val.get("potential_impact") or finding.get("impact", "")

        updated = self.db.update_finding(
            finding_id,
            classification=val["classification"],
            validation_status=val["classification"],
            confidence=val["confidence"],
            impact=impact_text,
            observed_impact=val.get("observed_impact"),
            potential_impact=val.get("potential_impact"),
            evidence_ids=supp_ids,
        )

        self.db.log_activity(
            project_id=project_id,
            event_type="FINDING_UPDATED",
            description=f"Applied validation #{val['id']} to Finding {finding_id}: {val['classification']} [{val['confidence']}]",
        )
        return updated

    # -------------------------------------------------------------
    # Rule Heuristic Helpers
    # -------------------------------------------------------------

    def _detect_contradictions_and_support(
        self,
        observations: List[Dict[str, Any]],
        hypothesis_title: str,
    ) -> Tuple[List[int], List[str], List[int], List[str]]:
        """Separates observations into supporting vs contradictory."""
        contra_keywords = [
            "401", "403", "unauthorized", "forbidden", "access denied", "denied",
            "signature verification failed", "signature failed", "invalid signature",
            "signature verified", "token rejected", "expired token rejected",
            "permission denied", "csrf token mismatch", "blocked by waf",
            "sanitized", "escaped", "input rejected", "invalid token",
            "invalidresettoken", "invalid session", "rejected"
        ]

        contradictory_ids: List[int] = []
        contradictory_stmts: List[str] = []
        supporting_ids: List[int] = []
        supporting_stmts: List[str] = []

        for obs in observations:
            stmt = obs.get("statement", "")
            stmt_lower = stmt.lower()
            obs_id = obs["id"]

            is_contra = False
            for kw in contra_keywords:
                if kw in stmt_lower:
                    contradictory_ids.append(obs_id)
                    contradictory_stmts.append(f"[OBS-{obs_id}] {stmt}")
                    is_contra = True
                    break

            if not is_contra:
                supporting_ids.append(obs_id)
                supporting_stmts.append(f"[OBS-{obs_id}] {stmt}")

        return supporting_ids, supporting_stmts, contradictory_ids, contradictory_stmts

    def _detect_alternative_explanations(
        self,
        observations: List[Dict[str, Any]],
        evidence_items: List[Dict[str, Any]],
    ) -> List[str]:
        alternatives = []
        all_text = " ".join(
            [(o.get("statement") or "") for o in observations]
            + [f"{e.get('content') or ''} {e.get('description') or ''}" for e in evidence_items]
        ).lower()

        if "cache-control" in all_text or "age:" in all_text or "x-cache" in all_text:
            alternatives.append("Observed response may be served from intermediate cache rather than origin server.")
        if "public" in all_text or "anonymous" in all_text or "well-known" in all_text or "docs" in all_text:
            alternatives.append("Endpoint or data may be intentionally public by architectural design.")
        if "demo" in all_text or "test" in all_text or "sample" in all_text:
            alternatives.append("Target asset or credential may be a test/demo fixture with mock responses.")
        if "stale" in all_text or "expired" in all_text or "session" in all_text:
            alternatives.append("Response could reflect stale session state rather than an active authorization bypass.")
        if "proxy" in all_text or "gateway" in all_text or "cloudflare" in all_text or "nginx" in all_text:
            alternatives.append("Header or error behavior may be generated by reverse proxy / API gateway rather than application logic.")
        if not alternatives and (observations or evidence_items):
            alternatives.append("Observed behavior could represent expected API design rather than authorization bypass without multi-role comparison.")
        return alternatives

    def _detect_missing_evidence(
        self,
        observations: List[Dict[str, Any]],
        has_contradiction: bool,
    ) -> List[str]:
        missing = [
            "Differential comparison requests between distinct authenticated user roles (e.g. User A vs User B).",
            "Baseline request showing behavior when no authentication token or cookie is supplied.",
            "Reproduction trace demonstrating persistence of the behavior across multiple sessions.",
        ]
        if has_contradiction:
            missing.insert(0, "Clarifying test resolving why contradictory access control rejections (401/403) were observed.")
        return missing

    def _assess_impact_separation(
        self,
        observations: List[Dict[str, Any]],
        hypothesis_title: str,
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Returns (observed_impact, potential_impact, unsupported_impact)."""
        if not observations:
            return None, "Potential impact cannot be determined without empirical evidence.", "Any claimed security impact is unsupported."

        obs_stmts = [o.get("statement", "") for o in observations]
        observed_str = "; ".join(obs_stmts[:3])
        observed_impact = f"Evidence directly demonstrates: {observed_str}"

        potential_impact = f"If verified across unauthorized sessions, could lead to {hypothesis_title.lower()}."
        unsupported_impact = "Complete account takeover, server-side code execution, or full tenant compromise is unsupported by current evidence."
        return observed_impact, potential_impact, unsupported_impact


# Facade alias for FindingValidationEngine
FindingValidationEngine = ValidationAssistant


def _extract_json(text: str) -> dict:
    """Extract a JSON object from a response that may contain markdown code fences."""
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
    except (json.JSONDecodeError, ValueError):
        return {}
