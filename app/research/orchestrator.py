"""Research Orchestrator service — project-aware research guidance.

Answers the question: "What should I investigate next in this project?"
Combines ProjectContext, ProjectHealth, and hybrid knowledge retrieval to produce
structured, prioritized next-step recommendations for the human researcher.

SAFETY:
- The orchestrator NEVER performs autonomous target scanning, exploitation, or payload execution.
- Every recommendation is a HUMAN ACTION CHECKPOINT for the researcher.
- Unknown-scope assets are never assumed to be authorized.
- Hypotheses remain theories until verified with researcher-supplied evidence.
"""

import json
import re
from typing import Any, Dict, List, Optional

from app.agent.prompts import RESEARCH_ORCHESTRATOR_SYSTEM_PROMPT, build_research_orchestrator_prompt
from app.config import get_settings, Settings
from app.knowledge.retriever import KnowledgeRetriever
from app.research.context import (
    ContextLimits,
    ProjectContextBuilder,
    evaluate_project_health,
    format_context_summary,
)
from app.research.models import (
    HypothesisStatus,
    ObjectiveStatus,
    ProjectContext,
    ProjectHealth,
    ProjectOverallState,
    ResearchOrchestrationResult,
    ResearchRecommendation,
    ScopeStatus,
)
from app.storage.database import DatabaseManager


class ResearchOrchestrator:
    """Orchestrates research inquiry based on project state and local security knowledge."""

    def __init__(
        self,
        db: DatabaseManager,
        retriever: Optional[KnowledgeRetriever] = None,
        settings: Optional[Settings] = None,
        genai_client: Optional[Any] = None,
        limits: Optional[ContextLimits] = None,
    ):
        self.db = db
        self.settings = settings or get_settings()
        self.retriever = retriever or KnowledgeRetriever(db)
        self._genai_client = genai_client
        self.limits = limits or ContextLimits()
        self.context_builder = ProjectContextBuilder(
            db=db,
            limits=self.limits,
            retriever=self.retriever,
        )

    def _get_client(self) -> Optional[Any]:
        if self._genai_client is not None:
            return self._genai_client
        if not self.settings.has_gemini_key:
            return None
        from google import genai
        return genai.Client(api_key=self.settings.gemini_api_key)

    def orchestrate(
        self,
        project_id: int,
        limit: int = 3,
        sources_only: bool = False,
    ) -> ResearchOrchestrationResult:
        """Determine what the researcher should investigate next.

        1. Assembles bounded project context snapshot.
        2. Computes deterministic project health.
        3. Queries relevant knowledge references via hybrid retrieval.
        4. If sources_only=True or no Gemini key, uses deterministic heuristics.
        5. If Gemini is available, uses grounded AI orchestration.
        6. Returns structured ResearchOrchestrationResult.
        """
        # Step 1: Build context and health
        context = self.context_builder.build_context(project_id, include_knowledge=True)
        health = evaluate_project_health(context)

        # Step 2: Extract knowledge sources
        relevant_sources = list(context.knowledge_sources)

        # Step 3: Check if offline / sources_only mode is required
        client = self._get_client()
        if sources_only or client is None:
            return self._deterministic_orchestrate(context, health, relevant_sources, limit=limit)

        # Step 4: AI-assisted Orchestration via Gemini
        context_text = format_context_summary(context)
        health_summary = (
            f"Overall State: {health.overall_state.value}\n"
            f"Scope Status: {health.scope_status}\n"
            f"Objective Status: {health.objective_status}\n"
            f"Hypothesis Status: {health.hypothesis_status}\n"
            f"Evidence Status: {health.evidence_status}\n"
            f"Finding Status: {health.finding_status}\n"
            f"Blockers: {health.blockers}\n"
            f"Warnings: {health.warnings}"
        )
        knowledge_text = "\n".join(relevant_sources)
        user_prompt = build_research_orchestrator_prompt(context_text, health_summary, knowledge_text)

        from google.genai import types

        try:
            response = client.models.generate_content(
                model=self.settings.gemini_model,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=RESEARCH_ORCHESTRATOR_SYSTEM_PROMPT,
                    temperature=0.2,
                ),
            )
            raw_text = response.text if hasattr(response, "text") and response.text else "{}"
            data = _extract_json(raw_text)
            if not data or "recommendations" not in data:
                # Fall back gracefully to deterministic logic if JSON was invalid
                return self._deterministic_orchestrate(
                    context,
                    health,
                    relevant_sources,
                    limit=limit,
                    fallback_warning="Gemini returned non-structured response. Using deterministic orchestration.",
                )

            # Parse recommendations
            recs: List[ResearchRecommendation] = []
            for item in data.get("recommendations", [])[:limit]:
                recs.append(
                    ResearchRecommendation(
                        title=str(item.get("title", "Research Recommendation")),
                        objective_id=item.get("objective_id"),
                        hypothesis_id=item.get("hypothesis_id"),
                        rationale=str(item.get("rationale", "")),
                        relevant_knowledge=_safe_list(item.get("relevant_knowledge")),
                        evidence_needed=_safe_list(item.get("evidence_needed")),
                        validation_questions=_safe_list(item.get("validation_questions")),
                        priority=str(item.get("priority", "MEDIUM")).upper(),
                        confidence=str(item.get("confidence", "LOW")).upper(),
                        blockers=_safe_list(item.get("blockers")),
                    )
                )

            # Combine health blockers/warnings with AI output
            all_blockers = list(set(health.blockers + _safe_list(data.get("blockers"))))
            all_warnings = list(set(health.warnings + _safe_list(data.get("warnings"))))

            return ResearchOrchestrationResult(
                project_state_summary=str(data.get("project_state_summary", "Project analysis complete.")),
                health=health,
                blockers=all_blockers,
                warnings=all_warnings,
                recommendations=recs,
                next_best_question=str(data.get("next_best_question", "What technical evidence should be collected next?")),
                relevant_sources=relevant_sources,
            )

        except Exception as e:
            return self._deterministic_orchestrate(
                context,
                health,
                relevant_sources,
                limit=limit,
                fallback_warning=f"Gemini API error ({e}). Using deterministic orchestration.",
            )

    def _deterministic_orchestrate(
        self,
        context: ProjectContext,
        health: ProjectHealth,
        relevant_sources: List[str],
        limit: int = 3,
        fallback_warning: Optional[str] = None,
    ) -> ResearchOrchestrationResult:
        """Deterministic, rule-based next-research planner (no Gemini call required)."""
        recommendations: List[ResearchRecommendation] = []
        warnings = list(health.warnings)
        if fallback_warning:
            warnings.append(fallback_warning)

        # 1. State: BLOCKED or NO_SCOPE
        if health.overall_state == ProjectOverallState.BLOCKED or health.scope_status in ("NO_SCOPE", "ALL_UNKNOWN_ASSETS"):
            summary = "Research is currently blocked due to missing or unverified scope authorization."
            recommendations.append(
                ResearchRecommendation(
                    title="Define Scope and Authorize Target Assets",
                    rationale="Testing cannot begin without explicit authorization notes and in-scope target definition.",
                    relevant_knowledge=relevant_sources[:2],
                    evidence_needed=["Engagement rules", "Program policy documentation", "Explicit target authorization list"],
                    validation_questions=["Are the target domains/APIs owned or explicitly authorized for security testing?"],
                    priority="HIGH",
                    confidence="HIGH",
                    blockers=["Missing in-scope authorization."],
                )
            )
            next_q = "What specific assets and constraints are defined in the authorized scope documentation?"

        # 2. State: HAS UNKNOWN ASSETS
        elif context.unknown_scope_assets and not context.in_scope_assets:
            summary = "Assets have been cataloged, but their authorization status is UNKNOWN."
            recommendations.append(
                ResearchRecommendation(
                    title="Verify Asset Authorization Status",
                    rationale="Assets default to UNKNOWN scope. The researcher must verify in-scope status before performing tests.",
                    relevant_knowledge=[],
                    evidence_needed=["Bug bounty policy or scope documentation"],
                    validation_questions=["Is each asset explicitly included in the program policy?"],
                    priority="HIGH",
                    confidence="HIGH",
                    blockers=["Assets marked UNKNOWN scope."],
                )
            )
            unknown_names = ", ".join(a.name for a in context.unknown_scope_assets[:3])
            next_q = f"Are the following assets explicitly authorized for active testing: {unknown_names}?"

        # 3. State: INITIALIZING / NO OBJECTIVES
        elif not context.objectives:
            summary = "Project scope is established, but no research objectives have been defined."
            goal = context.project.research_goal or "systematic security assessment"
            recommendations.append(
                ResearchRecommendation(
                    title="Formulate Core Research Objectives",
                    rationale=f"Define specific testing objectives aligned with the research goal: '{goal}'.",
                    relevant_knowledge=relevant_sources[:3],
                    evidence_needed=["Architectural overview", "Key endpoints or interfaces list"],
                    validation_questions=["What core security boundaries (e.g. auth, access control, input handling) need evaluation?"],
                    priority="HIGH",
                    confidence="MEDIUM",
                    blockers=[],
                )
            )
            next_q = f"What primary security boundaries should be evaluated to achieve: '{goal}'?"

        # 4. State: READY_FOR_RESEARCH / NO HYPOTHESES
        elif not context.hypotheses:
            summary = "Research objectives exist, but no testable hypotheses have been generated yet."
            primary_obj = context.open_objectives[0] if context.open_objectives else context.objectives[0]
            recommendations.append(
                ResearchRecommendation(
                    title=f"Generate Testable Hypotheses for '{primary_obj.title}'",
                    objective_id=primary_obj.id,
                    rationale="Formulate specific, testable security hypotheses based on known methodologies.",
                    relevant_knowledge=relevant_sources[:3],
                    evidence_needed=["Endpoint behaviors", "Technology stack documentation"],
                    validation_questions=["What specific failure modes or bypasses are plausible for this objective?"],
                    priority="HIGH",
                    confidence="MEDIUM",
                    blockers=[],
                )
            )
            next_q = f"What specific architectural assumptions or edge cases in '{primary_obj.title}' could be tested?"

        # 5. State: UNTESTED HYPOTHESES / AWAITING EVIDENCE OR VALIDATION
        elif context.untested_hypotheses:
            hyps_with_ev = {e.hypothesis_id for e in context.evidence if e.hypothesis_id}.union(
                {o.hypothesis_id for o in context.observations if o.hypothesis_id}
            )
            summary = f"Project has {len(context.untested_hypotheses)} untested hypothesis(es)."
            for hyp in context.untested_hypotheses[:limit]:
                if hyp.id in hyps_with_ev:
                    recommendations.append(
                        ResearchRecommendation(
                            title=f"Validate Hypothesis: {hyp.title}",
                            objective_id=hyp.objective_id,
                            hypothesis_id=hyp.id,
                            rationale=f"Hypothesis #{hyp.id} has linked evidence/observations. Run finding validation to assess sufficiency.",
                            relevant_knowledge=relevant_sources[:2],
                            evidence_needed=["Multi-role comparison requests", "Baseline unauthenticated request"],
                            validation_questions=[
                                "Does the evidence establish that authorization was bypassed?",
                                "Are there benign alternative explanations (e.g. cached responses)?",
                            ],
                            priority="HIGH",
                            confidence="MEDIUM",
                            blockers=[],
                        )
                    )
                else:
                    recommendations.append(
                        ResearchRecommendation(
                            title=f"Investigate Hypothesis: {hyp.title}",
                            objective_id=hyp.objective_id,
                            hypothesis_id=hyp.id,
                            rationale="Hypothesis is currently UNTESTED and lacks evidence. Collect technical captures.",
                            relevant_knowledge=relevant_sources[:2],
                            evidence_needed=["HTTP request and response pairs", "Application error logs", "Parameter tamper observations"],
                            validation_questions=[
                                "Does the observed behavior deviate from expected security controls?",
                                "Is the behavior reproducible across different sessions or roles?",
                            ],
                            priority="HIGH",
                            confidence="MEDIUM",
                            blockers=[],
                        )
                    )
            first_hyp = context.untested_hypotheses[0]
            next_q = f"What concrete technical evidence demonstrates whether '{first_hyp.title}' is valid?"

        # 6. State: VALIDATION REQUIRED (Unconfirmed findings or contradictory evidence)
        elif any(f.validation_status == "UNCONFIRMED" for f in context.findings):
            unconfirmed = [f for f in context.findings if f.validation_status == "UNCONFIRMED"]
            summary = f"{len(unconfirmed)} finding(s) require rigorous validation and falsification screening."

            # Check if any recent validation surfaced contradictions
            recent_contra = [
                v for v in getattr(context, "latest_validations", [])
                if v.contradictory_observation_ids
            ]
            if recent_contra:
                cv = recent_contra[-1]
                recommendations.append(
                    ResearchRecommendation(
                        title=f"Resolve Contradictory Evidence for Hypothesis #{cv.hypothesis_id or 'N/A'}",
                        hypothesis_id=cv.hypothesis_id,
                        rationale="Validation identified contradictory observations indicating security controls may be active. Perform clarifying differential tests.",
                        relevant_knowledge=relevant_sources[:2],
                        evidence_needed=["Differential tests clarifying why access denial was observed"],
                        validation_questions=["Why did some requests return 401/403 while others succeeded?"],
                        priority="HIGH",
                        confidence="LOW",
                        blockers=[],
                    )
                )

            for finding in unconfirmed[:limit - len(recommendations)]:
                recommendations.append(
                    ResearchRecommendation(
                        title=f"Validate Finding: {finding.title}",
                        rationale="Finding is UNCONFIRMED. Screen for benign alternative explanations and false positives.",
                        relevant_knowledge=relevant_sources[:2],
                        evidence_needed=["Multi-role verification", "Session isolation proofs", "Impact demonstration evidence"],
                        validation_questions=[
                            "Can this behavior be explained by intended application features?",
                            "Is there demonstrable security impact on confidentiality, integrity, or availability?",
                        ],
                        priority="HIGH",
                        confidence="MEDIUM",
                        blockers=[],
                    )
                )
            first_f = unconfirmed[0]
            next_q = f"Does the current evidence rule out benign alternative explanations for '{first_f.title}'?"

        # 7. State: READY_FOR_REPORT
        elif health.overall_state == ProjectOverallState.READY_FOR_REPORT:
            summary = "All objectives, hypotheses, and findings have been investigated and validated."
            for f in context.findings:
                if f.classification in ("CONFIRMED", "LIKELY"):
                    recommendations.append(
                        ResearchRecommendation(
                            title=f"Generate Security Report for Finding #{f.id}: {f.title}",
                            rationale=f"Finding #{f.id} is {f.classification}. Synthesize into formal Bug Bounty or Internal Security Report using 'project report {f.id}'.",
                            relevant_knowledge=[],
                            evidence_needed=["Final reproduction steps verification", "Remediation recommendations"],
                            validation_questions=["Are all reproduction steps clear, minimal, and fully documented?"],
                            priority="HIGH",
                            confidence="HIGH",
                            blockers=[],
                        )
                    )
            if not recommendations:
                recommendations.append(
                    ResearchRecommendation(
                        title="Review Findings and Prepare Research Report",
                        rationale="All active research streams are resolved. Prepare structured technical report.",
                        relevant_knowledge=[],
                        evidence_needed=["Final reproduction steps verification", "Remediation recommendations"],
                        validation_questions=["Are all reproduction steps clear, minimal, and fully documented?"],
                        priority="MEDIUM",
                        confidence="HIGH",
                        blockers=[],
                    )
                )
            next_q = "Are all confirmed findings documented with unambiguous reproduction steps and remediation guidance?"

        # 8. General Research in Progress
        else:
            summary = "Research is actively in progress across open objectives."
            primary_obj = context.open_objectives[0] if context.open_objectives else (context.objectives[0] if context.objectives else None)
            obj_title = primary_obj.title if primary_obj else "systematic testing"
            recommendations.append(
                ResearchRecommendation(
                    title=f"Continue Active Research on '{obj_title}'",
                    objective_id=primary_obj.id if primary_obj else None,
                    rationale="Conduct systematic inquiry on remaining open objectives and gather corroborating evidence.",
                    relevant_knowledge=relevant_sources[:2],
                    evidence_needed=["Observed behavior logs", "Boundary test captures"],
                    validation_questions=["Have all critical asset endpoints for this objective been assessed?"],
                    priority="MEDIUM",
                    confidence="MEDIUM",
                    blockers=[],
                )
            )
            next_q = f"What additional evidence is needed to complete the objective: '{obj_title}'?"

        return ResearchOrchestrationResult(
            project_state_summary=summary,
            health=health,
            blockers=health.blockers,
            warnings=warnings,
            recommendations=recommendations[:limit],
            next_best_question=next_q,
            relevant_sources=relevant_sources,
        )


def _extract_json(text: str) -> dict:
    """Extract a JSON object from text that may contain markdown code fences."""
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


def _safe_list(value: Any) -> List[str]:
    """Safely coerce a value to a list of strings."""
    if isinstance(value, list):
        return [str(x) for x in value if x is not None]
    if isinstance(value, str):
        return [value] if value.strip() else []
    return []
