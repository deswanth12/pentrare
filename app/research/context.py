"""Project context builder and health analyzer for Phase 6.

Assembles bounded, strongly typed project state snapshots for reasoning
and research orchestration without secret leaks or unbounded memory dumps.
"""

import json
import re
from typing import Any, Dict, List, Optional

from app.config import get_settings
from app.knowledge.retriever import KnowledgeRetriever
from app.research.models import (
    Asset,
    EvidenceArtifact,
    FindingRecord,
    Hypothesis,
    HypothesisStatus,
    ObjectiveStatus,
    Observation,
    ProjectActivity,
    ProjectContext,
    ProjectHealth,
    ProjectOverallState,
    ProjectRecord,
    ProjectScope,
    ResearchEvidence,
    ResearchObjective,
    ScopeStatus,
    TruncationInfo,
    ValidationRecord,
    ReportRecord,
)
from app.storage.database import DatabaseManager


class ContextLimits:
    """Configurable bounds to prevent context window explosion."""

    def __init__(
        self,
        max_activities: int = 15,
        max_evidence: int = 20,
        max_findings: int = 20,
        max_hypotheses: int = 25,
        max_objectives: int = 25,
        max_assets: int = 50,
        max_knowledge_sources: int = 8,
        max_chars: int = 25000,
    ):
        self.max_activities = max_activities
        self.max_evidence = max_evidence
        self.max_findings = max_findings
        self.max_hypotheses = max_hypotheses
        self.max_objectives = max_objectives
        self.max_assets = max_assets
        self.max_knowledge_sources = max_knowledge_sources
        self.max_chars = max_chars


def evaluate_project_health(context: ProjectContext) -> ProjectHealth:
    """Evaluate deterministic workflow health from current project context.

    Note: This measures WORKFLOW READINESS and PROGRESSION, not an
    arbitrary numerical security score.
    """
    blockers: List[str] = []
    warnings: List[str] = []

    # 1. Scope Health
    scope = context.scope
    has_in_scope = len(context.in_scope_assets) > 0
    has_unknown = len(context.unknown_scope_assets) > 0

    if not scope or (not scope.in_scope_assets and not scope.out_of_scope_assets and not scope.authorization_notes):
        scope_status = "NO_SCOPE"
        blockers.append("No explicit scope or authorization notes defined.")
    elif has_unknown and not has_in_scope:
        scope_status = "ALL_UNKNOWN_ASSETS"
        blockers.append("All project assets have UNKNOWN scope. Verify authorization before any testing.")
    elif has_unknown:
        scope_status = "HAS_UNKNOWN_ASSETS"
        warnings.append(f"{len(context.unknown_scope_assets)} asset(s) have UNKNOWN scope. Authorization must be confirmed.")
    else:
        scope_status = "DEFINED"

    # 2. Project Goal
    goal = context.project.research_goal
    if not goal or not goal.strip():
        warnings.append("Project has no defined research goal. Consider defining one to focus testing.")

    # 3. Objective Health
    total_objs = len(context.objectives)
    open_objs = len(context.open_objectives)
    if total_objs == 0:
        objective_status = "NO_OBJECTIVES"
        warnings.append("No research objectives defined yet.")
    elif open_objs > 0:
        objective_status = "OPEN_OBJECTIVES_PRESENT"
    else:
        objective_status = "ALL_COMPLETED"

    # 4. Hypothesis Health
    total_hyps = len(context.hypotheses)
    untested_hyps = len(context.untested_hypotheses)
    inconclusive_hyps = [h for h in context.hypotheses if h.status == HypothesisStatus.INCONCLUSIVE]

    if total_hyps == 0:
        hypothesis_status = "NO_HYPOTHESES"
    elif untested_hyps > 0:
        hypothesis_status = "UNTESTED_PRESENT"
    elif inconclusive_hyps:
        hypothesis_status = "INCONCLUSIVE_PRESENT"
        warnings.append(f"{len(inconclusive_hyps)} hypothesis(es) are inconclusive and require additional evidence.")
    else:
        hypothesis_status = "ALL_TESTED"

    # 5. Evidence Health
    total_ev = len(context.evidence) + len(context.artifacts)
    # Check if hypotheses lack evidence
    hyps_with_evidence = {e.hypothesis_id for e in context.evidence if e.hypothesis_id is not None}
    hyps_with_obs = {o.hypothesis_id for o in context.observations if o.hypothesis_id is not None}
    all_hyps_with_ev = hyps_with_evidence.union(hyps_with_obs)
    hyps_missing_ev = [h for h in context.hypotheses if h.id not in all_hyps_with_ev]

    if total_hyps > 0 and total_ev == 0:
        evidence_status = "NO_EVIDENCE"
        warnings.append("Hypotheses exist but zero researcher evidence has been recorded.")
    elif hyps_missing_ev and total_hyps > 0:
        evidence_status = "MISSING_EVIDENCE"
        warnings.append(f"{len(hyps_missing_ev)} hypothesis(es) lack linked evidence.")
    elif total_ev > 0:
        evidence_status = "EVIDENCE_COLLECTED"
    else:
        evidence_status = "NO_EVIDENCE"

    # 6. Finding Health
    unconfirmed_findings = [
        f for f in context.findings
        if f.validation_status == "UNCONFIRMED" or f.classification == "UNCONFIRMED"
    ]
    confirmed_findings = [
        f for f in context.findings
        if f.classification in ("CONFIRMED", "LIKELY")
    ]

    if len(context.findings) == 0:
        finding_status = "NO_FINDINGS"
    elif unconfirmed_findings:
        finding_status = "UNVALIDATED_FINDINGS"
        warnings.append(f"{len(unconfirmed_findings)} finding(s) are awaiting validation.")
    elif confirmed_findings:
        finding_status = "CONFIRMED_PRESENT"
    else:
        finding_status = "FINDINGS_RESOLVED"

    # 7. Overall State Determination
    if blockers:
        overall_state = ProjectOverallState.BLOCKED
    elif scope_status == "NO_SCOPE" or total_objs == 0:
        overall_state = ProjectOverallState.INITIALIZING
    elif total_hyps == 0:
        overall_state = ProjectOverallState.READY_FOR_RESEARCH
    elif untested_hyps > 0 and total_ev == 0:
        overall_state = ProjectOverallState.AWAITING_EVIDENCE
    elif unconfirmed_findings:
        overall_state = ProjectOverallState.VALIDATION_REQUIRED
    elif open_objs > 0 or untested_hyps > 0 or hyps_missing_ev:
        overall_state = ProjectOverallState.RESEARCH_IN_PROGRESS
    elif total_objs > 0 and open_objs == 0 and untested_hyps == 0 and not unconfirmed_findings:
        overall_state = ProjectOverallState.READY_FOR_REPORT
    else:
        overall_state = ProjectOverallState.RESEARCH_IN_PROGRESS

    return ProjectHealth(
        overall_state=overall_state,
        scope_status=scope_status,
        objective_status=objective_status,
        hypothesis_status=hypothesis_status,
        evidence_status=evidence_status,
        finding_status=finding_status,
        blockers=blockers,
        warnings=warnings,
    )


class ProjectContextBuilder:
    """Builds a deterministic, bounded, and sanitized snapshot of project state."""

    def __init__(
        self,
        db: DatabaseManager,
        limits: Optional[ContextLimits] = None,
        retriever: Optional[KnowledgeRetriever] = None,
    ):
        self.db = db
        self.limits = limits or ContextLimits()
        self.retriever = retriever

    def build_context(
        self,
        project_id: int,
        include_knowledge: bool = True,
        knowledge_query: Optional[str] = None,
    ) -> ProjectContext:
        """Assemble bounded project context.

        1. Fetches metadata and entities.
        2. Applies deterministic limits and prioritization.
        3. Annotates truncation metadata if thresholds are exceeded.
        4. Queries relevant knowledge references (bounded).
        5. Sanitizes against credentials and secret leakage.
        """
        # Fetch raw project
        raw_proj = self.db.get_project_by_id(project_id)
        if not raw_proj:
            raise ValueError(f"Project ID {project_id} not found.")

        proj_rec = ProjectRecord(
            id=raw_proj["id"],
            name=_scrub_secrets(raw_proj["name"]),
            description=_scrub_secrets(raw_proj.get("description")),
            status=raw_proj.get("status", "active"),
            research_goal=_scrub_secrets(raw_proj.get("research_goal")),
            scope_summary=_scrub_secrets(raw_proj.get("scope_summary")),
            created_at=raw_proj.get("created_at"),
            updated_at=raw_proj.get("updated_at"),
        )

        # Scope
        raw_scope = self.db.get_project_scope(project_id)
        scope_rec: Optional[ProjectScope] = None
        if raw_scope:
            scope_rec = ProjectScope(
                id=raw_scope["id"],
                project_id=raw_scope["project_id"],
                in_scope_assets=raw_scope.get("in_scope_assets", "[]"),
                out_of_scope_assets=raw_scope.get("out_of_scope_assets", "[]"),
                allowed_testing_notes=_scrub_secrets(raw_scope.get("allowed_testing_notes")),
                prohibited_actions=_scrub_secrets(raw_scope.get("prohibited_actions")),
                authorization_notes=_scrub_secrets(raw_scope.get("authorization_notes")),
                created_at=raw_scope.get("created_at"),
                updated_at=raw_scope.get("updated_at"),
            )

        # Assets
        raw_assets = self.db.list_assets(project_id)
        all_assets: List[Asset] = []
        for a in raw_assets:
            all_assets.append(
                Asset(
                    id=a["id"],
                    project_id=a["project_id"],
                    name=_scrub_secrets(a["name"]),
                    asset_type=a.get("asset_type", "other"),
                    identifier=_scrub_secrets(a.get("identifier")),
                    scope_status=a.get("scope_status", ScopeStatus.UNKNOWN),
                    technology=_scrub_secrets(a.get("technology")),
                    notes=_scrub_secrets(a.get("notes")),
                    created_at=a.get("created_at"),
                    updated_at=a.get("updated_at"),
                )
            )

        # Objectives
        raw_objs = self.db.list_objectives(project_id)
        all_objs: List[ResearchObjective] = []
        for o in raw_objs:
            all_objs.append(
                ResearchObjective(
                    id=o["id"],
                    project_id=o["project_id"],
                    title=_scrub_secrets(o["title"]),
                    description=_scrub_secrets(o.get("description")),
                    priority=o.get("priority", "MEDIUM"),
                    status=o.get("status", "OPEN"),
                    notes=_scrub_secrets(o.get("notes")),
                    created_at=o.get("created_at"),
                    updated_at=o.get("updated_at"),
                )
            )

        # Hypotheses
        raw_hyps = self.db.list_hypotheses(project_id)
        all_hyps: List[Hypothesis] = []
        for h in raw_hyps:
            all_hyps.append(
                Hypothesis(
                    id=h["id"],
                    project_id=h["project_id"],
                    objective_id=h.get("objective_id"),
                    title=_scrub_secrets(h["title"]),
                    description=_scrub_secrets(h.get("description")),
                    rationale=_scrub_secrets(h.get("rationale")),
                    status=h.get("status", HypothesisStatus.UNTESTED),
                    confidence=h.get("confidence", "LOW"),
                    created_at=h.get("created_at"),
                    updated_at=h.get("updated_at"),
                )
            )

        # Evidence
        raw_ev = self.db.list_research_evidence(project_id)
        all_ev: List[ResearchEvidence] = []
        for e in raw_ev:
            all_ev.append(
                ResearchEvidence(
                    id=e["id"],
                    project_id=e["project_id"],
                    hypothesis_id=e.get("hypothesis_id"),
                    evidence_type=e.get("evidence_type", "OBSERVATION"),
                    title=_scrub_secrets(e["title"]),
                    description=_scrub_secrets(e.get("description")),
                    content=_scrub_secrets(e.get("content")),
                    source=_scrub_secrets(e.get("source")),
                    researcher_note=_scrub_secrets(e.get("researcher_note")),
                    confidence=e.get("confidence", "LOW"),
                    timestamp=e.get("timestamp"),
                    created_at=e.get("created_at"),
                )
            )

        # Findings
        raw_findings = self.db.list_findings(project_id)
        all_findings: List[FindingRecord] = []
        for f in raw_findings:
            all_findings.append(
                FindingRecord(
                    id=f["id"],
                    project_id=f["project_id"],
                    title=_scrub_secrets(f["title"]),
                    severity=f.get("severity", "Unknown"),
                    classification=f.get("classification", "UNCONFIRMED"),
                    affected_asset=_scrub_secrets(f.get("affected_asset")),
                    summary=_scrub_secrets(f.get("summary")),
                    technical_details=_scrub_secrets(f.get("technical_details")),
                    impact=_scrub_secrets(f.get("impact")),
                    root_cause=_scrub_secrets(f.get("root_cause")),
                    remediation=_scrub_secrets(f.get("remediation")),
                    evidence_ids=f.get("evidence_ids", "[]"),
                    validation_status=f.get("validation_status", "UNCONFIRMED"),
                    confidence=f.get("confidence", "LOW"),
                    created_at=f.get("created_at"),
                    updated_at=f.get("updated_at"),
                )
            )

        # Activities
        raw_act = self.db.list_activities(project_id)
        all_act: List[ProjectActivity] = []
        for act in raw_act:
            all_act.append(
                ProjectActivity(
                    id=act["id"],
                    project_id=act["project_id"],
                    event_type=act["event_type"],
                    description=_scrub_secrets(act.get("description")),
                    timestamp=act.get("timestamp"),
                )
            )

        # Truncation tracking
        truncated_categories: List[str] = []
        total_counts = {
            "assets": len(all_assets),
            "objectives": len(all_objs),
            "hypotheses": len(all_hyps),
            "evidence": len(all_ev),
            "findings": len(all_findings),
            "activities": len(all_act),
        }

        # 1. Truncate Assets (keep IN_SCOPE, then UNKNOWN, then OUT_OF_SCOPE)
        retained_assets = all_assets
        if len(all_assets) > self.limits.max_assets:
            in_s = [a for a in all_assets if a.scope_status == ScopeStatus.IN_SCOPE]
            unk_s = [a for a in all_assets if a.scope_status == ScopeStatus.UNKNOWN]
            out_s = [a for a in all_assets if a.scope_status == ScopeStatus.OUT_OF_SCOPE]
            prioritized = in_s + unk_s + out_s
            retained_assets = prioritized[: self.limits.max_assets]
            truncated_categories.append("assets")

        # 2. Truncate Objectives (keep OPEN/IN_PROGRESS first)
        retained_objs = all_objs
        if len(all_objs) > self.limits.max_objectives:
            open_first = sorted(all_objs, key=lambda x: 0 if x.status in (ObjectiveStatus.OPEN, ObjectiveStatus.IN_PROGRESS) else 1)
            retained_objs = open_first[: self.limits.max_objectives]
            truncated_categories.append("objectives")

        # 3. Truncate Hypotheses (keep UNTESTED first)
        retained_hyps = all_hyps
        if len(all_hyps) > self.limits.max_hypotheses:
            untested_first = sorted(all_hyps, key=lambda x: 0 if x.status == HypothesisStatus.UNTESTED else 1)
            retained_hyps = untested_first[: self.limits.max_hypotheses]
            truncated_categories.append("hypotheses")

        # 4. Truncate Evidence (keep most recent)
        retained_ev = all_ev
        if len(all_ev) > self.limits.max_evidence:
            retained_ev = all_ev[-self.limits.max_evidence :]
            truncated_categories.append("evidence")

        # 5. Truncate Findings (keep UNCONFIRMED / LIKELY first)
        retained_findings = all_findings
        if len(all_findings) > self.limits.max_findings:
            unconfirmed_first = sorted(all_findings, key=lambda x: 0 if x.validation_status == "UNCONFIRMED" else 1)
            retained_findings = unconfirmed_first[: self.limits.max_findings]
            truncated_categories.append("findings")

        # 6. Truncate Activities (keep latest N)
        retained_act = all_act
        if len(all_act) > self.limits.max_activities:
            retained_act = all_act[-self.limits.max_activities :]
            truncated_categories.append("activities")

        retained_counts = {
            "assets": len(retained_assets),
            "objectives": len(retained_objs),
            "hypotheses": len(retained_hyps),
            "evidence": len(retained_ev),
            "findings": len(retained_findings),
            "activities": len(retained_act),
        }

        trunc_info = TruncationInfo(
            truncated=bool(truncated_categories),
            truncated_categories=truncated_categories,
            total_items_counted=total_counts,
            items_retained=retained_counts,
        )

        # Partition assets
        in_scope_assets = [a for a in retained_assets if a.scope_status == ScopeStatus.IN_SCOPE]
        out_of_scope_assets = [a for a in retained_assets if a.scope_status == ScopeStatus.OUT_OF_SCOPE]
        unknown_scope_assets = [a for a in retained_assets if a.scope_status == ScopeStatus.UNKNOWN]

        # Partition objectives
        open_objs = [o for o in retained_objs if o.status in (ObjectiveStatus.OPEN, ObjectiveStatus.IN_PROGRESS)]
        comp_objs = [o for o in retained_objs if o.status == ObjectiveStatus.COMPLETED]

        # Partition hypotheses
        untested_hyps = [h for h in retained_hyps if h.status == HypothesisStatus.UNTESTED]

        # Bounded Knowledge Retrieval
        knowledge_sources: List[str] = []
        if include_knowledge and self.retriever:
            query = knowledge_query or proj_rec.research_goal
            if not query and open_objs:
                query = open_objs[0].title
            if not query and untested_hyps:
                query = untested_hyps[0].title
            if not query:
                query = proj_rec.name

            if query and query.strip():
                try:
                    results = self.retriever.search(
                        query.strip(),
                        limit=self.limits.max_knowledge_sources,
                        mode="hybrid",
                    )
                    for r in results:
                        source_id = f"[{r.source_path} § {r.section} (score: {r.score:.2f})]"
                        knowledge_sources.append(source_id)
                except Exception:
                    # Non-fatal if retrieval fails
                    pass

        # Phase 7: Evidence Artifacts & Observations
        raw_artifacts = self.db.list_evidence_artifacts(project_id)
        all_artifacts: List[EvidenceArtifact] = []
        for art in raw_artifacts:
            all_artifacts.append(
                EvidenceArtifact(
                    id=art["id"],
                    project_id=art["project_id"],
                    filename=_scrub_secrets(art["filename"]),
                    artifact_type=art.get("artifact_type", "UNKNOWN"),
                    source_path=_scrub_secrets(art.get("source_path")),
                    content_hash=art.get("content_hash", ""),
                    size_bytes=art.get("size_bytes", 0),
                    metadata=art.get("metadata", {}),
                    created_at=art.get("created_at"),
                )
            )

        raw_observations = self.db.list_observations(project_id)
        all_observations: List[Observation] = []
        for obs in raw_observations:
            all_observations.append(
                Observation(
                    id=obs["id"],
                    artifact_id=obs["artifact_id"],
                    project_id=obs["project_id"],
                    category=obs.get("category", "OTHER"),
                    statement=_scrub_secrets(obs["statement"]),
                    source_location=obs.get("source_location"),
                    confidence=obs.get("confidence", "MEDIUM"),
                    hypothesis_id=obs.get("hypothesis_id"),
                    created_at=obs.get("created_at"),
                )
            )

        # Phase 8: Finding Validations History
        raw_validations = self.db.list_validations(project_id) if hasattr(self.db, "list_validations") else []
        all_validations: List[ValidationRecord] = []
        for val in raw_validations[-5:]:
            all_validations.append(
                ValidationRecord(
                    id=val["id"],
                    project_id=val["project_id"],
                    finding_id=val.get("finding_id"),
                    hypothesis_id=val.get("hypothesis_id"),
                    classification=val.get("classification", "UNCONFIRMED"),
                    evidence_strength=val.get("evidence_strength", "NONE"),
                    confidence=val.get("confidence", "LOW"),
                    reasoning=_scrub_secrets(val.get("reasoning")),
                    supporting_observation_ids=val.get("supporting_observation_ids", []),
                    contradictory_observation_ids=val.get("contradictory_observation_ids", []),
                    alternative_explanations=val.get("alternative_explanations", []),
                    missing_evidence=val.get("missing_evidence", []),
                    observed_impact=_scrub_secrets(val.get("observed_impact")),
                    potential_impact=_scrub_secrets(val.get("potential_impact")),
                    unsupported_impact=_scrub_secrets(val.get("unsupported_impact")),
                    validation_questions=val.get("validation_questions", []),
                    knowledge_sources=val.get("knowledge_sources", []),
                    created_at=val.get("created_at"),
                )
            )

        # Phase 9: Security Reports
        raw_reports = self.db.list_reports(project_id=project_id) if hasattr(self.db, "list_reports") else []
        all_reports: List[ReportRecord] = []
        for rep in raw_reports[-5:]:
            all_reports.append(
                ReportRecord(
                    id=rep["id"],
                    project_id=rep["project_id"],
                    finding_id=rep["finding_id"],
                    validation_id=rep.get("validation_id"),
                    version=rep.get("version", 1),
                    title=_scrub_secrets(rep["title"]),
                    template_type=rep.get("template_type", "BUG_BOUNTY"),
                    status=rep.get("status", "DRAFT"),
                    format=rep.get("format", "MARKDOWN"),
                    content=_scrub_secrets(rep.get("content", "")),
                    report_metadata=rep.get("report_metadata", {}),
                    content_hash=rep.get("content_hash", ""),
                    approved_by=rep.get("approved_by"),
                    approved_at=rep.get("approved_at"),
                    created_at=rep.get("created_at"),
                    updated_at=rep.get("updated_at"),
                )
            )

        return ProjectContext(
            project=proj_rec,
            scope=scope_rec,
            assets=retained_assets,
            in_scope_assets=in_scope_assets,
            out_of_scope_assets=out_of_scope_assets,
            unknown_scope_assets=unknown_scope_assets,
            objectives=retained_objs,
            open_objectives=open_objs,
            completed_objectives=comp_objs,
            hypotheses=retained_hyps,
            untested_hypotheses=untested_hyps,
            evidence=retained_ev,
            findings=retained_findings,
            recent_activities=retained_act,
            knowledge_sources=knowledge_sources,
            artifacts=all_artifacts,
            observations=all_observations,
            latest_validations=all_validations,
            latest_reports=all_reports,
            reports_count=len(raw_reports),
            truncation=trunc_info,
        )


def format_context_summary(context: ProjectContext) -> str:
    """Format a human-readable text summary of the bounded project context."""
    lines: List[str] = []
    p = context.project
    lines.append("=" * 65)
    lines.append(f" PROJECT CONTEXT: {p.name} (ID: {p.id})")
    lines.append("=" * 65)
    lines.append(f"Status:        {p.status}")
    lines.append(f"Research Goal: {p.research_goal or '(not set)'}")
    lines.append(f"Description:   {p.description or '-'}")
    lines.append("")

    # Scope
    lines.append("SCOPE & AUTHORIZATION:")
    if context.scope:
        s = context.scope
        lines.append(f"  In-Scope Targets ({len(s.in_scope_assets)}):     " + (", ".join(s.in_scope_assets) if s.in_scope_assets else "(none)"))
        lines.append(f"  Out-of-Scope Targets ({len(s.out_of_scope_assets)}): " + (", ".join(s.out_of_scope_assets) if s.out_of_scope_assets else "(none)"))
        lines.append(f"  Authorization Notes: {s.authorization_notes or '(not specified)'}")
        if s.prohibited_actions:
            lines.append(f"  Prohibited Actions:  {s.prohibited_actions}")
    else:
        lines.append("  (No scope record found. Use 'project add-scope')")
    lines.append("")

    # Assets
    lines.append(f"ASSET INVENTORY ({len(context.assets)} items):")
    if context.in_scope_assets:
        lines.append(f"  IN_SCOPE ({len(context.in_scope_assets)}): " + ", ".join(a.name for a in context.in_scope_assets))
    if context.unknown_scope_assets:
        lines.append(f"  UNKNOWN ({len(context.unknown_scope_assets)}):  " + ", ".join(a.name for a in context.unknown_scope_assets) + " [!] Requires scope verification")
    if context.out_of_scope_assets:
        lines.append(f"  OUT_OF_SCOPE ({len(context.out_of_scope_assets)}): " + ", ".join(a.name for a in context.out_of_scope_assets))
    if not context.assets:
        lines.append("  (No assets recorded)")
    lines.append("")

    # Objectives
    lines.append(f"RESEARCH OBJECTIVES ({len(context.objectives)} total, {len(context.open_objectives)} open):")
    for o in context.objectives:
        lines.append(f"  [{o.status}] [{o.priority}] ID:{o.id} - {o.title}")
    if not context.objectives:
        lines.append("  (No objectives recorded)")
    lines.append("")

    # Hypotheses
    lines.append(f"HYPOTHESES ({len(context.hypotheses)} total, {len(context.untested_hypotheses)} untested):")
    for h in context.hypotheses:
        lines.append(f"  [{h.status}] [Conf:{h.confidence}] ID:{h.id} - {h.title}")
    if not context.hypotheses:
        lines.append("  (No hypotheses recorded)")
    lines.append("")

    # Evidence
    lines.append(f"RESEARCH EVIDENCE ({len(context.evidence)} items):")
    for ev in context.evidence:
        hyp_link = f" (Hypothesis: {ev.hypothesis_id})" if ev.hypothesis_id else ""
        lines.append(f"  [{ev.evidence_type}] ID:{ev.id} - {ev.title}{hyp_link}")
    if not context.evidence:
        lines.append("  (No evidence recorded)")
    lines.append("")

    # Phase 7 Artifacts & Observations
    if context.artifacts:
        lines.append(f"INGESTED EVIDENCE ARTIFACTS ({len(context.artifacts)} items):")
        for art in context.artifacts[-5:]:
            lines.append(f"  [ID:{art.id}] {art.filename} ({art.artifact_type.value}, {art.size_bytes}B)")
        lines.append("")

    if context.observations:
        lines.append(f"STRUCTURED OBSERVATIONS ({len(context.observations)} items):")
        for obs in context.observations[-6:]:
            h_link = f" (Hypothesis: {obs.hypothesis_id})" if obs.hypothesis_id else ""
            lines.append(f"  [{obs.category.value}] {obs.statement}{h_link}")
        lines.append("")

    # Findings
    lines.append(f"FINDINGS ({len(context.findings)} items):")
    for f in context.findings:
        lines.append(f"  [{f.severity}] [{f.classification}] ID:{f.id} - {f.title}")
    if not context.findings:
        lines.append("  (No findings recorded)")
    lines.append("")

    # Recent finding validations (Phase 8)
    if context.latest_validations:
        lines.append(f"RECENT FINDING VALIDATIONS ({len(context.latest_validations)} records):")
        for v in context.latest_validations:
            lines.append(f"  [Validation #{v.id}] Hyp:{v.hypothesis_id or 'N/A'} -> {v.classification} [{v.evidence_strength}, Conf:{v.confidence}]")
        lines.append("")

    # Security reports (Phase 9)
    if context.latest_reports:
        lines.append(f"SECURITY REPORTS ({context.reports_count} total):")
        for rep in context.latest_reports:
            lines.append(f"  [Report #{rep.id} v{rep.version}] Finding:{rep.finding_id} -> {rep.status} ({rep.template_type})")
        lines.append("")

    # Recent activities
    lines.append(f"RECENT ACTIVITIES ({len(context.recent_activities)} events):")
    for act in context.recent_activities[-5:]:
        ts = str(act.timestamp or "")[:19]
        lines.append(f"  {ts} [{act.event_type}] {act.description or ''}")
    lines.append("")

    # Knowledge sources
    if context.knowledge_sources:
        lines.append(f"RELEVANT KNOWLEDGE SOURCES ({len(context.knowledge_sources)}):")
        for src in context.knowledge_sources:
            lines.append(f"  {src}")
        lines.append("")

    # Truncation notice
    if context.truncation.truncated:
        lines.append("[!] CONTEXT TRUNCATED to fit budget:")
        lines.append(f"    Truncated categories: {', '.join(context.truncation.truncated_categories)}")
        lines.append("")

    lines.append("=" * 65)
    return "\n".join(lines)


def _scrub_secrets(text: Optional[str]) -> Optional[str]:
    """Sanitize text to prevent accidental leakage of API keys, tokens, or credentials."""
    if not text:
        return text
    # Mask API key patterns
    scrubbed = re.sub(r"AIza[0-9A-Za-z\-_]{35}", "[REDACTED_API_KEY]", text)
    scrubbed = re.sub(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}", "Bearer [REDACTED_TOKEN]", scrubbed)
    scrubbed = re.sub(r"(?i)(password|secret|api_key)\s*[:=]\s*['\"][^'\"]+['\"]", r"\1=[REDACTED]", scrubbed)
    return scrubbed
