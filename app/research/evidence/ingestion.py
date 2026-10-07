"""Evidence Ingestion Service for Phase 7.

Coordinates hashing, duplicate detection, parsing, observation extraction,
and database persistence for researcher-supplied artifacts.
"""

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.config import get_settings, Settings
from app.knowledge.retriever import KnowledgeRetriever
from app.research.evidence.analyzer import EvidenceAnalyzer
from app.research.evidence.parsers import ParserRegistry
from app.research.models import (
    ArtifactType,
    EvidenceArtifact,
    NormalizedEvidence,
    Observation,
)
from app.storage.database import DatabaseManager


class EvidenceIngestionService:
    """Ingests, parses, normalizes, and indexes researcher-supplied evidence artifacts."""

    def __init__(
        self,
        db: DatabaseManager,
        retriever: Optional[KnowledgeRetriever] = None,
        settings: Optional[Settings] = None,
        genai_client: Optional[Any] = None,
    ):
        self.db = db
        self.settings = settings or get_settings()
        self.retriever = retriever
        self.registry = ParserRegistry()
        self.analyzer = EvidenceAnalyzer(
            settings=self.settings,
            genai_client=genai_client,
            retriever=retriever,
        )

    def ingest_file(
        self,
        project_id: int,
        file_path: Path,
        hypothesis_id: Optional[int] = None,
        use_ai: bool = True,
    ) -> Tuple[Dict[str, Any], NormalizedEvidence, Dict[str, Any]]:
        """Ingest an artifact file from disk."""
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Evidence file not found: {file_path}")

        # Read content safely
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                content = path.read_text(encoding="cp1252", errors="replace")
            except Exception:
                content = path.read_text(encoding="latin-1", errors="replace")

        return self.ingest_content(
            project_id=project_id,
            content=content,
            filename=path.name,
            source_path=str(path),
            hypothesis_id=hypothesis_id,
            use_ai=use_ai,
        )

    def ingest_content(
        self,
        project_id: int,
        content: str,
        filename: str = "evidence.txt",
        source_path: Optional[str] = None,
        hypothesis_id: Optional[int] = None,
        use_ai: bool = True,
    ) -> Tuple[Dict[str, Any], NormalizedEvidence, Dict[str, Any]]:
        """Ingest raw evidence text/content into a project."""
        # 1. Validate project
        project = self.db.get_project_by_id(project_id)
        if not project:
            raise ValueError(f"Project ID {project_id} not found.")

        # 2. Compute SHA-256 content hash
        content_bytes = content.encode("utf-8")
        content_hash = hashlib.sha256(content_bytes).hexdigest()
        size_bytes = len(content_bytes)

        # 3. Duplicate detection
        existing = self.db.get_evidence_artifact_by_hash(project_id, content_hash)
        if existing:
            self.db.log_activity(
                project_id,
                "ARTIFACT_DUPLICATE",
                f"Duplicate artifact '{filename}' detected (SHA-256: {content_hash[:10]}...)",
            )
            # Fetch existing observations
            existing_obs_rows = self.db.list_observations(project_id, artifact_id=existing["id"])
            existing_obs = [
                Observation(
                    id=r["id"],
                    artifact_id=r["artifact_id"],
                    project_id=r["project_id"],
                    category=r["category"],
                    statement=r["statement"],
                    source_location=r.get("source_location"),
                    confidence=r.get("confidence", "MEDIUM"),
                    hypothesis_id=r.get("hypothesis_id"),
                    created_at=r.get("created_at"),
                )
                for r in existing_obs_rows
            ]
            normalized = NormalizedEvidence(
                artifact_id=existing["id"],
                artifact_type=existing["artifact_type"],
                title=f"Existing Artifact: {existing['filename']}",
                summary=f"Previously imported artifact (ID: {existing['id']}).",
                observations=existing_obs,
                metadata=existing.get("metadata", {}),
                source_reference=existing.get("source_path") or filename,
            )
            return existing, normalized, {"is_duplicate": True, "artifact_id": existing["id"]}

        # 4. Select parser & parse
        path_obj = Path(source_path) if source_path else Path(filename)
        parser = self.registry.get_parser(path_obj, content)
        normalized = parser.parse(path_obj, content, project_id=project_id)

        # 5. Persist artifact record
        artifact_record = self.db.add_evidence_artifact(
            project_id=project_id,
            filename=filename,
            artifact_type=normalized.artifact_type.value,
            content_hash=content_hash,
            size_bytes=size_bytes,
            source_path=source_path,
            metadata=normalized.metadata,
        )
        artifact_id = artifact_record["id"]
        normalized.artifact_id = artifact_id

        # 6. Persist observations
        persisted_obs: List[Observation] = []
        for obs in normalized.observations:
            obs_row = self.db.add_observation(
                artifact_id=artifact_id,
                project_id=project_id,
                category=obs.category.value,
                statement=obs.statement,
                source_location=obs.source_location,
                confidence=obs.confidence,
                hypothesis_id=hypothesis_id,
            )
            persisted_obs.append(
                Observation(
                    id=obs_row["id"],
                    artifact_id=artifact_id,
                    project_id=project_id,
                    category=obs.category,
                    statement=obs.statement,
                    source_location=obs.source_location,
                    confidence=obs.confidence,
                    hypothesis_id=hypothesis_id,
                    created_at=obs_row.get("created_at"),
                )
            )
        normalized.observations = persisted_obs

        # 7. Mirror to research_evidence table for Phase 5 compatibility
        mapped_ev_type = "OBSERVATION"
        if normalized.artifact_type in (ArtifactType.HTTP, ArtifactType.HAR):
            mapped_ev_type = "HTTP_RESPONSE"
        elif normalized.artifact_type == ArtifactType.LOG:
            mapped_ev_type = "LOG"
        elif normalized.artifact_type == ArtifactType.SOURCE_CODE:
            mapped_ev_type = "SOURCE_CODE"
        elif normalized.artifact_type == ArtifactType.CONFIGURATION:
            mapped_ev_type = "CONFIGURATION"
        elif normalized.artifact_type == ArtifactType.IMAGE:
            mapped_ev_type = "SCREENSHOT"
        elif normalized.artifact_type == ArtifactType.MARKDOWN:
            mapped_ev_type = "DOCUMENT"

        self.db.add_research_evidence(
            project_id=project_id,
            hypothesis_id=hypothesis_id,
            evidence_type=mapped_ev_type,
            title=f"Artifact: {filename}",
            description=normalized.summary,
            content=content[:5000],  # bounded sample
            source=source_path or "Researcher uploaded file",
            researcher_note=f"Parsed by {parser.__class__.__name__}",
            confidence="HIGH",
        )

        # 8. Log activity timeline
        self.db.log_activity(
            project_id,
            "ARTIFACT_IMPORTED",
            f"Imported artifact '{filename}' ({normalized.artifact_type.value}, {len(persisted_obs)} observations)",
        )

        # 9. AI Analysis (if requested)
        analysis_result: Dict[str, Any] = {}
        if use_ai:
            hypotheses = self.db.list_hypotheses(project_id)
            analysis_result = self.analyzer.analyze(normalized, hypotheses)
            self.db.log_activity(
                project_id,
                "ANALYSIS_COMPLETED",
                f"Evidence analysis completed for artifact {artifact_id}",
            )

        return artifact_record, normalized, analysis_result
