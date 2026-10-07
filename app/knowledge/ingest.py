"""Knowledge ingestion pipeline for file discovery, parsing, chunking, and incremental storage."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Callable

from app.storage.database import DatabaseManager
from .parser import DocumentParser, ParsedDocument
from .chunker import DocumentChunker, KnowledgeChunk

# File extensions supported for parsing
SUPPORTED_EXTENSIONS = {
    ".md",
    ".markdown",
    ".mdx",
    ".txt",
    ".rst",
    ".html",
    ".htm",
    ".pdf",
}

# Directories to strictly exclude from scanning
EXCLUDED_DIR_NAMES = {
    ".git",
    ".github",
    ".agents",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".pytest_cache",
    "static",
    "dist",
    "build",
}


class IngestionPipeline:
    """Orchestrates scanning, parsing, chunking, and incremental indexing of knowledge documents."""

    def __init__(
        self,
        knowledge_dir: Path,
        db: DatabaseManager,
        parser: Optional[DocumentParser] = None,
        chunker: Optional[DocumentChunker] = None,
    ):
        self.knowledge_dir = Path(knowledge_dir)
        self.db = db
        self.parser = parser or DocumentParser()
        self.chunker = chunker or DocumentChunker()

    def discover_files(self) -> Dict[str, Any]:
        """Scan directory and partition files into supported, skipped, and discovered."""
        if not self.knowledge_dir.exists():
            return {
                "discovered": 0,
                "supported": [],
                "skipped": [],
            }

        supported_files: List[Path] = []
        skipped_files: List[Path] = []

        for p in self.knowledge_dir.rglob("*"):
            if not p.is_file():
                continue

            # Check if any parent directory is in excluded set
            parts = p.parts
            if any(ex in parts for ex in EXCLUDED_DIR_NAMES):
                skipped_files.append(p)
                continue

            ext = p.suffix.lower()
            if ext in SUPPORTED_EXTENSIONS:
                supported_files.append(p)
            else:
                skipped_files.append(p)

        return {
            "discovered": len(supported_files) + len(skipped_files),
            "supported": supported_files,
            "skipped": skipped_files,
        }

    def _compute_file_hash(self, file_path: Path) -> str:
        """Compute SHA-256 hash of file content."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def run(
        self,
        force: bool = False,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> Dict[str, Any]:
        """Execute the ingestion pipeline with incremental updates."""
        started_at = datetime.now(timezone.utc).isoformat()
        self.db.init_db()

        discovery = self.discover_files()
        supported_files: List[Path] = discovery["supported"]
        total_discovered = discovery["discovered"]
        total_skipped_discovery = len(discovery["skipped"])

        files_processed = 0
        files_skipped_unchanged = 0
        files_failed = 0
        chunks_created = 0
        failed_files: List[Dict[str, Any]] = []

        # Track seen source paths on disk for stale document cleanup
        seen_source_paths: Set[str] = set()

        total_supported = len(supported_files)

        for idx, file_path in enumerate(supported_files):
            try:
                rel_path = file_path.relative_to(self.knowledge_dir).as_posix()
            except ValueError:
                rel_path = file_path.name
            seen_source_paths.add(rel_path)

            if progress_callback:
                progress_callback(rel_path, idx + 1, total_supported)

            # Check content hash for incremental update
            try:
                file_hash = self._compute_file_hash(file_path)
            except Exception as e:
                files_failed += 1
                failed_files.append(
                    {
                        "source": rel_path,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                    }
                )
                continue

            existing_doc = self.db.get_document_by_path(rel_path)
            if existing_doc and not force:
                if (
                    existing_doc.get("content_hash") == file_hash
                    and existing_doc.get("status") == "active"
                ):
                    files_skipped_unchanged += 1
                    continue

            # Parse and chunk document
            try:
                parsed_doc: ParsedDocument = self.parser.parse(
                    file_path, base_dir=self.knowledge_dir
                )
                chunks: List[KnowledgeChunk] = self.chunker.chunk(parsed_doc)

                # Upsert document record in DB
                doc_id = self.db.upsert_document(
                    source_path=rel_path,
                    filename=file_path.name,
                    file_type=parsed_doc.file_type,
                    title=parsed_doc.title,
                    content_hash=file_hash,
                )

                # Remove existing chunks for this document if updating
                self.db.delete_document_chunks(doc_id)

                # Batch insert chunks and FTS index
                chunk_dicts = [c.model_dump() for c in chunks]
                inserted = self.db.insert_chunks_batch(
                    document_id=doc_id,
                    chunks=chunk_dicts,
                    source_path=rel_path,
                    title=parsed_doc.title,
                )

                chunks_created += inserted
                files_processed += 1

            except Exception as e:
                files_failed += 1
                failed_files.append(
                    {
                        "source": rel_path,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                    }
                )

        # Prune documents that have been deleted from the knowledge directory
        self.db.prune_deleted_documents(self.knowledge_dir)

        completed_at = datetime.now(timezone.utc).isoformat()
        status_str = "SUCCESS" if files_failed == 0 else "PARTIAL_SUCCESS"
        error_log = json.dumps(failed_files) if failed_files else ""

        run_id = self.db.record_ingestion_run(
            started_at=started_at,
            completed_at=completed_at,
            files_discovered=total_discovered,
            files_processed=files_processed,
            files_skipped=files_skipped_unchanged + total_skipped_discovery,
            files_failed=files_failed,
            chunks_created=chunks_created,
            status=status_str,
            error_log=error_log,
        )

        return {
            "run_id": run_id,
            "status": status_str,
            "files_discovered": total_discovered,
            "files_processed": files_processed,
            "files_skipped": files_skipped_unchanged + total_skipped_discovery,
            "files_failed": files_failed,
            "chunks_created": chunks_created,
            "failed_files": failed_files,
            "started_at": started_at,
            "completed_at": completed_at,
        }
