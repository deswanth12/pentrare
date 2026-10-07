"""SQLite database manager, schema initialization, and knowledge storage operations."""

import sqlite3
import os
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, List, Optional, Dict, Any


class DatabaseManager:
    """Manages SQLite connections, schema initialization, and transactional queries."""

    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provide a transactional scope around a series of operations."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Internal helper: safe column addition (idempotent)
    # ------------------------------------------------------------------

    def _add_column_if_missing(
        self,
        conn: "sqlite3.Connection",
        table: str,
        column: str,
        col_def: str,
    ) -> None:
        """Add a column to an existing table only if it does not already exist."""
        existing = [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")

    def init_db(self) -> None:
        """Initialize all required SQLite database tables (additive/idempotent).

        Phase 1-4 tables are preserved unchanged.
        Phase 5 tables are added with CREATE TABLE IF NOT EXISTS.
        New columns on existing tables are added with ALTER TABLE IF NOT EXISTS guard.
        """
        phase1_4_schema = """
        -- Research Projects & Workspaces (Phase 1)
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS research_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            item_code TEXT NOT NULL,
            title TEXT NOT NULL,
            security_area TEXT NOT NULL,
            reason TEXT,
            preconditions TEXT,
            expected_behavior TEXT,
            evidence_required TEXT,
            risk TEXT,
            status TEXT NOT NULL DEFAULT 'Not Tested',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            research_item_id INTEGER REFERENCES research_items(id) ON DELETE SET NULL,
            evidence_type TEXT NOT NULL,
            description TEXT,
            raw_content TEXT,
            source_file TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'Unknown',
            classification TEXT NOT NULL DEFAULT 'UNCONFIRMED',
            affected_asset TEXT,
            summary TEXT,
            technical_details TEXT,
            steps_to_reproduce TEXT,
            expected_behavior TEXT,
            observed_behavior TEXT,
            security_impact TEXT,
            root_cause TEXT,
            remediation TEXT,
            validation_notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Phase 2: Knowledge Base Schema
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_path TEXT UNIQUE NOT NULL,
            filename TEXT NOT NULL,
            file_type TEXT NOT NULL,
            title TEXT,
            content_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS chunks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
            chunk_id TEXT UNIQUE NOT NULL,
            section TEXT,
            page INTEGER,
            content TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            tags TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS ingestion_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            files_discovered INTEGER DEFAULT 0,
            files_processed INTEGER DEFAULT 0,
            files_skipped INTEGER DEFAULT 0,
            files_failed INTEGER DEFAULT 0,
            chunks_created INTEGER DEFAULT 0,
            status TEXT DEFAULT 'running',
            error_log TEXT
        );

        -- Legacy / compat table for knowledge chunks
        CREATE TABLE IF NOT EXISTS knowledge_chunks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chunk_id TEXT UNIQUE NOT NULL,
            source_file TEXT NOT NULL,
            source_path TEXT NOT NULL,
            source_type TEXT NOT NULL,
            title TEXT,
            section TEXT,
            content TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            tags TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Phase 5: Structured Research Project Intelligence
        -- Scope model: IN_SCOPE / OUT_OF_SCOPE / UNKNOWN per project
        CREATE TABLE IF NOT EXISTS project_scope (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            in_scope_assets TEXT NOT NULL DEFAULT '[]',
            out_of_scope_assets TEXT NOT NULL DEFAULT '[]',
            allowed_testing_notes TEXT,
            prohibited_actions TEXT,
            authorization_notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Asset inventory (researcher-supplied, NOT auto-enumerated)
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            asset_type TEXT NOT NULL DEFAULT 'other',
            identifier TEXT,
            scope_status TEXT NOT NULL DEFAULT 'UNKNOWN',
            technology TEXT,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Research objectives
        CREATE TABLE IF NOT EXISTS objectives (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            description TEXT,
            priority TEXT NOT NULL DEFAULT 'MEDIUM',
            status TEXT NOT NULL DEFAULT 'OPEN',
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Hypotheses (NOT findings — require evidence & validation to become findings)
        CREATE TABLE IF NOT EXISTS hypotheses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            objective_id INTEGER REFERENCES objectives(id) ON DELETE SET NULL,
            title TEXT NOT NULL,
            description TEXT,
            rationale TEXT,
            status TEXT NOT NULL DEFAULT 'UNTESTED',
            confidence TEXT NOT NULL DEFAULT 'LOW',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Researcher-supplied evidence (NEVER AI-fabricated)
        CREATE TABLE IF NOT EXISTS research_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            hypothesis_id INTEGER REFERENCES hypotheses(id) ON DELETE SET NULL,
            evidence_type TEXT NOT NULL DEFAULT 'OBSERVATION',
            title TEXT NOT NULL,
            description TEXT,
            content TEXT,
            source TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            researcher_note TEXT,
            confidence TEXT NOT NULL DEFAULT 'LOW',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Project activity timeline
        CREATE TABLE IF NOT EXISTS project_activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            event_type TEXT NOT NULL,
            description TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Phase 7: Evidence Intelligence & Artifact Analysis
        CREATE TABLE IF NOT EXISTS evidence_artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            filename TEXT NOT NULL,
            artifact_type TEXT NOT NULL DEFAULT 'UNKNOWN',
            source_path TEXT,
            content_hash TEXT NOT NULL,
            size_bytes INTEGER NOT NULL DEFAULT 0,
            metadata TEXT NOT NULL DEFAULT '{}',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS evidence_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            artifact_id INTEGER NOT NULL REFERENCES evidence_artifacts(id) ON DELETE CASCADE,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            category TEXT NOT NULL DEFAULT 'OTHER',
            statement TEXT NOT NULL,
            source_location TEXT,
            confidence TEXT NOT NULL DEFAULT 'MEDIUM',
            hypothesis_id INTEGER REFERENCES hypotheses(id) ON DELETE SET NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Performance Indexes (Phase 1-4)
        CREATE INDEX IF NOT EXISTS idx_research_items_project ON research_items(project_id);
        CREATE INDEX IF NOT EXISTS idx_evidence_project ON evidence(project_id);
        CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
        CREATE INDEX IF NOT EXISTS idx_documents_path ON documents(source_path);
        CREATE INDEX IF NOT EXISTS idx_documents_hash ON documents(content_hash);
        CREATE INDEX IF NOT EXISTS idx_chunks_document ON chunks(document_id);
        CREATE INDEX IF NOT EXISTS idx_chunks_chunk_id ON chunks(chunk_id);
        CREATE INDEX IF NOT EXISTS idx_chunks_hash ON chunks(content_hash);
        CREATE INDEX IF NOT EXISTS idx_knowledge_hash ON knowledge_chunks(content_hash);

        -- Performance Indexes (Phase 5)
        CREATE INDEX IF NOT EXISTS idx_scope_project ON project_scope(project_id);
        CREATE INDEX IF NOT EXISTS idx_assets_project ON assets(project_id);
        CREATE INDEX IF NOT EXISTS idx_objectives_project ON objectives(project_id);
        CREATE INDEX IF NOT EXISTS idx_hypotheses_project ON hypotheses(project_id);
        CREATE INDEX IF NOT EXISTS idx_hypotheses_objective ON hypotheses(objective_id);
        CREATE INDEX IF NOT EXISTS idx_res_evidence_project ON research_evidence(project_id);
        CREATE INDEX IF NOT EXISTS idx_res_evidence_hypothesis ON research_evidence(hypothesis_id);
        CREATE INDEX IF NOT EXISTS idx_activities_project ON project_activities(project_id);
        CREATE INDEX IF NOT EXISTS idx_activities_timestamp ON project_activities(timestamp);

        -- Performance Indexes (Phase 7)
        CREATE INDEX IF NOT EXISTS idx_artifacts_project ON evidence_artifacts(project_id);
        CREATE INDEX IF NOT EXISTS idx_artifacts_hash ON evidence_artifacts(content_hash);
        CREATE INDEX IF NOT EXISTS idx_observations_artifact ON evidence_observations(artifact_id);
        CREATE INDEX IF NOT EXISTS idx_observations_project ON evidence_observations(project_id);
        CREATE INDEX IF NOT EXISTS idx_observations_hypothesis ON evidence_observations(hypothesis_id);

        -- Phase 8: Finding Validation History
        CREATE TABLE IF NOT EXISTS finding_validations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
            hypothesis_id INTEGER REFERENCES hypotheses(id) ON DELETE SET NULL,
            classification TEXT NOT NULL DEFAULT 'UNCONFIRMED',
            evidence_strength TEXT NOT NULL DEFAULT 'NONE',
            confidence TEXT NOT NULL DEFAULT 'LOW',
            reasoning TEXT,
            supporting_observation_ids TEXT NOT NULL DEFAULT '[]',
            contradictory_observation_ids TEXT NOT NULL DEFAULT '[]',
            alternative_explanations TEXT NOT NULL DEFAULT '[]',
            missing_evidence TEXT NOT NULL DEFAULT '[]',
            observed_impact TEXT,
            potential_impact TEXT,
            unsupported_impact TEXT,
            validation_questions TEXT NOT NULL DEFAULT '[]',
            knowledge_sources TEXT NOT NULL DEFAULT '[]',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Performance Indexes (Phase 8)
        CREATE INDEX IF NOT EXISTS idx_validations_project ON finding_validations(project_id);
        CREATE INDEX IF NOT EXISTS idx_validations_finding ON finding_validations(finding_id);
        CREATE INDEX IF NOT EXISTS idx_validations_hypothesis ON finding_validations(hypothesis_id);

        -- Phase 9: Security Report Generation Engine
        CREATE TABLE IF NOT EXISTS security_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            validation_id INTEGER REFERENCES finding_validations(id) ON DELETE SET NULL,
            version INTEGER NOT NULL DEFAULT 1,
            title TEXT NOT NULL,
            template_type TEXT NOT NULL DEFAULT 'BUG_BOUNTY',
            status TEXT NOT NULL DEFAULT 'DRAFT',
            format TEXT NOT NULL DEFAULT 'MARKDOWN',
            content TEXT NOT NULL,
            report_metadata TEXT NOT NULL DEFAULT '{}',
            content_hash TEXT NOT NULL,
            approved_by TEXT,
            approved_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Performance Indexes (Phase 9)
        CREATE INDEX IF NOT EXISTS idx_reports_project ON security_reports(project_id);
        CREATE INDEX IF NOT EXISTS idx_reports_finding ON security_reports(finding_id);
        CREATE INDEX IF NOT EXISTS idx_reports_status ON security_reports(status);
        """
        with self.get_connection() as conn:
            conn.executescript(phase1_4_schema)
            # Create FTS5 virtual table for full-text search
            conn.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
                    chunk_id UNINDEXED,
                    document_id UNINDEXED,
                    section,
                    content,
                    source_path,
                    title,
                    tokenize='unicode61'
                );
                """
            )
            # Phase 5: safe column additions to pre-existing tables
            self._add_column_if_missing(conn, "projects", "research_goal", "TEXT")
            self._add_column_if_missing(conn, "projects", "scope_summary", "TEXT")
            self._add_column_if_missing(conn, "findings", "impact", "TEXT")
            self._add_column_if_missing(conn, "findings", "evidence_ids", "TEXT DEFAULT '[]'")
            self._add_column_if_missing(conn, "findings", "validation_status", "TEXT DEFAULT 'UNCONFIRMED'")
            self._add_column_if_missing(conn, "findings", "confidence", "TEXT DEFAULT 'LOW'")
            # Phase 8: impact separation on findings table
            self._add_column_if_missing(conn, "findings", "observed_impact", "TEXT")
            self._add_column_if_missing(conn, "findings", "potential_impact", "TEXT")


    # -------------------------------------------------------------
    # Project Operations
    # -------------------------------------------------------------

    def create_project(self, name: str, description: str = "") -> Dict[str, Any]:
        """Create a new project record."""
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Project name cannot be empty")

        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO projects (name, description, status, created_at, updated_at)
                VALUES (?, ?, 'active', ?, ?)
                """,
                (clean_name, description.strip(), now, now),
            )
            project_id = cursor.lastrowid

            row = conn.execute(
                "SELECT * FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            return dict(row)

    def get_project(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieve a project by name."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM projects WHERE name = ?", (name.strip(),)
            ).fetchone()
            return dict(row) if row else None

    def list_projects(self) -> List[Dict[str, Any]]:
        """List all research projects."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM projects ORDER BY created_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def get_project_count(self) -> int:
        """Count total active projects."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM projects").fetchone()
            return row["count"] if row else 0

    def get_findings_count(self, project_id: Optional[int] = None) -> int:
        """Count total findings across all or a single project."""
        with self.get_connection() as conn:
            if project_id is not None:
                row = conn.execute(
                    "SELECT COUNT(*) AS count FROM findings WHERE project_id = ?",
                    (project_id,),
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) AS count FROM findings").fetchone()
            return row["count"] if row else 0

    # -------------------------------------------------------------
    # Knowledge Base: Documents & Chunks Operations
    # -------------------------------------------------------------

    def get_document_by_path(self, source_path: str) -> Optional[Dict[str, Any]]:
        """Fetch document record by source path."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM documents WHERE source_path = ?", (source_path,)
            ).fetchone()
            return dict(row) if row else None

    def upsert_document(
        self,
        source_path: str,
        filename: str,
        file_type: str,
        title: str,
        content_hash: str,
    ) -> int:
        """Insert or update a document record, returning its ID."""
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT id FROM documents WHERE source_path = ?", (source_path,)
            ).fetchone()
            if row:
                doc_id = row["id"]
                conn.execute(
                    """
                    UPDATE documents
                    SET filename = ?, file_type = ?, title = ?, content_hash = ?, status = 'active', updated_at = ?
                    WHERE id = ?
                    """,
                    (filename, file_type, title, content_hash, now, doc_id),
                )
                return doc_id
            else:
                cursor = conn.execute(
                    """
                    INSERT INTO documents (source_path, filename, file_type, title, content_hash, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
                    """,
                    (source_path, filename, file_type, title, content_hash, now, now),
                )
                return cursor.lastrowid

    def mark_document_inactive(self, source_path: str) -> None:
        """Mark a document inactive and clean up its search index."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT id FROM documents WHERE source_path = ?", (source_path,)
            ).fetchone()
            if row:
                doc_id = row["id"]
                conn.execute("UPDATE documents SET status = 'inactive' WHERE id = ?", (doc_id,))
                conn.execute("DELETE FROM chunks WHERE document_id = ?", (doc_id,))
                conn.execute("DELETE FROM chunks_fts WHERE document_id = ?", (doc_id,))

    def prune_deleted_documents(self, knowledge_dir: Path) -> int:
        """Mark active documents as inactive if their corresponding file no longer exists in knowledge_dir."""
        pruned_count = 0
        knowledge_dir = Path(knowledge_dir)
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT id, source_path FROM documents WHERE status = 'active'"
            ).fetchall()
            for r in rows:
                doc_path = knowledge_dir / r["source_path"]
                if not doc_path.exists():
                    doc_id = r["id"]
                    conn.execute("UPDATE documents SET status = 'inactive' WHERE id = ?", (doc_id,))
                    conn.execute("DELETE FROM chunks WHERE document_id = ?", (doc_id,))
                    conn.execute("DELETE FROM chunks_fts WHERE document_id = ?", (doc_id,))
                    pruned_count += 1
        return pruned_count

    def delete_document_chunks(self, document_id: int) -> None:
        """Remove existing chunks for a document prior to re-indexing."""
        with self.get_connection() as conn:
            conn.execute("DELETE FROM chunks WHERE document_id = ?", (document_id,))
            conn.execute("DELETE FROM chunks_fts WHERE document_id = ?", (document_id,))

    def insert_chunks_batch(
        self,
        document_id: int,
        chunks: List[Dict[str, Any]],
        source_path: str,
        title: str,
    ) -> int:
        """Batch insert chunks into storage and FTS index."""
        if not chunks:
            return 0

        inserted_count = 0
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            for chunk in chunks:
                try:
                    conn.execute(
                        """
                        INSERT INTO chunks (document_id, chunk_id, section, page, content, content_hash, tags, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            document_id,
                            chunk["chunk_id"],
                            chunk.get("section", ""),
                            chunk.get("page"),
                            chunk["content"],
                            chunk["content_hash"],
                            chunk.get("tags", ""),
                            now,
                        ),
                    )
                    conn.execute(
                        """
                        INSERT INTO chunks_fts (chunk_id, document_id, section, content, source_path, title)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            chunk["chunk_id"],
                            document_id,
                            chunk.get("section", ""),
                            chunk["content"],
                            source_path,
                            title,
                        ),
                    )
                    inserted_count += 1
                except sqlite3.IntegrityError:
                    # Duplicate chunk ID, skip
                    continue
        return inserted_count

    def record_ingestion_run(
        self,
        started_at: str,
        completed_at: str,
        files_discovered: int,
        files_processed: int,
        files_skipped: int,
        files_failed: int,
        chunks_created: int,
        status: str = "success",
        error_log: str = "",
    ) -> int:
        """Record statistics from an ingestion execution."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO ingestion_runs (
                    started_at, completed_at, files_discovered, files_processed,
                    files_skipped, files_failed, chunks_created, status, error_log
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    started_at,
                    completed_at,
                    files_discovered,
                    files_processed,
                    files_skipped,
                    files_failed,
                    chunks_created,
                    status,
                    error_log,
                ),
            )
            return cursor.lastrowid

    def get_last_ingestion_run(self) -> Optional[Dict[str, Any]]:
        """Retrieve most recent ingestion run record."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM ingestion_runs ORDER BY id DESC LIMIT 1"
            ).fetchone()
            return dict(row) if row else None

    def get_knowledge_stats(self) -> Dict[str, Any]:
        """Aggregate metrics on documents, chunks, and index health."""
        with self.get_connection() as conn:
            doc_row = conn.execute(
                "SELECT COUNT(*) AS count FROM documents WHERE status = 'active'"
            ).fetchone()
            doc_count = doc_row["count"] if doc_row else 0

            chunk_row = conn.execute("SELECT COUNT(*) AS count FROM chunks").fetchone()
            chunk_count = chunk_row["count"] if chunk_row else 0

            last_run = self.get_last_ingestion_run()

            db_size_bytes = 0
            if self.db_path.exists():
                db_size_bytes = self.db_path.stat().st_size

            return {
                "active_documents": doc_count,
                "total_chunks": chunk_count,
                "last_run": last_run,
                "db_size_bytes": db_size_bytes,
                "db_size_mb": round(db_size_bytes / (1024 * 1024), 2),
            }

    def search_chunks_fts(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Execute full-text BM25 search against the chunks index."""
        clean_terms = [t.strip().replace('"', '""') for t in query.split() if t.strip()]
        if not clean_terms:
            return []

        # Build FTS5 query: match all terms or terms with high relevance
        # Format: "term1" "term2" ... with fallback to OR if exact match yields few results
        exact_query = " ".join(f'"{term}"' for term in clean_terms)
        or_query = " OR ".join(f'"{term}"' for term in clean_terms)

        sql = """
        SELECT
            c.chunk_id,
            d.filename AS source_file,
            d.source_path,
            d.title,
            c.section,
            c.page,
            c.content,
            bm25(chunks_fts, 2.0, 5.0, 1.0, 1.0) AS raw_score
        FROM chunks_fts fts
        JOIN chunks c ON c.chunk_id = fts.chunk_id
        JOIN documents d ON d.id = c.document_id
        WHERE chunks_fts MATCH ? AND d.status = 'active'
        ORDER BY raw_score ASC
        LIMIT ?
        """

        with self.get_connection() as conn:
            try:
                rows = conn.execute(sql, (exact_query, limit)).fetchall()
                if not rows and len(clean_terms) > 1:
                    rows = conn.execute(sql, (or_query, limit)).fetchall()
            except sqlite3.OperationalError:
                # Fallback to sanitized simple string if syntax error in MATCH
                rows = conn.execute(sql, (or_query, limit)).fetchall()

            results = []
            for r in rows:
                item = dict(r)
                # In SQLite FTS5 bm25(), lower is more relevant (typically negative).
                # Convert to positive normalized score for friendly display.
                raw = item.get("raw_score", 0.0)
                item["score"] = round(abs(float(raw)), 4)
                results.append(item)
            return results

    def get_all_active_chunks(
        self,
        batch_size: Optional[int] = None,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Retrieve active knowledge chunks ordered by ID."""
        sql = """
        SELECT
            c.chunk_id,
            c.document_id,
            c.section,
            c.page,
            c.content,
            c.content_hash,
            d.filename AS source_file,
            d.source_path,
            d.title
        FROM chunks c
        JOIN documents d ON d.id = c.document_id
        WHERE d.status = 'active'
        ORDER BY c.id ASC
        """
        params: List[Any] = []
        if batch_size is not None:
            sql += " LIMIT ? OFFSET ?"
            params.extend([batch_size, offset])

        with self.get_connection() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    def get_active_chunk_count(self) -> int:
        """Count total chunks belonging to active documents."""
        sql = """
        SELECT COUNT(*) AS count
        FROM chunks c
        JOIN documents d ON d.id = c.document_id
        WHERE d.status = 'active'
        """
        with self.get_connection() as conn:
            row = conn.execute(sql).fetchone()
            return row["count"] if row else 0

    def get_chunks_by_ids(self, chunk_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """Fetch metadata and content for a list of chunk IDs."""
        if not chunk_ids:
            return {}

        results: Dict[str, Dict[str, Any]] = {}
        # Batch in chunks of 400 to avoid SQLite variable limit
        batch_size = 400
        for i in range(0, len(chunk_ids), batch_size):
            batch = chunk_ids[i : i + batch_size]
            placeholders = ",".join("?" for _ in batch)
            sql = f"""
            SELECT
                c.chunk_id,
                c.document_id,
                c.section,
                c.page,
                c.content,
                c.content_hash,
                d.filename AS source_file,
                d.source_path,
                d.title
            FROM chunks c
            JOIN documents d ON d.id = c.document_id
            WHERE c.chunk_id IN ({placeholders}) AND d.status = 'active'
            """
            with self.get_connection() as conn:
                rows = conn.execute(sql, batch).fetchall()
                for r in rows:
                    item = dict(r)
                    results[item["chunk_id"]] = item

        return results


# ==========================================================================
# Phase 5: Enhanced Project Operations
# ==========================================================================


    # ==========================================================================
    # Phase 5: Enhanced Project Operations
    # ==========================================================================

    def get_project_by_id(self, project_id: int):
        """Retrieve a project by numeric ID."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            return dict(row) if row else None

    def update_project(self, project_id: int, **kwargs):
        """Update whitelisted project fields."""
        from datetime import datetime, timezone as _tz
        allowed = {"description", "research_goal", "scope_summary", "status"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return self.get_project_by_id(project_id)
        updates["updated_at"] = datetime.now(_tz.utc).isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [project_id]
        with self.get_connection() as conn:
            conn.execute(f"UPDATE projects SET {set_clause} WHERE id = ?", values)
            row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
            return dict(row) if row else None

    # --- Scope ---

    def set_project_scope(self, project_id, in_scope_assets=None,
                          out_of_scope_assets=None, allowed_testing_notes=None,
                          prohibited_actions=None, authorization_notes=None):
        """Upsert project scope record. Authorization must be explicitly stated."""
        import json as _j
        from datetime import datetime, timezone as _tz
        now = datetime.now(_tz.utc).isoformat()
        ins = _j.dumps(in_scope_assets or [])
        outs = _j.dumps(out_of_scope_assets or [])
        with self.get_connection() as conn:
            ex = conn.execute(
                "SELECT id FROM project_scope WHERE project_id = ?", (project_id,)
            ).fetchone()
            if ex:
                conn.execute(
                    "UPDATE project_scope SET in_scope_assets=?,out_of_scope_assets=?,"
                    "allowed_testing_notes=?,prohibited_actions=?,authorization_notes=?,"
                    "updated_at=? WHERE project_id=?",
                    (ins, outs, allowed_testing_notes, prohibited_actions,
                     authorization_notes, now, project_id),
                )
                sid = ex["id"]
            else:
                c = conn.execute(
                    "INSERT INTO project_scope (project_id,in_scope_assets,"
                    "out_of_scope_assets,allowed_testing_notes,prohibited_actions,"
                    "authorization_notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                    (project_id, ins, outs, allowed_testing_notes,
                     prohibited_actions, authorization_notes, now, now),
                )
                sid = c.lastrowid
            row = conn.execute("SELECT * FROM project_scope WHERE id=?", (sid,)).fetchone()
            return dict(row)

    def get_project_scope(self, project_id):
        """Retrieve scope record for a project."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM project_scope WHERE project_id=?", (project_id,)
            ).fetchone()
            return dict(row) if row else None

    # --- Assets ---

    def add_asset(self, project_id, name, asset_type="other", identifier=None,
                  scope_status="UNKNOWN", technology=None, notes=None):
        """Add a researcher-supplied asset. scope_status defaults to UNKNOWN.

        Assets are NEVER auto-enumerated. A URL alone is not authorization.
        """
        from datetime import datetime, timezone as _tz
        now = datetime.now(_tz.utc).isoformat()
        with self.get_connection() as conn:
            c = conn.execute(
                "INSERT INTO assets (project_id,name,asset_type,identifier,scope_status,"
                "technology,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (project_id, name.strip(), asset_type, identifier,
                 scope_status, technology, notes, now, now),
            )
            row = conn.execute("SELECT * FROM assets WHERE id=?", (c.lastrowid,)).fetchone()
            return dict(row)

    def list_assets(self, project_id):
        """List all assets for a project."""
        with self.get_connection() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM assets WHERE project_id=? ORDER BY created_at ASC",
                (project_id,),
            ).fetchall()]

    def get_asset(self, asset_id):
        """Retrieve a single asset by ID."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
            return dict(row) if row else None

    # --- Objectives ---

    def add_objective(self, project_id, title, description=None,
                      priority="MEDIUM", notes=None):
        """Add a research objective. Status starts as OPEN."""
        from datetime import datetime, timezone as _tz
        now = datetime.now(_tz.utc).isoformat()
        with self.get_connection() as conn:
            c = conn.execute(
                "INSERT INTO objectives (project_id,title,description,priority,status,"
                "notes,created_at,updated_at) VALUES(?,?,?,?,'OPEN',?,?,?)",
                (project_id, title.strip(), description, priority, notes, now, now),
            )
            row = conn.execute("SELECT * FROM objectives WHERE id=?", (c.lastrowid,)).fetchone()
            return dict(row)

    def list_objectives(self, project_id):
        """List all objectives for a project."""
        with self.get_connection() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM objectives WHERE project_id=? ORDER BY created_at ASC",
                (project_id,),
            ).fetchall()]

    def get_objective(self, objective_id):
        """Retrieve a single objective."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM objectives WHERE id=?", (objective_id,)
            ).fetchone()
            return dict(row) if row else None

    def update_objective_status(self, objective_id, status):
        """Update objective lifecycle status."""
        from datetime import datetime, timezone as _tz
        now = datetime.now(_tz.utc).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE objectives SET status=?,updated_at=? WHERE id=?",
                (status, now, objective_id),
            )
            row = conn.execute(
                "SELECT * FROM objectives WHERE id=?", (objective_id,)
            ).fetchone()
            return dict(row) if row else None

    # --- Hypotheses ---

    def add_hypothesis(self, project_id, title, description=None, rationale=None,
                       objective_id=None, confidence="LOW"):
        """Add a hypothesis. Status MUST start as UNTESTED.

        A hypothesis is NOT a finding. It requires evidence + validation
        before it can be considered a security finding.
        """
        from datetime import datetime, timezone as _tz
        now = datetime.now(_tz.utc).isoformat()
        with self.get_connection() as conn:
            c = conn.execute(
                "INSERT INTO hypotheses (project_id,objective_id,title,description,"
                "rationale,status,confidence,created_at,updated_at) "
                "VALUES(?,?,?,?,?,'UNTESTED',?,?,?)",
                (project_id, objective_id, title.strip(), description,
                 rationale, confidence, now, now),
            )
            row = conn.execute("SELECT * FROM hypotheses WHERE id=?", (c.lastrowid,)).fetchone()
            return dict(row)

    def list_hypotheses(self, project_id):
        """List all hypotheses for a project."""
        with self.get_connection() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM hypotheses WHERE project_id=? ORDER BY created_at ASC",
                (project_id,),
            ).fetchall()]

    def get_hypothesis(self, hypothesis_id):
        """Retrieve a single hypothesis."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM hypotheses WHERE id=?", (hypothesis_id,)
            ).fetchone()
            return dict(row) if row else None

    def update_hypothesis_status(self, hypothesis_id, status, confidence):
        """Update hypothesis status and confidence after researcher testing."""
        from datetime import datetime, timezone as _tz
        now = datetime.now(_tz.utc).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE hypotheses SET status=?,confidence=?,updated_at=? WHERE id=?",
                (status, confidence, now, hypothesis_id),
            )
            row = conn.execute(
                "SELECT * FROM hypotheses WHERE id=?", (hypothesis_id,)
            ).fetchone()
            return dict(row) if row else None

    # --- Research Evidence ---

    def add_research_evidence(self, project_id, title, evidence_type="OBSERVATION",
                              description=None, content=None, source=None,
                              hypothesis_id=None, researcher_note=None, confidence="LOW"):
        """Store researcher-supplied evidence.

        NEVER store AI-generated content here. The 'content' field holds
        only what the researcher explicitly provides. Missing evidence
        remains missing and is never fabricated.
        """
        from datetime import datetime, timezone as _tz
        now = datetime.now(_tz.utc).isoformat()
        with self.get_connection() as conn:
            c = conn.execute(
                "INSERT INTO research_evidence (project_id,hypothesis_id,evidence_type,"
                "title,description,content,source,researcher_note,confidence,"
                "timestamp,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (project_id, hypothesis_id, evidence_type, title.strip(),
                 description, content, source, researcher_note, confidence, now, now),
            )
            row = conn.execute(
                "SELECT * FROM research_evidence WHERE id=?", (c.lastrowid,)
            ).fetchone()
            return dict(row)

    def list_research_evidence(self, project_id):
        """List all evidence for a project."""
        with self.get_connection() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM research_evidence WHERE project_id=? ORDER BY created_at ASC",
                (project_id,),
            ).fetchall()]

    def get_research_evidence(self, evidence_id):
        """Retrieve a single evidence item."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM research_evidence WHERE id=?", (evidence_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_research_evidence_by_ids(self, evidence_ids):
        """Fetch multiple evidence items by ID list."""
        if not evidence_ids:
            return []
        ph = ",".join("?" for _ in evidence_ids)
        with self.get_connection() as conn:
            return [dict(r) for r in conn.execute(
                f"SELECT * FROM research_evidence WHERE id IN ({ph})", evidence_ids
            ).fetchall()]

    # --- Enhanced Findings ---

    def create_finding(self, project_id, title, severity="Unknown",
                       classification="UNCONFIRMED", affected_asset=None, summary=None,
                       technical_details=None, impact=None, root_cause=None,
                       remediation=None, evidence_ids=None,
                       validation_status="UNCONFIRMED", confidence="LOW",
                       **kwargs):
        """Create a structured finding.

        classification defaults to UNCONFIRMED. It must be explicitly upgraded
        by the researcher with supporting evidence.
        """
        import json as _j
        from datetime import datetime, timezone as _tz
        now = datetime.now(_tz.utc).isoformat()
        ev = _j.dumps(evidence_ids or [])
        with self.get_connection() as conn:
            c = conn.execute(
                "INSERT INTO findings (project_id,title,severity,classification,"
                "affected_asset,summary,technical_details,impact,root_cause,"
                "remediation,evidence_ids,validation_status,confidence,"
                "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (project_id, title.strip(), severity, classification, affected_asset,
                 summary, technical_details, impact, root_cause, remediation,
                 ev, validation_status, confidence, now, now),
            )
            fid = c.lastrowid
        if kwargs:
            self.update_finding(fid, **kwargs)
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
            return dict(row)

    def list_findings(self, project_id):
        """List all findings for a project."""
        with self.get_connection() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM findings WHERE project_id=? ORDER BY created_at ASC",
                (project_id,),
            ).fetchall()]

    def get_finding(self, finding_id):
        """Retrieve a single finding."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
            return dict(row) if row else None

    def update_finding(self, finding_id, **kwargs):
        """Update whitelisted finding fields."""
        import json as _j
        from datetime import datetime, timezone as _tz
        allowed = {
            "title", "severity", "classification", "affected_asset", "summary",
            "technical_details", "impact", "root_cause", "remediation",
            "validation_status", "confidence", "evidence_ids",
            "steps_to_reproduce", "expected_behavior", "observed_behavior",
            "security_impact", "validation_notes",
            "observed_impact", "potential_impact",
        }
        updates = {}
        for k, v in kwargs.items():
            if k not in allowed:
                continue
            updates[k] = _j.dumps(v) if k == "evidence_ids" and isinstance(v, list) else v
        if not updates:
            return self.get_finding(finding_id)
        updates["updated_at"] = datetime.now(_tz.utc).isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [finding_id]
        with self.get_connection() as conn:
            conn.execute(f"UPDATE findings SET {set_clause} WHERE id=?", values)
            row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
            return dict(row) if row else None

    # --- Activity Log ---

    def log_activity(self, project_id, event_type, description=None):
        """Append an event to the project activity timeline."""
        from datetime import datetime, timezone as _tz
        now = datetime.now(_tz.utc).isoformat()
        with self.get_connection() as conn:
            c = conn.execute(
                "INSERT INTO project_activities (project_id,event_type,description,timestamp)"
                " VALUES(?,?,?,?)",
                (project_id, event_type, description, now),
            )
            row = conn.execute(
                "SELECT * FROM project_activities WHERE id=?", (c.lastrowid,)
            ).fetchone()
            return dict(row)

    def list_activities(self, project_id):
        """List activity timeline in chronological order."""
        with self.get_connection() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM project_activities WHERE project_id=? ORDER BY timestamp ASC",
                (project_id,),
            ).fetchall()]

    def get_project_summary_counts(self, project_id):
        """Return entity counts for project show display."""
        with self.get_connection() as conn:
            def _c(table):
                row = conn.execute(
                    f"SELECT COUNT(*) AS c FROM {table} WHERE project_id=?", (project_id,)
                ).fetchone()
                return row["c"] if row else 0
            return {
                "assets": _c("assets"),
                "objectives": _c("objectives"),
                "hypotheses": _c("hypotheses"),
                "evidence": _c("research_evidence"),
                "findings": _c("findings"),
                "activities": _c("project_activities"),
                "artifacts": _c("evidence_artifacts"),
                "observations": _c("evidence_observations"),
                "validations": _c("finding_validations"),
                "reports": _c("security_reports"),
            }

    # --- Phase 7: Evidence Artifacts & Observations ---

    def add_evidence_artifact(
        self,
        project_id: int,
        filename: str,
        artifact_type: str = "UNKNOWN",
        content_hash: str = "",
        size_bytes: int = 0,
        source_path: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record an ingested evidence artifact with content hash for duplicate detection."""
        meta_json = json.dumps(metadata or {})
        with self.get_connection() as conn:
            c = conn.execute(
                """
                INSERT INTO evidence_artifacts (
                    project_id, filename, artifact_type, source_path,
                    content_hash, size_bytes, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (project_id, filename, artifact_type, source_path, content_hash, size_bytes, meta_json),
            )
            row = conn.execute("SELECT * FROM evidence_artifacts WHERE id = ?", (c.lastrowid,)).fetchone()
            return dict(row)

    def get_evidence_artifact_by_hash(self, project_id: int, content_hash: str) -> Optional[Dict[str, Any]]:
        """Look up existing artifact in project by content hash (duplicate detection)."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM evidence_artifacts WHERE project_id = ? AND content_hash = ?",
                (project_id, content_hash),
            ).fetchone()
            return dict(row) if row else None

    def get_evidence_artifact(self, artifact_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve evidence artifact by primary key."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM evidence_artifacts WHERE id = ?", (artifact_id,)).fetchone()
            return dict(row) if row else None

    def list_evidence_artifacts(self, project_id: int) -> List[Dict[str, Any]]:
        """List all evidence artifacts for a project."""
        with self.get_connection() as conn:
            return [
                dict(r) for r in conn.execute(
                    "SELECT * FROM evidence_artifacts WHERE project_id = ? ORDER BY id ASC",
                    (project_id,),
                ).fetchall()
            ]

    def add_observation(
        self,
        artifact_id: int,
        project_id: int,
        category: str,
        statement: str,
        source_location: Optional[str] = None,
        confidence: str = "MEDIUM",
        hypothesis_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Record a structured observation extracted from an evidence artifact."""
        with self.get_connection() as conn:
            c = conn.execute(
                """
                INSERT INTO evidence_observations (
                    artifact_id, project_id, category, statement,
                    source_location, confidence, hypothesis_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (artifact_id, project_id, category, statement, source_location, confidence, hypothesis_id),
            )
            row = conn.execute("SELECT * FROM evidence_observations WHERE id = ?", (c.lastrowid,)).fetchone()
            return dict(row)

    def list_observations(
        self,
        project_id: int,
        artifact_id: Optional[int] = None,
        hypothesis_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """List observations filtered by project, artifact, or hypothesis."""
        query = "SELECT * FROM evidence_observations WHERE project_id = ?"
        params: List[Any] = [project_id]
        if artifact_id is not None:
            query += " AND artifact_id = ?"
            params.append(artifact_id)
        if hypothesis_id is not None:
            query += " AND hypothesis_id = ?"
            params.append(hypothesis_id)
        query += " ORDER BY id ASC"
        with self.get_connection() as conn:
            return [dict(r) for r in conn.execute(query, params).fetchall()]

    def get_observation(self, observation_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve observation by ID."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM evidence_observations WHERE id = ?", (observation_id,)).fetchone()
            return dict(row) if row else None

    def link_observation_to_hypothesis(self, observation_id: int, hypothesis_id: int) -> Optional[Dict[str, Any]]:
        """Link an individual observation to a hypothesis."""
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE evidence_observations SET hypothesis_id = ? WHERE id = ?",
                (hypothesis_id, observation_id),
            )
            row = conn.execute("SELECT * FROM evidence_observations WHERE id = ?", (observation_id,)).fetchone()
            return dict(row) if row else None

    def link_artifact_to_hypothesis(self, artifact_id: int, hypothesis_id: int) -> int:
        """Link all observations belonging to an artifact to a hypothesis."""
        with self.get_connection() as conn:
            c = conn.execute(
                "UPDATE evidence_observations SET hypothesis_id = ? WHERE artifact_id = ?",
                (hypothesis_id, artifact_id),
            )
            return c.rowcount

    # -------------------------------------------------------------
    # Phase 8: Finding Validation Operations
    # -------------------------------------------------------------

    def record_validation(
        self,
        project_id: int,
        hypothesis_id: Optional[int] = None,
        finding_id: Optional[int] = None,
        classification: str = "UNCONFIRMED",
        evidence_strength: str = "NONE",
        confidence: str = "LOW",
        reasoning: str = "",
        supporting_observation_ids: Optional[List[int]] = None,
        contradictory_observation_ids: Optional[List[int]] = None,
        alternative_explanations: Optional[List[str]] = None,
        missing_evidence: Optional[List[str]] = None,
        observed_impact: Optional[str] = None,
        potential_impact: Optional[str] = None,
        unsupported_impact: Optional[str] = None,
        validation_questions: Optional[List[str]] = None,
        knowledge_sources: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Record an immutable finding validation audit entry."""
        with self.get_connection() as conn:
            c = conn.execute(
                """
                INSERT INTO finding_validations (
                    project_id, finding_id, hypothesis_id,
                    classification, evidence_strength, confidence, reasoning,
                    supporting_observation_ids, contradictory_observation_ids,
                    alternative_explanations, missing_evidence,
                    observed_impact, potential_impact, unsupported_impact,
                    validation_questions, knowledge_sources
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    project_id,
                    finding_id,
                    hypothesis_id,
                    classification,
                    evidence_strength,
                    confidence,
                    reasoning,
                    json.dumps(supporting_observation_ids or []),
                    json.dumps(contradictory_observation_ids or []),
                    json.dumps(alternative_explanations or []),
                    json.dumps(missing_evidence or []),
                    observed_impact,
                    potential_impact,
                    unsupported_impact,
                    json.dumps(validation_questions or []),
                    json.dumps(knowledge_sources or []),
                ),
            )
            row = conn.execute("SELECT * FROM finding_validations WHERE id = ?", (c.lastrowid,)).fetchone()
            return dict(row)

    def get_validation(self, validation_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a specific validation audit record by ID."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM finding_validations WHERE id = ?", (validation_id,)).fetchone()
            return dict(row) if row else None

    def list_validations(
        self,
        project_id: Optional[int] = None,
        finding_id: Optional[int] = None,
        hypothesis_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """List validation history in chronological order."""
        query = "SELECT * FROM finding_validations WHERE 1=1"
        params: List[Any] = []
        if project_id is not None:
            query += " AND project_id = ?"
            params.append(project_id)
        if finding_id is not None:
            query += " AND finding_id = ?"
            params.append(finding_id)
        if hypothesis_id is not None:
            query += " AND hypothesis_id = ?"
            params.append(hypothesis_id)
        query += " ORDER BY id ASC"
        with self.get_connection() as conn:
            return [dict(r) for r in conn.execute(query, params).fetchall()]

    def get_latest_validation(
        self,
        project_id: Optional[int] = None,
        finding_id: Optional[int] = None,
        hypothesis_id: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve the most recent validation record for a project, finding, or hypothesis."""
        query = "SELECT * FROM finding_validations WHERE 1=1"
        params: List[Any] = []
        if project_id is not None:
            query += " AND project_id = ?"
            params.append(project_id)
        if finding_id is not None:
            query += " AND finding_id = ?"
            params.append(finding_id)
        if hypothesis_id is not None:
            query += " AND hypothesis_id = ?"
            params.append(hypothesis_id)
        query += " ORDER BY id DESC LIMIT 1"
        with self.get_connection() as conn:
            row = conn.execute(query, params).fetchone()
            return dict(row) if row else None

    # -------------------------------------------------------------
    # Phase 9: Security Report Operations
    # -------------------------------------------------------------

    def save_report(
        self,
        project_id: int,
        finding_id: int,
        title: str,
        content: str,
        validation_id: Optional[int] = None,
        template_type: str = "BUG_BOUNTY",
        status: str = "DRAFT",
        format: str = "MARKDOWN",
        report_metadata: Optional[Dict[str, Any]] = None,
        version: Optional[int] = None,
        approved_by: Optional[str] = None,
        approved_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Save a new security report or report revision.

        Auto-increments version number per finding_id if version is not explicitly supplied.
        Computes SHA-256 content_hash.
        """
        import hashlib
        from datetime import datetime, timezone as _tz
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        meta_json = json.dumps(report_metadata or {})
        now = datetime.now(_tz.utc).isoformat()

        with self.get_connection() as conn:
            if version is None:
                row_v = conn.execute(
                    "SELECT MAX(version) AS max_v FROM security_reports WHERE finding_id = ?",
                    (finding_id,),
                ).fetchone()
                assigned_version = (row_v["max_v"] + 1) if (row_v and row_v["max_v"] is not None) else 1
            else:
                assigned_version = version

            c = conn.execute(
                """
                INSERT INTO security_reports (
                    project_id, finding_id, validation_id, version,
                    title, template_type, status, format, content,
                    report_metadata, content_hash, approved_by, approved_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    project_id,
                    finding_id,
                    validation_id,
                    assigned_version,
                    title,
                    template_type,
                    status,
                    format,
                    content,
                    meta_json,
                    content_hash,
                    approved_by,
                    approved_at,
                    now,
                    now,
                ),
            )
            report_id = c.lastrowid
            row = conn.execute("SELECT * FROM security_reports WHERE id = ?", (report_id,)).fetchone()
            return dict(row)

    def get_report(self, report_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a specific security report by ID."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM security_reports WHERE id = ?", (report_id,)).fetchone()
            return dict(row) if row else None

    def get_latest_report(
        self,
        finding_id: Optional[int] = None,
        project_id: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve the most recent security report for a finding or project."""
        query = "SELECT * FROM security_reports WHERE 1=1"
        params: List[Any] = []
        if finding_id is not None:
            query += " AND finding_id = ?"
            params.append(finding_id)
        if project_id is not None:
            query += " AND project_id = ?"
            params.append(project_id)
        query += " ORDER BY id DESC LIMIT 1"
        with self.get_connection() as conn:
            row = conn.execute(query, params).fetchone()
            return dict(row) if row else None

    def list_reports(
        self,
        project_id: Optional[int] = None,
        finding_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """List security reports ordered by creation date."""
        query = "SELECT * FROM security_reports WHERE 1=1"
        params: List[Any] = []
        if project_id is not None:
            query += " AND project_id = ?"
            params.append(project_id)
        if finding_id is not None:
            query += " AND finding_id = ?"
            params.append(finding_id)
        query += " ORDER BY version ASC, id ASC"
        with self.get_connection() as conn:
            return [dict(r) for r in conn.execute(query, params).fetchall()]

    def update_report_status(
        self,
        report_id: int,
        status: str,
        approved_by: Optional[str] = None,
        approved_at: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Update report lifecycle status (e.g. DRAFT -> READY_FOR_REVIEW -> APPROVED -> EXPORTED)."""
        from datetime import datetime, timezone as _tz
        now = datetime.now(_tz.utc).isoformat()
        with self.get_connection() as conn:
            if approved_by is not None:
                appr_time = approved_at or now
                conn.execute(
                    """
                    UPDATE security_reports
                    SET status = ?, approved_by = ?, approved_at = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (status, approved_by, appr_time, now, report_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE security_reports
                    SET status = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (status, now, report_id),
                )
            row = conn.execute("SELECT * FROM security_reports WHERE id = ?", (report_id,)).fetchone()
            return dict(row) if row else None



