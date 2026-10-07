"""Tests for knowledge ingestion pipeline and incremental indexing."""

import pytest
from pathlib import Path
from app.storage.database import DatabaseManager
from app.knowledge.ingest import IngestionPipeline


@pytest.fixture
def temp_knowledge_setup(tmp_path):
    """Fixture creating a temporary knowledge repository with mixed document types."""
    kb_dir = tmp_path / "knowledge_repo"
    kb_dir.mkdir()

    # Supported files
    (kb_dir / "web").mkdir()
    (kb_dir / "web" / "sqli.md").write_text("# SQL Injection\n\nMethodology for parameter analysis.", encoding="utf-8")
    (kb_dir / "web" / "xss.txt").write_text("Cross-Site Scripting\n\nReflected and DOM-based vectors.", encoding="utf-8")

    # Excluded files / folders
    (kb_dir / ".git").mkdir()
    (kb_dir / ".git" / "config").write_text("dummy", encoding="utf-8")
    (kb_dir / "web" / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n")

    db_path = tmp_path / "test_kb.db"
    db = DatabaseManager(db_path)
    db.init_db()

    return {"kb_dir": kb_dir, "db": db}


def test_file_discovery(temp_knowledge_setup):
    """Verify discovery filters supported vs. excluded files."""
    kb_dir = temp_knowledge_setup["kb_dir"]
    db = temp_knowledge_setup["db"]

    pipeline = IngestionPipeline(knowledge_dir=kb_dir, db=db)
    discovery = pipeline.discover_files()

    supported_names = [p.name for p in discovery["supported"]]
    assert "sqli.md" in supported_names
    assert "xss.txt" in supported_names
    assert "config" not in supported_names
    assert "image.png" not in supported_names


def test_full_and_incremental_ingestion(temp_knowledge_setup):
    """Verify first ingestion indexes documents, and second run skips unchanged files."""
    kb_dir = temp_knowledge_setup["kb_dir"]
    db = temp_knowledge_setup["db"]

    pipeline = IngestionPipeline(knowledge_dir=kb_dir, db=db)

    # First run
    run1 = pipeline.run()
    assert run1["status"] == "SUCCESS"
    assert run1["files_processed"] == 2
    assert run1["files_failed"] == 0
    assert run1["chunks_created"] >= 2

    # Check database state
    stats = db.get_knowledge_stats()
    assert stats["active_documents"] == 2
    assert stats["total_chunks"] >= 2

    # Second run without changes (Incremental)
    run2 = pipeline.run()
    assert run2["status"] == "SUCCESS"
    assert run2["files_processed"] == 0
    assert run2["files_skipped"] >= 2


def test_incremental_file_modification(temp_knowledge_setup):
    """Verify that editing a file triggers re-processing of only that file."""
    kb_dir = temp_knowledge_setup["kb_dir"]
    db = temp_knowledge_setup["db"]

    pipeline = IngestionPipeline(knowledge_dir=kb_dir, db=db)
    pipeline.run()

    # Modify sqli.md
    sqli_path = kb_dir / "web" / "sqli.md"
    sqli_path.write_text("# SQL Injection\n\nUpdated methodology with second-order injection.", encoding="utf-8")

    run_updated = pipeline.run()
    assert run_updated["files_processed"] == 1
    assert run_updated["files_failed"] == 0


def test_corrupted_file_error_handling(temp_knowledge_setup):
    """Verify that a corrupted file is recorded in failed_files without crashing the pipeline."""
    kb_dir = temp_knowledge_setup["kb_dir"]
    db = temp_knowledge_setup["db"]

    # Write a broken file pretending to be a PDF
    broken_pdf = kb_dir / "web" / "broken.pdf"
    broken_pdf.write_bytes(b"Not a valid PDF header or content")

    pipeline = IngestionPipeline(knowledge_dir=kb_dir, db=db)
    run_res = pipeline.run()

    assert run_res["files_failed"] == 1
    assert len(run_res["failed_files"]) == 1
    assert "broken.pdf" in run_res["failed_files"][0]["source"]
    # The valid files should still have processed
    assert run_res["files_processed"] == 2
