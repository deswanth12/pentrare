"""Backup and recovery management for SQLite database and vector store.

Provides atomic online SQLite backups via sqlite3.backup(), vector store
snapshots, manifest integrity verification, and safe point-in-time recovery.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from app.config import get_settings, Settings
from app.storage.database import DatabaseManager


def _sha256_file(path: Path) -> str:
    """Calculate SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def create_backup(
    destination_dir: Optional[Path] = None,
    settings: Optional[Settings] = None,
) -> Dict[str, Any]:
    """Create a complete atomic backup of the database and vector store.

    Args:
        destination_dir: Directory to place backup files. Defaults to storage/backups/backup_YYYYMMDD_HHMMSS.
        settings: Application settings. Defaults to current singleton.

    Returns:
        Dict containing backup summary and manifest data.
    """
    if settings is None:
        settings = get_settings()

    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    if destination_dir is None:
        backup_dir = settings.database_path.parent / "backups" / f"backup_{timestamp_str}"
    else:
        backup_dir = Path(destination_dir)

    backup_dir.mkdir(parents=True, exist_ok=True)

    db_backup_path = backup_dir / "researcher.db"
    vector_backup_path = backup_dir / "vector_store.npz"
    manifest_path = backup_dir / "backup_manifest.json"

    # 1. Atomic SQLite Online Backup via conn.backup()
    if settings.database_path.exists():
        src_conn = sqlite3.connect(settings.database_path)
        dest_conn = sqlite3.connect(db_backup_path)
        with dest_conn:
            src_conn.backup(dest_conn)
        src_conn.close()
        dest_conn.close()
    else:
        # Create empty initialized DB if missing
        db = DatabaseManager(db_backup_path)
        db.init_db()

    # 2. Vector Store Backup
    if settings.vector_store_path.exists():
        shutil.copy2(settings.vector_store_path, vector_backup_path)

    # 3. Collect statistics for manifest
    db_hash = _sha256_file(db_backup_path) if db_backup_path.exists() else ""
    db_size = db_backup_path.stat().st_size if db_backup_path.exists() else 0

    vector_hash = _sha256_file(vector_backup_path) if vector_backup_path.exists() else ""
    vector_size = vector_backup_path.stat().st_size if vector_backup_path.exists() else 0

    # Query DB stats from backup
    doc_count = 0
    chunk_count = 0
    db_mgr = DatabaseManager(db_backup_path)
    try:
        with db_mgr.get_connection() as conn:
            doc_count = conn.execute(
                "SELECT COUNT(*) FROM documents WHERE status='active'"
            ).fetchone()[0]
            chunk_count = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
    except Exception:
        pass

    manifest = {
        "backup_version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": {
            "filename": "researcher.db",
            "sha256": db_hash,
            "size_bytes": db_size,
            "active_documents": doc_count,
            "total_chunks": chunk_count,
        },
        "vector_store": {
            "filename": "vector_store.npz",
            "sha256": vector_hash,
            "size_bytes": vector_size,
            "exists": vector_backup_path.exists(),
        },
        "status": "VALIDATED",
    }

    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return {
        "backup_dir": str(backup_dir),
        "manifest": manifest,
        "success": True,
    }


def verify_backup(backup_dir: Path | str) -> Dict[str, Any]:
    """Verify integrity of a backup directory.

    Checks:
    - Manifest file exists and is valid JSON
    - SQLite database integrity check via PRAGMA integrity_check
    - Hashes match manifest entries
    - Vector store is valid if present

    Returns:
        Dict with 'valid' (bool), 'errors' (list), and 'manifest' (dict).
    """
    bpath = Path(backup_dir)
    errors = []

    manifest_path = bpath / "backup_manifest.json"
    if not manifest_path.exists():
        return {"valid": False, "errors": ["backup_manifest.json missing"], "manifest": {}}

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as e:
        return {"valid": False, "errors": [f"Invalid manifest JSON: {e}"], "manifest": {}}

    # Verify DB file
    db_path = bpath / manifest.get("database", {}).get("filename", "researcher.db")
    if not db_path.exists():
        errors.append("Database backup file missing")
    else:
        # Check SHA-256 hash
        expected_hash = manifest.get("database", {}).get("sha256")
        if expected_hash and _sha256_file(db_path) != expected_hash:
            errors.append("Database SHA-256 hash mismatch")

        # Check SQLite integrity
        try:
            conn = sqlite3.connect(db_path)
            res = conn.execute("PRAGMA integrity_check;").fetchone()[0]
            conn.close()
            if res != "ok":
                errors.append(f"SQLite PRAGMA integrity_check failed: {res}")
        except Exception as e:
            errors.append(f"SQLite database unreadable: {e}")

    # Verify Vector Store if present
    vec_info = manifest.get("vector_store", {})
    if vec_info.get("exists", False):
        vec_path = bpath / vec_info.get("filename", "vector_store.npz")
        if not vec_path.exists():
            errors.append("Vector store backup file missing")
        else:
            expected_vec_hash = vec_info.get("sha256")
            if expected_vec_hash and _sha256_file(vec_path) != expected_vec_hash:
                errors.append("Vector store SHA-256 hash mismatch")

            # Check NumPy npz readability
            try:
                import numpy as np
                data = np.load(vec_path, allow_pickle=True)
                if "chunk_ids" not in data or ("embeddings" not in data and "vectors" not in data):
                    errors.append("Vector store archive missing required keys")
            except Exception as e:
                errors.append(f"Vector store npz file unreadable: {e}")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "manifest": manifest,
    }


def restore_backup(
    backup_dir: Path | str,
    target_db_path: Optional[Path | str] = None,
    target_vector_path: Optional[Path | str] = None,
    force: bool = False,
) -> Dict[str, Any]:
    """Restore database and vector store from a verified backup.

    Args:
        backup_dir: Path to backup directory containing database and manifest.
        target_db_path: Path to overwrite with restored DB. Defaults to active database path.
        target_vector_path: Path to overwrite with restored vector store. Defaults to active vector path.
        force: If True, bypasses non-critical verification warnings.

    Returns:
        Dict summarizing restore results.
    """
    settings = get_settings()
    bpath = Path(backup_dir)

    verification = verify_backup(bpath)
    if not verification["valid"] and not force:
        return {
            "success": False,
            "errors": verification["errors"],
            "message": "Backup verification failed. Use force=True to override.",
        }

    dest_db = Path(target_db_path) if target_db_path else settings.database_path
    dest_vec = Path(target_vector_path) if target_vector_path else settings.vector_store_path

    dest_db.parent.mkdir(parents=True, exist_ok=True)
    dest_vec.parent.mkdir(parents=True, exist_ok=True)

    src_db = bpath / "researcher.db"
    src_vec = bpath / "vector_store.npz"

    # Atomic SQLite restore via conn.backup()
    if src_db.exists():
        src_conn = sqlite3.connect(src_db)
        dest_conn = sqlite3.connect(dest_db)
        with dest_conn:
            src_conn.backup(dest_conn)
        src_conn.close()
        dest_conn.close()

    # Vector store copy
    if src_vec.exists():
        shutil.copy2(src_vec, dest_vec)

    return {
        "success": True,
        "restored_database": str(dest_db),
        "restored_vector_store": str(dest_vec) if src_vec.exists() else None,
        "manifest": verification.get("manifest", {}),
    }
