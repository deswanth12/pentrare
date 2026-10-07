#!/usr/bin/env python3
"""Knowledge ingestion script for Agentic Security Researcher."""

import sys
import argparse
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.config import get_settings
from app.storage.database import DatabaseManager
from app.knowledge.ingest import IngestionPipeline


def main():
    parser = argparse.ArgumentParser(description="Ingest local security knowledge documents.")
    parser.add_argument("--force", action="store_true", help="Force re-indexing of all documents.")
    parser.add_argument("--dir", dest="custom_dir", default=None, help="Custom knowledge directory path.")
    args = parser.parse_args()

    settings = get_settings()
    target_dir = Path(args.custom_dir) if args.custom_dir else (settings.knowledge_dir / "PentestingEverything")

    print("=" * 60)
    print(" Agentic Security Researcher - Knowledge Ingestion")
    print("=" * 60)
    print(f"Target Knowledge Directory: {target_dir}")

    if not target_dir.exists():
        print(f"[-] Error: Knowledge directory not found at {target_dir}")
        sys.exit(1)

    db = DatabaseManager(settings.database_path)
    pipeline = IngestionPipeline(knowledge_dir=target_dir, db=db)

    def on_progress(path: str, current: int, total: int):
        if current % 20 == 0 or current == total:
            print(f"[*] Processing [{current}/{total}]: {path}")

    summary = pipeline.run(force=args.force, progress_callback=on_progress)

    print("\n" + "=" * 60)
    print(" Ingestion Summary")
    print("=" * 60)
    print(f"Files Discovered: {summary['files_discovered']}")
    print(f"Files Processed:  {summary['files_processed']}")
    print(f"Files Skipped:    {summary['files_skipped']}")
    print(f"Files Failed:     {summary['files_failed']}")
    print(f"Chunks Created:   {summary['chunks_created']}")
    print(f"Status:           {summary['status']}")

    if summary["failed_files"]:
        print("\nFailed Files:")
        for failed in summary["failed_files"]:
            print(f"  - {failed['source']}: [{failed['error_type']}] {failed['error_message']}")

    print("=" * 60)


if __name__ == "__main__":
    main()
