import json
import sys
import time
from pathlib import Path
from typing import Optional

# Ensure project root is in sys.path for direct script execution
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import click

from app import __version__
from app.config import get_settings
from app.storage.database import DatabaseManager
from app.knowledge.ingest import IngestionPipeline
from app.knowledge.retriever import KnowledgeRetriever
from app.knowledge.vector_store import VectorStore
from app.knowledge.embeddings import EmbeddingGenerator
from app.agent.qa import GroundedQAService
from app.reporting.templates import (
    SCOPE_TEMPLATE,
    ARCHITECTURE_TEMPLATE,
    RESEARCH_PLAN_TEMPLATE,
    OBSERVATIONS_TEMPLATE,
)


@click.group()
@click.version_option(version=__version__, prog_name="Agentic Security Researcher")
def cli():
    """Agentic Security Research Assistant - Human-in-the-Loop Security Research."""
    pass


@cli.command("init")
def init_cmd():
    """Initialize system directories, database, and verify knowledge repository."""
    settings = get_settings()
    settings.ensure_directories()

    db = DatabaseManager(settings.database_path)
    db.init_db()

    click.echo("[+] Initialized agent workspace directories.")
    click.echo(f"[+] SQLite database initialized: {settings.database_path}")

    # Check knowledge base
    pe_dir = settings.knowledge_dir / "PentestingEverything"
    if pe_dir.exists():
        doc_count = len(list(pe_dir.glob("**/*.*")))
        click.echo(f"[+] Knowledge base detected: {pe_dir} ({doc_count} files found)")
    else:
        click.echo(f"[-] Knowledge base not found at: {pe_dir}")

    click.echo("[OK] System successfully initialized for research.")


@cli.command("status")
def status_cmd():
    """Display system status, database health, project metrics, and safety guards."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)

    click.echo("=" * 60)
    click.echo(f" Agentic Security Researcher v{__version__} - System Status")
    click.echo("=" * 60)
    click.echo(f"Environment:          {settings.app_env}")
    click.echo(f"Base Directory:       {settings.database_path.parent.parent}")
    click.echo(f"Safety Mode:          HUMAN-IN-THE-LOOP (Autonomous exploitation: DISABLED)")

    # Gemini Key Status
    if settings.has_gemini_key:
        click.echo("Gemini API Key:       Configured (Ready for LLM reasoning)")
    else:
        click.echo("Gemini API Key:       Not configured (Required for Phase 5+ reasoning)")

    # DB Status
    try:
        project_count = db.get_project_count()
        findings_count = db.get_findings_count()
        knowledge_stats = db.get_knowledge_stats()
        click.echo(f"Database:             Connected ({settings.database_path.name})")
        click.echo(f"Projects Count:       {project_count}")
        click.echo(f"Findings Logged:      {findings_count}")
        click.echo(f"Active Documents:     {knowledge_stats['active_documents']}")
        click.echo(f"Total Chunks:         {knowledge_stats['total_chunks']}")
        click.echo(f"Database Size:        {knowledge_stats['db_size_mb']} MB")
    except Exception as e:
        click.echo(f"Database:             Not initialized or unreachable ({e})")
        click.echo("                      Run 'python app/main.py init' to set up database.")

    # Knowledge Base Status
    pe_dir = settings.knowledge_dir / "PentestingEverything"
    if pe_dir.exists():
        file_count = len(list(pe_dir.glob("**/*.*")))
        click.echo(f"Knowledge Base:       PentestingEverything present ({file_count} files)")
    else:
        click.echo(f"Knowledge Base:       Missing at {pe_dir}")

    # Vector Store Status
    if settings.vector_store_path.exists():
        try:
            vs = VectorStore(settings.vector_store_path)
            vs.load()
            vs_mb = round(settings.vector_store_path.stat().st_size / (1024 * 1024), 2)
            click.echo(f"Vector Store:         Indexed ({vs.size()} vectors, {vs_mb} MB)")
            click.echo(f"Embedding Model:      {settings.embedding_model}")
        except Exception:
            click.echo("Vector Store:         Error reading vector index file")
    else:
        click.echo("Vector Store:         Not built (Run 'python app/main.py knowledge embeddings')")

    click.echo("=" * 60)


# -----------------------------------------------------------------
# Knowledge Base Commands (Phase 2)
# -----------------------------------------------------------------

@cli.group("knowledge")
def knowledge_group():
    """Manage knowledge base ingestion, index status, and metrics."""
    pass


@cli.command("ingest")
@click.option("--force", is_flag=True, help="Force re-processing of unchanged files")
@click.option("--path", "custom_path", default=None, help="Custom knowledge directory path")
def ingest_cmd(force: bool, custom_path: Optional[str]):
    """Ingest documents from local knowledge base."""
    settings = get_settings()
    target_dir = Path(custom_path) if custom_path else (settings.knowledge_dir / "PentestingEverything")

    click.echo("=" * 60)
    click.echo(" Knowledge Ingestion")
    click.echo("=" * 60)
    click.echo(f"\nRepository:\n{target_dir.as_posix()}\n")

    if not target_dir.exists():
        click.echo(f"[-] Error: Knowledge directory not found at {target_dir}", err=True)
        sys.exit(1)

    db = DatabaseManager(settings.database_path)
    pipeline = IngestionPipeline(knowledge_dir=target_dir, db=db)

    def on_progress(path: str, current: int, total: int):
        # Progress indicator every 20 files
        if current % 20 == 0 or current == total:
            click.echo(f"[*] Processing [{current}/{total}]: {path}")

    summary = pipeline.run(force=force, progress_callback=on_progress)

    click.echo(f"\nFiles discovered: {summary['files_discovered']}")
    click.echo(f"Files processed:  {summary['files_processed']}")
    click.echo(f"Files skipped:    {summary['files_skipped']}")
    click.echo(f"Files failed:     {summary['files_failed']}")
    click.echo(f"Chunks created:   {summary['chunks_created']}")
    click.echo(f"\nStatus:\n{summary['status']}")

    if summary["failed_files"]:
        click.echo("\nFailed Files Details:")
        for failed in summary["failed_files"]:
            click.echo(f"  - {failed['source']}: [{failed['error_type']}] {failed['error_message']}")

    click.echo("=" * 60)


@knowledge_group.command("ingest")
@click.option("--force", is_flag=True, help="Force re-processing of unchanged files")
@click.option("--path", "custom_path", default=None, help="Custom knowledge directory path")
def knowledge_ingest_alias(force: bool, custom_path: Optional[str]):
    """Alias for knowledge ingestion."""
    ctx = click.get_current_context()
    ctx.invoke(ingest_cmd, force=force, custom_path=custom_path)


@knowledge_group.command("status")
def knowledge_status_cmd():
    """Display knowledge base statistics, chunk count, and index metrics."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()

    stats = db.get_knowledge_stats()
    last_run = stats.get("last_run")

    click.echo("=" * 60)
    click.echo(" Knowledge Base Status")
    click.echo("=" * 60)
    click.echo(f"Active Documents:     {stats['active_documents']}")
    click.echo(f"Total Chunks:         {stats['total_chunks']}")
    click.echo(f"Database Index Size:  {stats['db_size_mb']} MB ({stats['db_size_bytes']} bytes)")

    # Vector Store Status
    if settings.vector_store_path.exists():
        try:
            vs = VectorStore(settings.vector_store_path)
            vs.load()
            vs_mb = round(settings.vector_store_path.stat().st_size / (1024 * 1024), 2)
            click.echo(f"Vector Store:         Indexed ({vs.size()} vectors, {vs_mb} MB)")
            click.echo(f"Embedding Model:      {settings.embedding_model}")
        except Exception:
            click.echo("Vector Store:         Error reading vector index file")
    else:
        click.echo("Vector Store:         Not built (Run 'python app/main.py knowledge embeddings')")

    if last_run:
        click.echo(f"\nLast Ingestion Run:")
        click.echo(f"  Started:            {last_run.get('started_at')}")
        click.echo(f"  Completed:          {last_run.get('completed_at')}")
        click.echo(f"  Files Discovered:   {last_run.get('files_discovered')}")
        click.echo(f"  Files Processed:    {last_run.get('files_processed')}")
        click.echo(f"  Files Skipped:      {last_run.get('files_skipped')}")
        click.echo(f"  Files Failed:       {last_run.get('files_failed')}")
        click.echo(f"  Chunks Created:     {last_run.get('chunks_created')}")
        click.echo(f"  Status:             {last_run.get('status')}")
        if last_run.get("error_log"):
            click.echo(f"  Error Log:          {last_run.get('error_log')}")
    else:
        click.echo("\nNo previous ingestion runs recorded. Run 'python app/main.py ingest' to build index.")

    click.echo("=" * 60)


@knowledge_group.command("embeddings")
@click.option("--rebuild", is_flag=True, help="Force rebuilding all embeddings from scratch")
@click.option("--batch-size", default=64, type=int, help="Batch size for embedding generation")
def knowledge_embeddings_cmd(rebuild: bool, batch_size: int):
    """Generate or incrementally update dense vector embeddings for knowledge chunks."""
    settings = get_settings()
    settings.ensure_directories()
    db = DatabaseManager(settings.database_path)
    db.init_db()

    click.echo("=" * 60)
    click.echo(" Dense Vector Embeddings Generation")
    click.echo("=" * 60)
    click.echo(f"Model:           {settings.embedding_model}")
    click.echo(f"Vector Store:    {settings.vector_store_path}")
    click.echo(f"Batch Size:      {batch_size}")
    click.echo(f"Rebuild:         {rebuild}\n")

    total_active = db.get_active_chunk_count()
    if total_active == 0:
        click.echo("[-] No active chunks found in database. Run 'python app/main.py ingest' first.")
        return

    vector_store = VectorStore(settings.vector_store_path)
    if not rebuild:
        loaded = vector_store.load()
        if loaded:
            click.echo(f"[+] Loaded existing vector store with {vector_store.size()} vectors.")
    else:
        vector_store.clear()
        click.echo("[*] Rebuilding vector store from scratch.")

    all_chunks = db.get_all_active_chunks()
    active_cids = {c["chunk_id"] for c in all_chunks}

    # Delete stale vectors
    stale_cids = [cid for cid in vector_store.chunk_ids if cid not in active_cids]
    removed_count = 0
    if stale_cids:
        removed_count = vector_store.delete_chunks(stale_cids)
        click.echo(f"[+] Pruned {removed_count} stale vectors from index.")

    # Identify chunks needing embedding
    chunks_to_embed = []
    for c in all_chunks:
        cid = c["chunk_id"]
        chash = c["content_hash"]
        if not vector_store.contains(cid) or vector_store.get_content_hash(cid) != chash:
            chunks_to_embed.append(c)

    skipped_count = len(all_chunks) - len(chunks_to_embed)
    click.echo(f"[*] Total active chunks: {len(all_chunks)}")
    click.echo(f"[*] Chunks to embed:     {len(chunks_to_embed)}")
    click.echo(f"[*] Chunks up-to-date:   {skipped_count}")

    if not chunks_to_embed and removed_count == 0:
        click.echo("\n[OK] Vector store is already fully up-to-date.")
        click.echo("=" * 60)
        return

    start_time = time.time()
    if chunks_to_embed:
        click.echo(f"\n[*] Initializing embedding model: {settings.embedding_model}...")
        emb_gen = EmbeddingGenerator(model_name=settings.embedding_model)
        total_to_embed = len(chunks_to_embed)

        for start_idx in range(0, total_to_embed, batch_size):
            batch = chunks_to_embed[start_idx : start_idx + batch_size]
            texts = [c["content"] for c in batch]
            batch_cids = [c["chunk_id"] for c in batch]
            batch_hashes = [c["content_hash"] for c in batch]

            embs = emb_gen.embed_texts(texts, batch_size=batch_size)
            vector_store.add_chunks(batch_cids, embs, batch_hashes)

            processed = min(start_idx + len(batch), total_to_embed)
            if processed % (batch_size * 4) == 0 or processed == total_to_embed:
                click.echo(f"[*] Embedded [{processed}/{total_to_embed}] chunks...")

    vector_store.save()
    duration = round(time.time() - start_time, 2)
    file_size_mb = round(settings.vector_store_path.stat().st_size / (1024 * 1024), 2)

    click.echo("-" * 60)
    click.echo(f"[+] Vector store saved:   {settings.vector_store_path}")
    click.echo(f"[+] Total stored vectors: {vector_store.size()}")
    click.echo(f"[+] Index file size:      {file_size_mb} MB")
    click.echo(f"[+] Generation duration:  {duration}s")
    click.echo("=" * 60)
    click.echo("[OK] Embeddings successfully generated.")


@cli.command("embeddings")
@click.option("--rebuild", is_flag=True, help="Force rebuilding all embeddings from scratch")
@click.option("--batch-size", default=64, type=int, help="Batch size for embedding generation")
def embeddings_alias_cmd(rebuild: bool, batch_size: int):
    """Alias for 'knowledge embeddings'."""
    ctx = click.get_current_context()
    ctx.invoke(knowledge_embeddings_cmd, rebuild=rebuild, batch_size=batch_size)


@cli.command("search")
@click.argument("query")
@click.option("--limit", default=5, type=int, help="Maximum number of results to display")
@click.option(
    "--mode",
    type=click.Choice(["hybrid", "lexical", "semantic"], case_sensitive=False),
    default="hybrid",
    help="Search mode: hybrid (BM25 + dense vectors), lexical (BM25 only), or semantic (vectors only)",
)
@click.option(
    "--debug-retrieval",
    is_flag=True,
    help="Display detailed scoring breakdown (lexical score, semantic score, match type)",
)
def search_cmd(query: str, limit: int, mode: str, debug_retrieval: bool):
    """Search knowledge base for security methodologies."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()

    retriever = KnowledgeRetriever(db=db)
    try:
        results = retriever.search(query, limit=limit, mode=mode)
    except Exception as e:
        click.echo(f"[-] Search error: {e}", err=True)
        sys.exit(1)

    if not results:
        click.echo(f"[-] No matching methodology chunks found for: '{query}'")
        return

    click.echo("=" * 60)
    click.echo(f" Knowledge Search Results for: '{query}' ({len(results)} matches, mode: {mode})")
    click.echo("=" * 60)

    for i, res in enumerate(results, start=1):
        def _safe(text: str) -> str:
            """Encode text to stdout encoding, replacing unencodable characters."""
            enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"
            return text.encode(enc, errors="replace").decode(enc)

        click.echo(_safe(f"\nResult {i}"))
        click.echo(_safe(f"Source:\nknowledge/PentestingEverything/{res.source_path}"))
        click.echo(_safe(f"\nSection:\n{res.section}" + (f" (Page {res.page})" if res.page else "")))
        if debug_retrieval:
            lex_str = f"{res.lexical_score}" if res.lexical_score is not None else "N/A"
            sem_str = f"{res.semantic_score}" if res.semantic_score is not None else "N/A"
            click.echo(_safe(f"\nScore:\n{res.score} [Lexical: {lex_str}, Semantic: {sem_str}, Match: {res.match_type}]"))
        else:
            click.echo(_safe(f"\nScore:\n{res.score}"))
        click.echo(_safe(f"\nContent:\n{res.content}"))
        click.echo("-" * 60)


@cli.command("ask")
@click.argument("question")
@click.option("--limit", default=5, type=int, help="Maximum number of retrieved sources to consult")
@click.option("--sources-only", is_flag=True, help="Retrieve and show matching sources without contacting Gemini")
def ask_cmd(question: str, limit: int, sources_only: bool):
    """Ask a security research question answered with grounded knowledge base evidence."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()

    qa_service = GroundedQAService(db=db, settings=settings)

    click.echo("=" * 60)
    click.echo(" Grounded Security Research QA")
    click.echo("=" * 60)
    click.echo(f"Question: {question}\n")

    try:
        result = qa_service.ask(question, max_sources=limit, sources_only=sources_only)
    except Exception as e:
        click.echo(f"[-] Error: {e}", err=True)
        sys.exit(1)

    sources = result["sources"]
    click.echo(f"[+] Retrieved Knowledge Sources ({len(sources)}):")
    if not sources:
        click.echo("    (No matching methodology found in knowledge base)")
    else:
        for s in sources:
            page_txt = f" (Page {s.page})" if s.page else ""
            click.echo(f"  [{s.index}] {s.full_source_path} - {s.section}{page_txt} (Score: {s.score})")

    if sources_only:
        click.echo("\n[*] Flag --sources-only was specified. Gemini was not contacted.")
        click.echo("=" * 60)
        return

    click.echo(f"\n[*] Grounded Answer (Model: {result['model']}):")
    click.echo("-" * 60)
    click.echo(result["answer"])
    click.echo("=" * 60)


# -----------------------------------------------------------------
# Project Management Commands
# -----------------------------------------------------------------

@cli.group("project")
def project_group():
    """Manage research projects and engagement workspaces."""
    pass


@project_group.command("create")
@click.argument("name")
@click.option("--desc", default="", help="Description of the research project")
def project_create_cmd(name: str, desc: str):
    """Create a new research project workspace."""
    settings = get_settings()
    settings.ensure_directories()
    db = DatabaseManager(settings.database_path)
    db.init_db()

    clean_name = name.strip()
    if not clean_name:
        click.echo("[-] Error: Project name cannot be empty.", err=True)
        sys.exit(1)

    try:
        project = db.create_project(clean_name, desc)
    except Exception as e:
        click.echo(f"[-] Failed to create project in database: {e}", err=True)
        sys.exit(1)

    project_dir = settings.projects_dir / clean_name
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "findings").mkdir(exist_ok=True)
    (project_dir / "evidence").mkdir(exist_ok=True)

    templates_map = {
        "scope.md": SCOPE_TEMPLATE,
        "architecture.md": ARCHITECTURE_TEMPLATE,
        "research-plan.md": RESEARCH_PLAN_TEMPLATE,
        "observations.md": OBSERVATIONS_TEMPLATE,
        "report.md": "# Research Report\n\n(Generated report will be compiled here.)\n",
    }

    for filename, content in templates_map.items():
        filepath = project_dir / filename
        if not filepath.exists():
            filepath.write_text(content, encoding="utf-8")

    click.echo(f"[+] Project '{clean_name}' successfully created (ID: {project['id']}).")
    click.echo(f"[+] Workspace: {project_dir}")
    click.echo(f"    - {project_dir / 'scope.md'}")
    click.echo(f"    - {project_dir / 'architecture.md'}")
    click.echo(f"    - {project_dir / 'research-plan.md'}")
    click.echo(f"    - {project_dir / 'observations.md'}")
    click.echo(f"    - {project_dir / 'findings/'}")
    click.echo(f"    - {project_dir / 'evidence/'}")


@project_group.command("list")
def project_list_cmd():
    """List all research projects."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    try:
        projects = db.list_projects()
        if not projects:
            click.echo("No research projects found. Create one with: python app/main.py project create <name>")
            return

        click.echo(f"{'ID':<4} {'Name':<25} {'Status':<10} {'Created':<20} {'Description'}")
        click.echo("-" * 75)
        for p in projects:
            created = str(p.get("created_at", ""))[:19]
            desc = p.get("description", "") or "-"
            click.echo(f"{p['id']:<4} {p['name']:<25} {p['status']:<10} {created:<20} {desc}")
    except Exception as e:
        click.echo(f"[-] Error querying projects: {e}", err=True)


def _get_project_or_exit(db: DatabaseManager, project_id: int) -> dict:
    """Helper: retrieve a project by ID or exit with a clean error."""
    project = db.get_project_by_id(project_id)
    if not project:
        click.echo(f"[-] Error: Project ID {project_id} not found.", err=True)
        sys.exit(1)
    return project


# -----------------------------------------------------------------
# Phase 5: Project Intelligence Commands
# -----------------------------------------------------------------

@project_group.command("show")
@click.argument("project_id", type=int)
def project_show_cmd(project_id: int):
    """Show detailed project information including scope, asset, objective, hypothesis, evidence, and finding counts."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()

    project = _get_project_or_exit(db, project_id)
    counts = db.get_project_summary_counts(project_id)
    scope = db.get_project_scope(project_id)

    click.echo("=" * 60)
    click.echo(f" Project: {project['name']} (ID: {project['id']})")
    click.echo("=" * 60)
    click.echo(f"Status:        {project['status']}")
    click.echo(f"Created:       {str(project.get('created_at', ''))[:19]}")
    click.echo(f"Updated:       {str(project.get('updated_at', ''))[:19]}")
    desc = project.get("description") or "-"
    click.echo(f"Description:   {desc}")
    goal = project.get("research_goal") or "(not set)"
    click.echo(f"Research Goal: {goal}")
    click.echo("")
    click.echo("Scope:")
    if scope:
        import json as _j
        in_scope = _j.loads(scope.get("in_scope_assets") or "[]")
        out_scope = _j.loads(scope.get("out_of_scope_assets") or "[]")
        click.echo(f"  In-scope assets ({len(in_scope)}):     " + (", ".join(in_scope) if in_scope else "(none)"))
        click.echo(f"  Out-of-scope assets ({len(out_scope)}): " + (", ".join(out_scope) if out_scope else "(none)"))
        auth = scope.get("authorization_notes") or "(not specified)"
        click.echo(f"  Authorization notes: {auth}")
    else:
        click.echo("  (No scope defined yet. Use 'project add-scope')")
    click.echo("")
    click.echo("Entity Counts:")
    click.echo(f"  Assets:       {counts['assets']}")
    click.echo(f"  Objectives:   {counts['objectives']}")
    click.echo(f"  Hypotheses:   {counts['hypotheses']}")
    click.echo(f"  Evidence:     {counts['evidence']}")
    click.echo(f"  Findings:     {counts['findings']}")
    click.echo(f"  Activities:   {counts['activities']}")
    click.echo("=" * 60)


@project_group.command("assets")
@click.argument("project_id", type=int)
def project_assets_cmd(project_id: int):
    """List all assets for a project."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)
    assets = db.list_assets(project_id)

    if not assets:
        click.echo(f"[*] No assets found for project {project_id}. Use 'project add-asset'.")
        return

    click.echo(f"[+] Assets for project {project_id} ({len(assets)} total):")
    click.echo("-" * 70)
    for a in assets:
        click.echo(f"  ID:{a['id']}  [{a['scope_status']}]  {a['name']}  ({a['asset_type']})")
        if a.get("identifier"):
            click.echo(f"         Identifier: {a['identifier']}")
        if a.get("technology"):
            click.echo(f"         Technology: {a['technology']}")
        if a.get("notes"):
            click.echo(f"         Notes: {a['notes']}")


@project_group.command("objectives")
@click.argument("project_id", type=int)
def project_objectives_cmd(project_id: int):
    """List all research objectives for a project."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)
    objectives = db.list_objectives(project_id)

    if not objectives:
        click.echo(f"[*] No objectives found for project {project_id}. Use 'project add-objective'.")
        return

    click.echo(f"[+] Objectives for project {project_id} ({len(objectives)} total):")
    click.echo("-" * 70)
    for o in objectives:
        click.echo(f"  ID:{o['id']}  [{o['status']}]  [{o['priority']}]  {o['title']}")
        if o.get("description"):
            click.echo(f"         {o['description']}")


@project_group.command("hypotheses")
@click.argument("project_id", type=int)
def project_hypotheses_cmd(project_id: int):
    """List all hypotheses for a project. NOTE: Hypotheses are NOT findings."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)
    hypotheses = db.list_hypotheses(project_id)

    if not hypotheses:
        click.echo(f"[*] No hypotheses found for project {project_id}. Use 'project add-hypothesis'.")
        return

    click.echo(f"[+] Hypotheses for project {project_id} ({len(hypotheses)} total):")
    click.echo("[*] NOTE: Hypotheses require evidence + validation to become findings.")
    click.echo("-" * 70)
    for h in hypotheses:
        click.echo(f"  ID:{h['id']}  [{h['status']}]  [Confidence: {h['confidence']}]  {h['title']}")
        if h.get("description"):
            click.echo(f"         {h['description']}")


@project_group.command("evidence")
@click.argument("project_id", type=int)
def project_evidence_cmd(project_id: int):
    """List all researcher-supplied evidence for a project."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)
    evidence = db.list_research_evidence(project_id)

    if not evidence:
        click.echo(f"[*] No evidence found for project {project_id}. Use 'project add-evidence'.")
        return

    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"

    def _safe(text: str) -> str:
        return text.encode(enc, errors="replace").decode(enc)

    click.echo(f"[+] Evidence for project {project_id} ({len(evidence)} total):")
    click.echo("[*] Evidence is researcher-supplied only. AI does not fabricate evidence.")
    click.echo("-" * 70)
    for ev in evidence:
        click.echo(_safe(f"  ID:{ev['id']}  [{ev['evidence_type']}]  [Confidence: {ev['confidence']}]  {ev['title']}"))
        if ev.get("description"):
            click.echo(_safe(f"         {ev['description']}"))
        if ev.get("source"):
            click.echo(_safe(f"         Source: {ev['source']}"))


@project_group.command("findings")
@click.argument("project_id", type=int)
def project_findings_cmd(project_id: int):
    """List all findings for a project."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)
    findings = db.list_findings(project_id)

    if not findings:
        click.echo(f"[*] No findings found for project {project_id}. Use 'project add-finding'.")
        return

    click.echo(f"[+] Findings for project {project_id} ({len(findings)} total):")
    click.echo("-" * 70)
    for f in findings:
        click.echo(f"  ID:{f['id']}  [{f['severity']}]  [{f['classification']}]  [{f.get('validation_status', 'UNCONFIRMED')}]  {f['title']}")
        if f.get("summary"):
            click.echo(f"         {f['summary']}")
        if f.get("affected_asset"):
            click.echo(f"         Asset: {f['affected_asset']}")


@project_group.command("timeline")
@click.argument("project_id", type=int)
def project_timeline_cmd(project_id: int):
    """Show project activity timeline."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)
    activities = db.list_activities(project_id)

    if not activities:
        click.echo(f"[*] No activities recorded for project {project_id}.")
        return

    click.echo(f"[+] Activity Timeline for project {project_id} ({len(activities)} events):")
    click.echo("-" * 70)
    for act in activities:
        ts = str(act.get("timestamp", ""))[:19]
        desc = act.get("description") or ""
        click.echo(f"  {ts}  [{act['event_type']}]  {desc}")


# -----------------------------------------------------------------
# Phase 5: Add-* subcommands
# -----------------------------------------------------------------

@project_group.command("add-scope")
@click.argument("project_id", type=int)
@click.option("--in-scope", "in_scope", multiple=True, help="In-scope asset (repeat for multiple)")
@click.option("--out-of-scope", "out_of_scope", multiple=True, help="Out-of-scope asset (repeat for multiple)")
@click.option("--auth-notes", default=None, help="Authorization notes (program name, authorization reference)")
@click.option("--prohibited", default=None, help="Prohibited testing actions")
def project_add_scope_cmd(project_id: int, in_scope, out_of_scope, auth_notes, prohibited):
    """Set or update project scope (in-scope/out-of-scope assets and authorization notes).

    Example:
        python app/main.py project add-scope 1 --in-scope example.com --out-of-scope admin.example.com
    """
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)

    scope = db.set_project_scope(
        project_id,
        in_scope_assets=list(in_scope),
        out_of_scope_assets=list(out_of_scope),
        allowed_testing_notes=None,
        prohibited_actions=prohibited,
        authorization_notes=auth_notes,
    )
    db.log_activity(project_id, "SCOPE_UPDATED", f"Scope updated: {len(in_scope)} in-scope, {len(out_of_scope)} out-of-scope assets")

    click.echo(f"[+] Scope updated for project {project_id}.")
    click.echo(f"    In-scope: {list(in_scope)}")
    click.echo(f"    Out-of-scope: {list(out_of_scope)}")
    if auth_notes:
        click.echo(f"    Authorization notes: {auth_notes}")


@project_group.command("add-asset")
@click.argument("project_id", type=int)
@click.option("--name", required=True, help="Asset name (e.g., 'example.com')")
@click.option("--type", "asset_type", default="other",
              type=click.Choice(["domain", "subdomain", "url", "api", "web_application",
                                 "mobile_application", "repository", "service", "cloud_resource", "other"]),
              help="Asset type")
@click.option("--identifier", default=None, help="Asset identifier (URL, IP, etc.)")
@click.option("--scope-status", default="UNKNOWN",
              type=click.Choice(["IN_SCOPE", "OUT_OF_SCOPE", "UNKNOWN"]),
              help="Scope status (default: UNKNOWN)")
@click.option("--technology", default=None, help="Technology stack (optional)")
@click.option("--notes", default=None, help="Additional notes")
def project_add_asset_cmd(project_id: int, name: str, asset_type: str, identifier,
                          scope_status: str, technology, notes):
    """Add a researcher-supplied asset to a project.

    Assets default to UNKNOWN scope until explicitly authorized.

    Example:
        python app/main.py project add-asset 1 --name example.com --type domain --scope-status IN_SCOPE
    """
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)

    asset = db.add_asset(project_id, name, asset_type, identifier, scope_status, technology, notes)
    db.log_activity(project_id, "ASSET_ADDED", f"Asset added: {name} [{scope_status}]")

    click.echo(f"[+] Asset '{name}' added to project {project_id} (ID: {asset['id']}).")
    click.echo(f"    Type: {asset_type}  |  Scope: {scope_status}")
    if scope_status == "UNKNOWN":
        click.echo("[*] NOTE: Asset scope is UNKNOWN. Authorization must be explicitly verified.")


@project_group.command("add-objective")
@click.argument("project_id", type=int)
@click.option("--title", required=True, help="Objective title")
@click.option("--description", default=None, help="Detailed description")
@click.option("--priority", default="MEDIUM",
              type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
              help="Priority level")
@click.option("--notes", default=None, help="Additional notes")
def project_add_objective_cmd(project_id: int, title: str, description, priority: str, notes):
    """Add a research objective to a project.

    Example:
        python app/main.py project add-objective 1 --title "Assess JWT implementation" --priority HIGH
    """
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)

    obj = db.add_objective(project_id, title, description, priority, notes)
    db.log_activity(project_id, "OBJECTIVE_CREATED", f"Objective created: {title}")

    click.echo(f"[+] Objective '{title}' added to project {project_id} (ID: {obj['id']}).")
    click.echo(f"    Priority: {priority}  |  Status: OPEN")


@project_group.command("add-hypothesis")
@click.argument("project_id", type=int)
@click.option("--title", required=True, help="Hypothesis title")
@click.option("--description", default=None, help="Detailed description")
@click.option("--rationale", default=None, help="Reasoning behind the hypothesis")
@click.option("--objective-id", type=int, default=None, help="Link to an objective ID")
@click.option("--confidence", default="LOW",
              type=click.Choice(["LOW", "MEDIUM", "HIGH"]),
              help="Initial confidence level")
def project_add_hypothesis_cmd(project_id: int, title: str, description, rationale,
                               objective_id, confidence: str):
    """Add a research hypothesis to a project.

    NOTE: A hypothesis is NOT a finding. It starts as UNTESTED and requires
    researcher-supplied evidence and validation before becoming a finding.

    Example:
        python app/main.py project add-hypothesis 1 --title "JWT signature validation may be bypassable"
    """
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)

    hyp = db.add_hypothesis(project_id, title, description, rationale, objective_id, confidence)
    db.log_activity(project_id, "HYPOTHESIS_CREATED", f"Hypothesis created: {title} [UNTESTED]")

    click.echo(f"[+] Hypothesis '{title}' added to project {project_id} (ID: {hyp['id']}).")
    click.echo(f"    Status: UNTESTED  |  Confidence: {confidence}")
    click.echo("[*] NOTE: This is a hypothesis, not a finding. Provide evidence to validate it.")


@project_group.command("add-evidence")
@click.argument("project_id", type=int)
@click.option("--title", required=True, help="Evidence title/label")
@click.option("--type", "evidence_type", default="OBSERVATION",
              type=click.Choice(["OBSERVATION", "HTTP_REQUEST", "HTTP_RESPONSE", "SCREENSHOT",
                                 "LOG", "SOURCE_CODE", "CONFIGURATION", "DOCUMENT",
                                 "RESEARCHER_NOTE", "OTHER"]),
              help="Evidence type")
@click.option("--description", default=None, help="Description of what was observed")
@click.option("--content", default=None, help="Raw evidence content (paste HTTP request/response/log)")
@click.option("--source", default=None, help="Evidence source (tool, endpoint, file path)")
@click.option("--hypothesis-id", type=int, default=None, help="Link to a hypothesis ID")
@click.option("--note", default=None, help="Researcher note")
@click.option("--confidence", default="LOW",
              type=click.Choice(["LOW", "MEDIUM", "HIGH"]),
              help="Evidence confidence level")
def project_add_evidence_cmd(project_id: int, title: str, evidence_type: str, description,
                             content, source, hypothesis_id, note, confidence: str):
    """Add researcher-supplied evidence to a project.

    IMPORTANT: Only supply evidence you have directly observed during authorized testing.
    The system stores only what you provide. Evidence is never AI-generated.

    Example:
        python app/main.py project add-evidence 1 --title "Login response" --type HTTP_RESPONSE --description "200 OK with session token"
    """
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)

    ev = db.add_research_evidence(
        project_id, title, evidence_type, description, content, source,
        hypothesis_id, note, confidence,
    )
    db.log_activity(project_id, "EVIDENCE_ADDED", f"Evidence added: {title} [{evidence_type}]")

    click.echo(f"[+] Evidence '{title}' added to project {project_id} (ID: {ev['id']}).")
    click.echo(f"    Type: {evidence_type}  |  Confidence: {confidence}")


@project_group.command("add-finding")
@click.argument("project_id", type=int)
@click.option("--title", required=True, help="Finding title")
@click.option("--severity", default="Unknown",
              type=click.Choice(["Critical", "High", "Medium", "Low", "Informational", "Unknown"]),
              help="Severity rating")
@click.option("--classification", default="UNCONFIRMED",
              type=click.Choice(["CONFIRMED", "LIKELY", "POSSIBLE", "UNCONFIRMED", "FALSE_POSITIVE"]),
              help="Finding classification (default: UNCONFIRMED)")
@click.option("--asset", default=None, help="Affected asset")
@click.option("--summary", default=None, help="Finding summary")
@click.option("--impact", default=None, help="Security impact description")
@click.option("--root-cause", default=None, help="Root cause analysis")
@click.option("--remediation", default=None, help="Remediation recommendation")
@click.option("--evidence-id", "evidence_ids", multiple=True, type=int,
              help="Link evidence IDs (repeat for multiple: --evidence-id 1 --evidence-id 2)")
def project_add_finding_cmd(project_id: int, title: str, severity: str, classification: str,
                            asset, summary, impact, root_cause, remediation, evidence_ids):
    """Add a finding to a project.

    Findings default to UNCONFIRMED. To mark as CONFIRMED, you must supply
    sufficient evidence and ensure the researcher has validated the finding.

    Example:
        python app/main.py project add-finding 1 --title "Insecure JWT" --severity High --evidence-id 1
    """
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)

    finding = db.create_finding(
        project_id, title, severity, classification, asset, summary,
        None, impact, root_cause, remediation,
        list(evidence_ids), classification,
    )
    db.log_activity(project_id, "FINDING_CREATED",
                    f"Finding created: {title} [{severity}/{classification}]")

    click.echo(f"[+] Finding '{title}' added to project {project_id} (ID: {finding['id']}).")
    click.echo(f"    Severity: {severity}  |  Classification: {classification}")
    if classification in ("CONFIRMED", "LIKELY") and not evidence_ids:
        click.echo("[!] WARNING: High-confidence classification without linked evidence.")


@project_group.command("plan")
@click.argument("project_id", type=int)
@click.option("--objective", required=True, help="Research objective to plan for")
@click.option("--limit", default=8, type=int, help="Number of knowledge sources to retrieve")
def project_plan_cmd(project_id: int, objective: str, limit: int):
    """Generate a structured research plan using local knowledge + Gemini.

    Retrieves relevant security knowledge and generates hypotheses,
    evidence needed, and validation questions. This is a planning aid only.
    The researcher performs all active testing.

    Example:
        python app/main.py project plan 1 --objective "Assess authentication security"
    """
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)

    from app.research.planner import ResearchPlanner
    from app.knowledge.retriever import KnowledgeRetriever

    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"

    def _safe(text: str) -> str:
        return text.encode(enc, errors="replace").decode(enc)

    click.echo("=" * 60)
    click.echo(" Research Plan Generation")
    click.echo("=" * 60)
    click.echo(f"Project: {project_id}  |  Objective: {objective}")
    click.echo("[*] Retrieving relevant security knowledge...")

    retriever = KnowledgeRetriever(db=db)
    planner = ResearchPlanner(db=db, retriever=retriever, settings=settings)

    try:
        plan = planner.plan(project_id=project_id, objective=objective, knowledge_limit=limit)
    except Exception as e:
        click.echo(f"[-] Planning error: {e}", err=True)
        sys.exit(1)

    if plan.warning:
        click.echo(f"[!] {plan.warning}")

    click.echo(f"\n[+] Knowledge Sources Retrieved ({len(plan.knowledge_sources)}):")
    for src in plan.knowledge_sources:
        click.echo(_safe(f"    - {src}"))

    if plan.relevant_concepts:
        click.echo("\n[+] Relevant Security Concepts:")
        for c in plan.relevant_concepts:
            click.echo(_safe(f"    - {c}"))

    if plan.suggested_hypotheses:
        click.echo("\n[+] Suggested Hypotheses (all start as UNTESTED):")
        for h in plan.suggested_hypotheses:
            click.echo(_safe(f"    - {h}"))

    if plan.evidence_needed:
        click.echo("\n[+] Evidence Needed (to be collected during authorized testing):")
        for e in plan.evidence_needed:
            click.echo(_safe(f"    - {e}"))

    if plan.validation_questions:
        click.echo("\n[+] Validation Questions:")
        for q in plan.validation_questions:
            click.echo(_safe(f"    - {q}"))

    if plan.potential_finding_categories:
        click.echo("\n[+] Potential Finding Categories to Investigate:")
        for cat in plan.potential_finding_categories:
            click.echo(_safe(f"    - {cat}"))

    click.echo("\n[*] SAFETY NOTE: This plan does not confirm any vulnerabilities.")
    click.echo("[*] The researcher performs all active testing within authorized scope.")
    click.echo("=" * 60)


@project_group.command("validate")
@click.argument("project_id", type=int)
@click.option("--hypothesis-id", type=int, default=None, help="Hypothesis ID to validate")
@click.option("--finding-id", type=int, default=None, help="Finding ID to validate")
@click.option("--evidence-id", "evidence_ids", multiple=True, type=int,
              help="Evidence IDs to include (repeat: --evidence-id 1 --evidence-id 2)")
@click.option("--no-ai", is_flag=True, help="Run validation using deterministic rules without calling Gemini")
@click.option("--sources-only", is_flag=True, help="Validate using local retrieval without calling Gemini")
def project_validate_cmd(project_id: int, hypothesis_id: Optional[int], finding_id: Optional[int],
                         evidence_ids, no_ai: bool, sources_only: bool):
    """Run Finding Validation Engine against researcher-supplied evidence and observations.

    Evaluates whether empirical evidence sufficiently supports the hypothesis or finding.
    Evidence is NEVER fabricated -- only researcher-provided evidence is analyzed.
    Missing evidence remains missing.

    Example:
        python app/main.py project validate 1 --hypothesis-id 1 --evidence-id 1
        python app/main.py project validate 1 --finding-id 1 --no-ai
    """
    if hypothesis_id is None and finding_id is None:
        click.echo("[-] Error: Must provide at least --hypothesis-id or --finding-id for validation.", err=True)
        sys.exit(1)

    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)

    from app.research.validation_assistant import ValidationAssistant
    from app.knowledge.retriever import KnowledgeRetriever

    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"

    def _safe(text: str) -> str:
        return text.encode(enc, errors="replace").decode(enc)

    click.echo("=" * 65)
    click.echo(" Finding Validation Engine (Phase 8)")
    click.echo("=" * 65)
    click.echo(f"Project ID:     {project_id}")
    if hypothesis_id is not None:
        click.echo(f"Hypothesis ID:  {hypothesis_id}")
    if finding_id is not None:
        click.echo(f"Finding ID:     {finding_id}")
    click.echo(f"Evidence IDs:   {list(evidence_ids) or '(none explicit)'}")
    click.echo("")

    retriever = KnowledgeRetriever(db=db)
    assistant = ValidationAssistant(db=db, retriever=retriever, settings=settings)

    try:
        result = assistant.validate(
            project_id=project_id,
            hypothesis_id=hypothesis_id,
            finding_id=finding_id,
            evidence_ids=list(evidence_ids),
            no_ai=no_ai,
            sources_only=sources_only,
        )
    except ValueError as e:
        click.echo(f"[-] Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"[-] Validation error: {e}", err=True)
        sys.exit(1)

    if result.scope_warning:
        click.echo(f"[!] SCOPE / AUTHORIZATION WARNING:\n    {result.scope_warning}\n")

    if result.warning and not result.scope_warning:
        click.echo(f"[*] Note: {result.warning}\n")

    strength_val = result.evidence_strength.value if hasattr(result.evidence_strength, "value") else str(result.evidence_strength)
    conf_val = result.confidence.value if hasattr(result.confidence, "value") else str(result.confidence)

    click.echo(f"[+] Classification:        {result.classification}")
    click.echo(f"[+] Evidence Strength:     {strength_val}")
    click.echo(f"[+] Confidence:            {conf_val}")
    click.echo(f"[+] Evidence Sufficient:   {result.is_evidence_sufficient}")
    click.echo(f"[+] Impact Logical:        {result.impact_logical}")

    if result.supporting_observations:
        click.echo(f"\n[+] Supporting Observations ({len(result.supporting_observations)}):")
        for i, s in enumerate(result.supporting_observations):
            obs_id_tag = f"[OBS-{result.supporting_observation_ids[i]}] " if i < len(result.supporting_observation_ids) else ""
            click.echo(_safe(f"    - {obs_id_tag}{s}"))

    if result.contradictory_observations:
        click.echo(f"\n[!] Contradictory Observations ({len(result.contradictory_observations)}):")
        for i, c in enumerate(result.contradictory_observations):
            obs_id_tag = f"[OBS-{result.contradictory_observation_ids[i]}] " if i < len(result.contradictory_observation_ids) else ""
            click.echo(_safe(f"    - {obs_id_tag}{c}"))

    if result.alternative_explanations:
        click.echo(f"\n[*] Alternative Explanations ({len(result.alternative_explanations)}):")
        for a in result.alternative_explanations:
            click.echo(_safe(f"    - {a}"))

    if result.missing_evidence:
        click.echo(f"\n[*] Missing Evidence Needed ({len(result.missing_evidence)}):")
        for m in result.missing_evidence:
            click.echo(_safe(f"    - {m}"))

    click.echo("\n[+] Impact Assessment:")
    click.echo(_safe(f"    - Observed Impact:    {result.observed_impact or 'None demonstrated directly'}"))
    click.echo(_safe(f"    - Potential Impact:   {result.potential_impact or 'None'}"))
    click.echo(_safe(f"    - Unsupported Impact: {result.unsupported_impact or 'None'}"))

    if result.validation_questions:
        click.echo(f"\n[*] Validation Questions ({len(result.validation_questions)}):")
        for q in result.validation_questions:
            click.echo(_safe(f"    - {q}"))

    click.echo(f"\n[+] Reasoning / Analysis:\n{_safe(result.reasoning)}")

    if result.relevant_sources:
        click.echo(f"\n[+] Reference Knowledge Sources ({len(result.relevant_sources)}):")
        for src in result.relevant_sources:
            click.echo(_safe(f"    - {src}"))

    click.echo("\n" + "=" * 65)
    click.echo("[*] EXPLICIT UPDATE POLICY:")
    click.echo(f"[*] Validation recorded in audit history (ID: #{result.validation_id}).")
    click.echo("[*] Finding and hypothesis records are NOT automatically overwritten.")
    if finding_id is not None:
        click.echo(f"[*] To apply this validation to Finding #{finding_id}, run:")
        click.echo(f"[*]   python app/main.py project finding-apply-validation {finding_id} --validation-id {result.validation_id}")
    click.echo("=" * 65)


@project_group.command("validation-history")
@click.argument("finding_id", type=int)
@click.option("--project-id", type=int, default=None, help="Optional project ID filter")
def project_validation_history_cmd(finding_id: int, project_id: Optional[int]):
    """Show immutable validation audit history for a finding."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()

    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"

    def _safe(text: str) -> str:
        return text.encode(enc, errors="replace").decode(enc)

    finding = db.get_finding(finding_id)
    if not finding:
        click.echo(f"[-] Finding ID {finding_id} not found.", err=True)
        sys.exit(1)

    proj_id = project_id or finding.get("project_id")
    validations = db.list_validations(project_id=proj_id, finding_id=finding_id)

    if not validations and finding.get("hypothesis_id"):
        validations = db.list_validations(project_id=proj_id, hypothesis_id=finding["hypothesis_id"])

    if not validations:
        click.echo(f"[*] No validation records found for finding ID {finding_id}.")
        return

    click.echo("=" * 70)
    click.echo(f" Validation Audit History: Finding {finding_id} ('{finding['title']}')")
    click.echo("=" * 70)
    for v in validations:
        supp = json.loads(v["supporting_observation_ids"]) if isinstance(v.get("supporting_observation_ids"), str) else v.get("supporting_observation_ids", [])
        contra = json.loads(v["contradictory_observation_ids"]) if isinstance(v.get("contradictory_observation_ids"), str) else v.get("contradictory_observation_ids", [])
        click.echo(_safe(f"Validation #{v['id']} | {str(v.get('created_at', ''))[:19]} | [{v['classification']}] [{v['evidence_strength']}] (Confidence: {v['confidence']})"))
        click.echo(f"  Supporting Obs: {len(supp or [])} | Contradictory Obs: {len(contra or [])}")
        click.echo(_safe(f"  Reasoning: {str(v.get('reasoning', ''))[:120]}..."))
        click.echo("-" * 70)
    click.echo(f"[+] Total validations: {len(validations)}")
    click.echo("=" * 70)


@project_group.command("finding-show")
@click.argument("finding_id", type=int)
def project_finding_show_cmd(finding_id: int):
    """Display comprehensive details and latest validation status for a finding."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()

    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"

    def _safe(text: str) -> str:
        return text.encode(enc, errors="replace").decode(enc)

    finding = db.get_finding(finding_id)
    if not finding:
        click.echo(f"[-] Finding ID {finding_id} not found.", err=True)
        sys.exit(1)

    latest_val = db.get_latest_validation(finding.get("project_id"), finding_id=finding_id)
    if not latest_val and finding.get("hypothesis_id"):
        latest_val = db.get_latest_validation(finding.get("project_id"), hypothesis_id=finding["hypothesis_id"])

    click.echo("=" * 70)
    click.echo(f" Finding #{finding['id']}: {finding['title']}")
    click.echo("=" * 70)
    click.echo(f"Project ID:         {finding.get('project_id')}")
    click.echo(f"Severity:           {finding.get('severity', 'Unknown')}")
    click.echo(f"Classification:     {finding.get('classification', 'UNCONFIRMED')}")
    click.echo(f"Validation Status:  {finding.get('validation_status', 'UNCONFIRMED')}")
    click.echo(f"Confidence:         {finding.get('confidence', 'LOW')}")
    click.echo(f"Affected Asset:     {finding.get('affected_asset') or 'N/A'}")
    if finding.get("summary"):
        click.echo(_safe(f"\nSummary:\n  {finding['summary']}"))
    if finding.get("technical_details"):
        click.echo(_safe(f"\nTechnical Details:\n  {finding['technical_details']}"))
    if finding.get("observed_impact"):
        click.echo(_safe(f"\nObserved Impact:\n  {finding['observed_impact']}"))
    if finding.get("potential_impact"):
        click.echo(_safe(f"\nPotential Impact:\n  {finding['potential_impact']}"))
    elif finding.get("impact"):
        click.echo(_safe(f"\nImpact:\n  {finding['impact']}"))
    if finding.get("root_cause"):
        click.echo(_safe(f"\nRoot Cause:\n  {finding['root_cause']}"))
    if finding.get("remediation"):
        click.echo(_safe(f"\nRemediation:\n  {finding['remediation']}"))

    ev_ids = finding.get("evidence_ids")
    if ev_ids:
        if isinstance(ev_ids, str):
            try:
                ev_ids = json.loads(ev_ids)
            except Exception:
                pass
        click.echo(f"\nLinked Evidence / Observation IDs: {ev_ids}")

    if latest_val:
        click.echo("\n" + "-" * 70)
        click.echo(f"Latest Validation Record: #{latest_val['id']} ({str(latest_val.get('created_at', ''))[:19]})")
        click.echo(f"  Classification:    {latest_val['classification']}")
        click.echo(f"  Evidence Strength: {latest_val['evidence_strength']}")
        click.echo(f"  Confidence:        {latest_val['confidence']}")
        click.echo(_safe(f"  Reasoning:         {latest_val.get('reasoning', '')}"))
    else:
        click.echo("\nLatest Validation Record: None (Use 'project validate' to evaluate this finding)")

    click.echo("=" * 70)


@project_group.command("finding-apply-validation")
@click.argument("finding_id", type=int)
@click.option("--project-id", type=int, default=None, help="Project ID (optional, looked up from finding)")
@click.option("--validation-id", type=int, default=None, help="Validation ID to apply (defaults to latest)")
def project_finding_apply_validation_cmd(finding_id: int, project_id: Optional[int], validation_id: Optional[int]):
    """Explicitly update a finding using an audited validation record.

    In accordance with the Explicit Finding Update Policy, validations are not
    silently written to findings. This command applies the validation results.
    """
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()

    finding = db.get_finding(finding_id)
    if not finding:
        click.echo(f"[-] Finding ID {finding_id} not found.", err=True)
        sys.exit(1)

    proj_id = project_id or finding.get("project_id")
    _get_project_or_exit(db, proj_id)

    from app.research.validation_assistant import ValidationAssistant
    from app.knowledge.retriever import KnowledgeRetriever

    retriever = KnowledgeRetriever(db=db)
    assistant = ValidationAssistant(db=db, retriever=retriever, settings=settings)

    old_class = finding.get("classification")
    old_status = finding.get("validation_status")

    try:
        updated = assistant.apply_validation_to_finding(proj_id, finding_id, validation_id=validation_id)
    except ValueError as e:
        click.echo(f"[-] Error: {e}", err=True)
        sys.exit(1)

    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"

    def _safe(text: str) -> str:
        return text.encode(enc, errors="replace").decode(enc)

    click.echo("=" * 65)
    click.echo(f" Finding #{finding_id} Updated with Validation")
    click.echo("=" * 65)
    click.echo(_safe(f"Title:             {updated['title']}"))
    click.echo(f"Classification:    {old_class} -> {updated['classification']}")
    click.echo(f"Validation Status: {old_status} -> {updated['validation_status']}")
    click.echo(f"Confidence:        {updated['confidence']}")
    if updated.get("observed_impact"):
        click.echo(_safe(f"Observed Impact:   {updated['observed_impact']}"))
    if updated.get("potential_impact"):
        click.echo(_safe(f"Potential Impact:  {updated['potential_impact']}"))
    if updated.get("evidence_ids"):
        click.echo(f"Linked Evidence:   {updated['evidence_ids']}")
    click.echo("=" * 65)


# -----------------------------------------------------------------
# Phase 6: Orchestration & Project Context Commands
# -----------------------------------------------------------------

@project_group.command("context")
@click.argument("project_id", type=int)
def project_context_cmd(project_id: int):
    """Display bounded structured project context snapshot."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)

    from app.research.context import ProjectContextBuilder, format_context_summary
    from app.knowledge.retriever import KnowledgeRetriever

    retriever = KnowledgeRetriever(db=db)
    builder = ProjectContextBuilder(db=db, retriever=retriever)
    context = builder.build_context(project_id, include_knowledge=True)

    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"

    def _safe(text: str) -> str:
        return text.encode(enc, errors="replace").decode(enc)

    click.echo(_safe(format_context_summary(context)))


@project_group.command("health")
@click.argument("project_id", type=int)
def project_health_cmd(project_id: int):
    """Evaluate project workflow health, bottlenecks, and readiness."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)

    from app.research.context import ProjectContextBuilder, evaluate_project_health

    builder = ProjectContextBuilder(db=db, retriever=None)
    context = builder.build_context(project_id, include_knowledge=False)
    health = evaluate_project_health(context)

    click.echo("=" * 60)
    click.echo(f" Project Health: {context.project.name} (ID: {project_id})")
    click.echo("=" * 60)
    click.echo(f"Overall State:     {health.overall_state.value}")
    click.echo(f"Scope Status:      {health.scope_status}")
    click.echo(f"Objective Status:  {health.objective_status}")
    click.echo(f"Hypothesis Status: {health.hypothesis_status}")
    click.echo(f"Evidence Status:   {health.evidence_status}")
    click.echo(f"Finding Status:    {health.finding_status}")

    if health.blockers:
        click.echo("\n[!] Critical Blockers:")
        for b in health.blockers:
            click.echo(f"    - {b}")

    if health.warnings:
        click.echo("\n[*] Workflow Warnings:")
        for w in health.warnings:
            click.echo(f"    - {w}")

    click.echo("\n[*] Note: Workflow status measures research readiness, not an arbitrary security score.")
    click.echo("=" * 60)


@project_group.command("next")
@click.argument("project_id", type=int)
@click.option("--limit", default=3, type=int, help="Maximum number of recommendations to display")
@click.option("--sources-only", is_flag=True, help="Use deterministic state + local retrieval without calling Gemini")
def project_next_cmd(project_id: int, limit: int, sources_only: bool):
    """Determine what the human researcher should investigate next.

    Synthesizes project context, health, and local knowledge to suggest
    prioritized inquiries and evidence to collect.
    """
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)

    from app.research.orchestrator import ResearchOrchestrator
    from app.knowledge.retriever import KnowledgeRetriever

    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"

    def _safe(text: str) -> str:
        return text.encode(enc, errors="replace").decode(enc)

    retriever = KnowledgeRetriever(db=db)
    orchestrator = ResearchOrchestrator(db=db, retriever=retriever, settings=settings)

    click.echo("=" * 65)
    click.echo(" Research Orchestrator: Next Steps")
    click.echo("=" * 65)

    try:
        result = orchestrator.orchestrate(project_id, limit=limit, sources_only=sources_only)
    except Exception as e:
        click.echo(f"[-] Orchestration error: {e}", err=True)
        sys.exit(1)

    click.echo(f"Project State:  {result.health.overall_state.value}")
    click.echo(f"Summary:        {_safe(result.project_state_summary)}")
    click.echo("")

    if result.blockers:
        click.echo("[!] Blockers:")
        for b in result.blockers:
            click.echo(_safe(f"    - {b}"))
        click.echo("")

    if result.warnings:
        click.echo("[*] Warnings:")
        for w in result.warnings:
            click.echo(_safe(f"    - {w}"))
        click.echo("")

    click.echo(f"[+] Recommended Next Actions ({len(result.recommendations)}):")
    click.echo("-" * 65)
    for i, rec in enumerate(result.recommendations, 1):
        click.echo(_safe(f"{i}. [{rec.priority}] {rec.title}"))
        click.echo(_safe(f"   Rationale: {rec.rationale}"))
        if rec.evidence_needed:
            click.echo(_safe(f"   Evidence to Collect: {', '.join(rec.evidence_needed)}"))
        if rec.validation_questions:
            click.echo(_safe(f"   Validation Questions: {', '.join(rec.validation_questions)}"))
        if rec.blockers:
            click.echo(_safe(f"   Blockers: {', '.join(rec.blockers)}"))
        click.echo("")

    click.echo("=" * 65)
    click.echo("[+] Next Best Research Question:")
    click.echo(_safe(f"    \"{result.next_best_question}\""))
    click.echo("=" * 65)

    if result.relevant_sources:
        click.echo("\n[+] Relevant Knowledge Base References:")
        for src in result.relevant_sources:
            click.echo(_safe(f"    - {src}"))

    click.echo("\n[*] HUMAN-IN-THE-LOOP CHECKPOINT:")
    click.echo("[*] The researcher conducts all active testing. The assistant never interacts with targets.")
    click.echo("=" * 65)


# -----------------------------------------------------------------
# Phase 7: Evidence Intelligence & Artifact Analysis Commands
# -----------------------------------------------------------------

@project_group.command("evidence-import")
@click.argument("project_id", type=int)
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--no-ai", is_flag=True, help="Parse and normalize without calling Gemini AI analyzer")
@click.option("--hypothesis-id", type=int, default=None, help="Link extracted observations to a hypothesis")
def project_evidence_import_cmd(project_id: int, file_path: str, no_ai: bool, hypothesis_id: Optional[int]):
    """Import and parse a researcher-supplied evidence artifact (HTTP, HAR, JSON, log, code)."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)

    from app.research.evidence.ingestion import EvidenceIngestionService
    from pathlib import Path

    service = EvidenceIngestionService(db=db, settings=settings)

    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"

    def _safe(text: str) -> str:
        return text.encode(enc, errors="replace").decode(enc)

    try:
        artifact, normalized, analysis = service.ingest_file(
            project_id=project_id,
            file_path=Path(file_path),
            hypothesis_id=hypothesis_id,
            use_ai=not no_ai,
        )
    except Exception as e:
        click.echo(f"[-] Evidence import failed: {e}", err=True)
        sys.exit(1)

    is_dup = analysis.get("is_duplicate", False)
    if is_dup:
        click.echo(f"[*] DUPLICATE ARTIFACT: Content matches existing artifact ID {artifact['id']}.")
        click.echo(f"[*] Reusing {len(normalized.observations)} previously extracted observations.")
    else:
        click.echo(f"[+] Artifact '{artifact['filename']}' successfully imported (ID: {artifact['id']}).")
        click.echo(f"    Type: {artifact['artifact_type']}  |  Size: {artifact['size_bytes']} bytes")
        click.echo(f"    SHA-256: {artifact['content_hash'][:16]}...")
        click.echo(f"[+] Extracted {len(normalized.observations)} factual observation(s):")
        for obs in normalized.observations:
            click.echo(_safe(f"    - [{obs.category.value}] {obs.statement}"))

        if analysis and not is_dup:
            click.echo("\n[+] Evidence Analysis Summary:")
            click.echo(_safe(f"    {analysis.get('summary', '')}"))
            if analysis.get("technical_context"):
                click.echo(_safe(f"\n[+] Technical Context:\n    {analysis['technical_context']}"))
            if analysis.get("missing_aspects"):
                click.echo("\n[*] Missing Evidence Needed for Validation:")
                for m in analysis["missing_aspects"]:
                    click.echo(_safe(f"    - {m}"))

    click.echo("\n[*] OBSERVATION != VULNERABILITY:")
    click.echo("[*] Observations represent static facts. Run 'project validate' to test against hypotheses.")


@project_group.command("artifacts")
@click.argument("project_id", type=int)
def project_artifacts_cmd(project_id: int):
    """List imported evidence artifacts for a project."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)

    artifacts = db.list_evidence_artifacts(project_id)
    if not artifacts:
        click.echo(f"[*] No evidence artifacts imported for project {project_id}.")
        return

    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"

    def _safe(text: str) -> str:
        return text.encode(enc, errors="replace").decode(enc)

    click.echo(f"[+] Evidence Artifacts for project {project_id} ({len(artifacts)} items):")
    click.echo(f"{'ID':<4} {'Type':<14} {'Size':<10} {'Filename':<35} {'SHA-256'}")
    click.echo("-" * 75)
    for a in artifacts:
        click.echo(_safe(f"{a['id']:<4} {a['artifact_type']:<14} {a['size_bytes']:<10} {a['filename']:<35} {a['content_hash'][:12]}..."))


@project_group.command("observations")
@click.argument("project_id", type=int)
@click.option("--artifact-id", type=int, default=None, help="Filter by artifact ID")
@click.option("--hypothesis-id", type=int, default=None, help="Filter by hypothesis ID")
def project_observations_cmd(project_id: int, artifact_id: Optional[int], hypothesis_id: Optional[int]):
    """List structured factual observations extracted from evidence artifacts."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)

    observations = db.list_observations(project_id, artifact_id=artifact_id, hypothesis_id=hypothesis_id)
    if not observations:
        click.echo(f"[*] No observations found for project {project_id}.")
        return

    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"

    def _safe(text: str) -> str:
        return text.encode(enc, errors="replace").decode(enc)

    click.echo(f"[+] Structured Observations ({len(observations)} items):")
    click.echo("-" * 75)
    for o in observations:
        hyp_tag = f" [Hypothesis: {o['hypothesis_id']}]" if o.get("hypothesis_id") else ""
        loc_tag = f" ({o['source_location']})" if o.get("source_location") else ""
        click.echo(_safe(f"ID:{o['id']} [{o['category']}]{loc_tag}{hyp_tag}"))
        click.echo(_safe(f"   {o['statement']}"))


@project_group.command("artifact-show")
@click.argument("artifact_id", type=int)
def project_artifact_show_cmd(artifact_id: int):
    """Display details and extracted observations for a specific evidence artifact."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()

    artifact = db.get_evidence_artifact(artifact_id)
    if not artifact:
        click.echo(f"[-] Artifact ID {artifact_id} not found.", err=True)
        sys.exit(1)

    observations = db.list_observations(artifact["project_id"], artifact_id=artifact_id)

    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"

    def _safe(text: str) -> str:
        return text.encode(enc, errors="replace").decode(enc)

    click.echo("=" * 65)
    click.echo(f" Artifact Details: {artifact['filename']} (ID: {artifact['id']})")
    click.echo("=" * 65)
    click.echo(f"Project ID:    {artifact['project_id']}")
    click.echo(f"Artifact Type: {artifact['artifact_type']}")
    click.echo(f"File Size:     {artifact['size_bytes']} bytes")
    click.echo(f"Source Path:   {artifact.get('source_path') or '(direct input)'}")
    click.echo(f"SHA-256 Hash:  {artifact['content_hash']}")
    click.echo(f"Imported At:   {str(artifact.get('created_at', ''))[:19]}")

    click.echo(f"\n[+] Extracted Observations ({len(observations)}):")
    for o in observations:
        loc = f" ({o['source_location']})" if o.get("source_location") else ""
        click.echo(_safe(f"  - [{o['category']}]{loc}: {o['statement']}"))
    click.echo("=" * 65)


@project_group.command("evidence-link")
@click.argument("project_id", type=int)
@click.option("--artifact-id", type=int, required=True, help="Artifact ID to link")
@click.option("--hypothesis-id", type=int, required=True, help="Hypothesis ID to link to")
def project_evidence_link_cmd(project_id: int, artifact_id: int, hypothesis_id: int):
    """Link an evidence artifact's observations to a research hypothesis."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()
    _get_project_or_exit(db, project_id)

    hyp = db.get_hypothesis(hypothesis_id)
    if not hyp:
        click.echo(f"[-] Hypothesis ID {hypothesis_id} not found.", err=True)
        sys.exit(1)

    art = db.get_evidence_artifact(artifact_id)
    if not art:
        click.echo(f"[-] Artifact ID {artifact_id} not found.", err=True)
        sys.exit(1)

    count = db.link_artifact_to_hypothesis(artifact_id, hypothesis_id)
    db.log_activity(
        project_id,
        "EVIDENCE_LINKED",
        f"Linked artifact {artifact_id} ({count} observations) to hypothesis {hypothesis_id}",
    )
    click.echo(f"[+] Successfully linked artifact {artifact_id} ({count} observations) to hypothesis {hypothesis_id} ('{hyp['title']}').")


# -----------------------------------------------------------------
# Phase 9: Security Report CLI Commands
# -----------------------------------------------------------------

@project_group.command("report")
@click.argument("finding_id", type=int)
@click.option(
    "--template-type",
    type=click.Choice(["BUG_BOUNTY", "INTERNAL", "RESEARCH_VALIDATION"], case_sensitive=False),
    default="BUG_BOUNTY",
    help="Report template structure (BUG_BOUNTY, INTERNAL, RESEARCH_VALIDATION)",
)
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["MARKDOWN", "JSON"], case_sensitive=False),
    default="MARKDOWN",
    help="Output format (MARKDOWN or JSON)",
)
@click.option("--no-ai", is_flag=True, help="Use deterministic report synthesis without calling Gemini")
@click.option("--validation-id", type=int, default=None, help="Explicit validation ID to base report on")
def project_report_cmd(finding_id: int, template_type: str, report_format: str, no_ai: bool, validation_id: Optional[int]):
    """Generate an authoritative, evidence-grounded security report for a finding."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()

    finding = db.get_finding(finding_id)
    if not finding:
        click.echo(f"[-] Finding ID {finding_id} not found.", err=True)
        sys.exit(1)

    from app.reporting.report_generator import ReportGenerator
    from app.research.models import ReportTemplateType, ReportFormat
    from app.knowledge.retriever import KnowledgeRetriever

    retriever = KnowledgeRetriever(db=db)
    generator = ReportGenerator(db=db, retriever=retriever, settings=settings)

    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"

    def _safe(text: str) -> str:
        return text.encode(enc, errors="replace").decode(enc)

    tmpl_enum = ReportTemplateType(template_type.upper())
    fmt_enum = ReportFormat(report_format.upper())

    click.echo(f"[*] Generating {tmpl_enum.value} report for finding #{finding_id}...")
    try:
        report = generator.generate_report(
            finding_id=finding_id,
            template_type=tmpl_enum,
            format=fmt_enum,
            validation_id=validation_id,
            use_ai=not no_ai,
        )
    except Exception as e:
        click.echo(f"[-] Failed to generate report: {e}", err=True)
        sys.exit(1)

    click.echo("=" * 70)
    click.echo(f"[+] Security Report Generated: #{report.id} (Revision v{report.version})")
    click.echo(f"    Title:         {_safe(report.title)}")
    click.echo(f"    Template:      {report.template_type.value}")
    click.echo(f"    Status:        {report.status.value}")
    click.echo(f"    Format:        {report.format.value}")
    click.echo(f"    Content Hash:  {report.content_hash[:16]}...")
    click.echo(f"    Citations:     {len(report.citations)} observation(s) linked")
    if report.analysis and report.analysis.warnings:
        click.echo("\n[!] Report Warnings:")
        for w in report.analysis.warnings:
            click.echo(_safe(f"    - {w}"))
    click.echo("=" * 70)
    click.echo("\n[+] Report Preview:\n")
    click.echo(_safe(report.content[:800]))
    if len(report.content) > 800:
        click.echo(_safe(f"\n... [{len(report.content) - 800} bytes truncated. Use 'project report-show {report.id}' to view full report]"))
    click.echo("\n[*] Next Steps:")
    click.echo(f"    - View full report:     python app/main.py project report-show {report.id}")
    click.echo(f"    - Approve report:       python app/main.py project report-approve {report.id}")
    click.echo(f"    - Export report:        python app/main.py project report-export {report.id} --output-path report.md")


@project_group.command("report-show")
@click.argument("report_id", type=int)
def project_report_show_cmd(report_id: int):
    """Display the full content of a security report."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()

    report = db.get_report(report_id)
    if not report:
        click.echo(f"[-] Report ID {report_id} not found.", err=True)
        sys.exit(1)

    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"

    def _safe(text: str) -> str:
        return text.encode(enc, errors="replace").decode(enc)

    click.echo(_safe(report["content"]))


@project_group.command("report-history")
@click.argument("finding_id", type=int)
def project_report_history_cmd(finding_id: int):
    """List revision history of generated security reports for a finding."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()

    finding = db.get_finding(finding_id)
    if not finding:
        click.echo(f"[-] Finding ID {finding_id} not found.", err=True)
        sys.exit(1)

    reports = db.list_reports(finding_id=finding_id)
    if not reports:
        click.echo(f"[*] No reports generated for finding #{finding_id} yet.")
        return

    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"

    def _safe(text: str) -> str:
        return text.encode(enc, errors="replace").decode(enc)

    click.echo(f"[+] Security Report History for Finding #{finding_id} ('{finding['title']}'):")
    click.echo(f"{'ID':<4} {'Ver':<5} {'Template':<16} {'Status':<12} {'Format':<10} {'Approved By':<20} {'Created At'}")
    click.echo("-" * 85)
    for r in reports:
        appr = r.get("approved_by") or "(Pending)"
        click.echo(_safe(
            f"{r['id']:<4} v{r['version']:<4} {r['template_type']:<16} {r['status']:<12} {r['format']:<10} {appr:<20} {str(r.get('created_at', ''))[:19]}"
        ))


@project_group.command("report-approve")
@click.argument("report_id", type=int)
@click.option("--reviewer", default="Lead Security Researcher", help="Reviewer identifier or name")
def project_report_approve_cmd(report_id: int, reviewer: str):
    """Approve a security report (transitions status to APPROVED)."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()

    from app.reporting.report_generator import ReportGenerator
    generator = ReportGenerator(db=db, settings=settings)

    try:
        updated = generator.approve_report(report_id, reviewer=reviewer)
    except Exception as e:
        click.echo(f"[-] Error approving report: {e}", err=True)
        sys.exit(1)

    click.echo(f"[+] Report #{report_id} v{updated['version']} has been APPROVED by '{reviewer}'.")
    click.echo(f"    Status:      {updated['status']}")
    click.echo(f"    Approved At: {updated['approved_at']}")


@project_group.command("report-export")
@click.argument("report_id", type=int)
@click.option("--format", "report_format", type=click.Choice(["markdown", "json"], case_sensitive=False), default="markdown")
@click.option("--output-path", type=click.Path(), default=None, help="File path to save the exported report")
def project_report_export_cmd(report_id: int, report_format: str, output_path: Optional[str]):
    """Export a security report to stdout or file, transitioning status to EXPORTED."""
    settings = get_settings()
    db = DatabaseManager(settings.database_path)
    db.init_db()

    from app.reporting.report_generator import ReportGenerator
    generator = ReportGenerator(db=db, settings=settings)

    try:
        content = generator.export_report(report_id, format=report_format, output_path=output_path)
    except Exception as e:
        click.echo(f"[-] Error exporting report: {e}", err=True)
        sys.exit(1)

    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"

    def _safe(text: str) -> str:
        return text.encode(enc, errors="replace").decode(enc)

    if output_path:
        click.echo(f"[+] Successfully exported report #{report_id} to '{output_path}'.")
    else:
        click.echo(_safe(content))


# -----------------------------------------------------------------
# Placeholder Commands for Future Phases
# -----------------------------------------------------------------

@cli.group("scope")
def scope_group():
    """Scope analysis commands."""
    pass


@scope_group.command("analyze")
@click.argument("scope_file", type=click.Path(exists=True))
def scope_analyze_cmd(scope_file: str):
    """Analyze engagement scope and policy constraints."""
    click.echo(f"[*] Scope analysis for '{scope_file}' will be implemented in Phase 6.")


@cli.command("analyze")
@click.argument("evidence_file", type=click.Path(exists=True))
def analyze_cmd(evidence_file: str):
    """Analyze provided evidence against security boundaries."""
    click.echo(f"[*] Evidence analysis for '{evidence_file}' will be implemented in Phase 8.")


@cli.group("finding")
def finding_group():
    """Finding validation commands."""
    pass


@finding_group.command("validate")
@click.argument("finding_file", type=click.Path(exists=True))
def finding_validate_cmd(finding_file: str):
    """Validate and attempt to falsify a suspected finding."""
    click.echo(f"[*] Finding validation for '{finding_file}' will be implemented in Phase 9.")


@cli.command("report")
@click.argument("finding_id", type=str)
@click.option(
    "--template-type",
    type=click.Choice(["BUG_BOUNTY", "INTERNAL", "RESEARCH_VALIDATION"], case_sensitive=False),
    default="BUG_BOUNTY",
    help="Report template structure",
)
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["MARKDOWN", "JSON"], case_sensitive=False),
    default="MARKDOWN",
    help="Output format (MARKDOWN or JSON)",
)
@click.option("--no-ai", is_flag=True, help="Use deterministic report synthesis without calling Gemini")
@click.pass_context
def report_cmd(ctx, finding_id: str, template_type: str, report_format: str, no_ai: bool):
    """Generate professional security report from a finding."""
    if str(finding_id).isdigit():
        ctx.invoke(
            project_report_cmd,
            finding_id=int(finding_id),
            template_type=template_type,
            report_format=report_format,
            no_ai=no_ai,
            validation_id=None,
        )
    else:
        click.echo(f"[*] Report generation for finding '{finding_id}' will be implemented in Phase 10.")




# ===========================================================================
# Phase 10: EVALUATE command group
# ===========================================================================


@cli.group("evaluate", invoke_without_command=True)
@click.option("--offline", "offline_mode", is_flag=True, default=True)
@click.option("--ai", "ai_mode", is_flag=True, default=False)
@click.option("--scenario", "scenario_id", default=None, help="Single scenario ID (e.g. A1, D3).")
@click.option("--category", default=None, help="Category prefix (A-G).")
@click.option("--limit", default=None, type=int)
@click.option("--verbose", is_flag=True, default=False)
@click.option("--json", "output_json", is_flag=True, default=False)
@click.option("--save", default=None)
@click.pass_context
def evaluate_group(ctx, offline_mode, ai_mode, scenario_id, category, limit, verbose, output_json, save):
    """Run Phase 10 synthetic security evaluation benchmark.

    Zero real-target interaction. Zero network traffic in offline mode.

    Examples:
      python app/main.py evaluate --offline
      python app/main.py evaluate --scenario D1 --verbose
      python app/main.py evaluate --category G
      python app/main.py evaluate --save report.md
    """
    if ctx.invoked_subcommand is not None:
        return
    _run_evaluate(
        offline_mode=offline_mode, ai_mode=ai_mode,
        scenario_ids=[scenario_id] if scenario_id else None,
        category=category, limit=limit, verbose=verbose,
        output_json=output_json, save=save,
    )


def _run_evaluate(offline_mode, ai_mode, scenario_ids, category, limit, verbose, output_json, save):
    """Shared evaluation execution."""
    from app.evaluation.models import EvalRunConfig
    from app.evaluation.runner import run_evaluation
    from app.evaluation.reports import format_json_report, save_report as _save_report

    config = EvalRunConfig(
        offline_mode=True,
        ai_mode=ai_mode and not offline_mode,
        scenario_ids=scenario_ids,
        category_filter=category,
        limit=limit,
        verbose=verbose,
    )

    click.echo("=" * 60)
    click.echo(" PENTRARE CONTROLLED EVALUATION")
    click.echo(" Agentic Security Researcher - Phase 10 Benchmark")
    click.echo("=" * 60)
    mode_str = "OFFLINE SYNTHETIC" if config.offline_mode else "AI-ASSISTED"
    click.echo(f" Mode:     {mode_str}")
    click.echo(f" Category: {config.category_filter or 'All'}")
    click.echo(f" Limit:    {config.limit or 'None'}")
    click.echo("")

    report = run_evaluation(config)
    m = report.metrics

    click.echo(f"Scenarios:                  {m.total_scenarios}")
    click.echo(f"Passed:                     {m.passed_scenarios}")
    click.echo(f"Failed:                     {m.failed_scenarios}")
    click.echo("")
    click.echo(f"Classification Accuracy:    {m.classification_exact_match:.1%} exact / {m.classification_acceptable_range:.1%} range")
    click.echo(f"Evidence Strength Accuracy: {m.evidence_strength_exact:.1%}")
    click.echo(f"Citation Precision/Recall:  {m.citation_precision:.1%} / {m.citation_recall:.1%}")
    click.echo(f"Contradiction Detection:    {m.contradiction_detection_rate:.1%}")
    click.echo(f"Missing Evidence Detection: {m.missing_evidence_detection_rate:.1%}")
    click.echo(f"Impact Grounding:           {m.impact_grounding_rate:.1%}")
    click.echo("")
    click.echo(f"False Confirmation Rate:    {m.false_confirmation_rate:.1%} ({m.false_confirmation_count} confirmations)")
    if m.false_confirmation_scenario_ids:
        ids_str = ", ".join(m.false_confirmation_scenario_ids)
        click.echo(f"  Affected scenarios:       {ids_str}")
    click.echo(f"False Negative Rate:        {m.false_negative_rate:.1%} ({m.false_negative_count} missed)")
    click.echo("")

    inj_result = "PASS" if m.injection_resistance_rate >= 1.0 else "FAIL"
    sec_result = "PASS" if m.secret_redaction_rate >= 1.0 else "FAIL"
    click.echo(f"Prompt Injection Resistance:{m.injection_resistance_rate:.1%} [{inj_result}]")
    click.echo(f"Secret Redaction:           {m.secret_redaction_rate:.1%} [{sec_result}]")
    click.echo("")

    if m.retrieval and m.retrieval.query_count > 0:
        r = m.retrieval
        click.echo(
            f"Retrieval Recall@5:  Lex={r.recall_at_5_lexical:.1%}"
            f" Sem={r.recall_at_5_semantic:.1%} Hyb={r.recall_at_5_hybrid:.1%}"
        )
        click.echo(
            f"Retrieval MRR:       Lex={r.mrr_lexical:.3f}"
            f" Sem={r.mrr_semantic:.3f} Hyb={r.mrr_hybrid:.3f}"
        )
        click.echo("")

    click.echo(f"Runtime:                    {m.total_runtime_ms:.0f} ms")
    click.echo("")

    if report.critical_failures:
        click.echo("CRITICAL FAILURES:")
        for f in report.critical_failures:
            click.echo(f"  !! {f}")
        click.echo("")

    if report.warnings:
        click.echo("WARNINGS:")
        for w in report.warnings:
            click.echo(f"  ~~ {w}")
        click.echo("")

    if verbose:
        click.echo("Per-Scenario Results:")
        for r in report.scenario_results:
            status = "PASS" if r.passed else "FAIL"
            reason = r.failure_reasons[0][:50] if r.failure_reasons else ""
            pred = r.predicted_classification or "N/A"
            click.echo(f"  {r.scenario_id:<6} {r.category.value:<22} {status:<6} {pred:<18} {reason}")
        click.echo("")

    click.echo("=" * 60)
    click.echo(f"Overall:  {report.verdict.value}")
    click.echo("=" * 60)

    if save:
        saved = _save_report(report, Path(save))
        click.echo(f"[+] Markdown report: {saved}")
        json_path = saved.with_suffix(".json")
        click.echo(f"[+] JSON report:     {json_path}")

    if output_json:
        click.echo(format_json_report(report))


@evaluate_group.command("retrieval")
def evaluate_retrieval_cmd():
    """Evaluate hybrid retrieval quality against the knowledge base."""
    from app.evaluation.runner import _evaluate_retrieval
    from app.evaluation.models import EvalRunConfig
    config = EvalRunConfig(offline_mode=True)
    click.echo("[*] Running retrieval evaluation...")
    metrics = _evaluate_retrieval(config)
    if metrics and metrics.query_count > 0:
        click.echo(f"Queries:   {metrics.query_count}")
        click.echo(
            f"Recall@5   Lex={metrics.recall_at_5_lexical:.1%}"
            f" Sem={metrics.recall_at_5_semantic:.1%} Hyb={metrics.recall_at_5_hybrid:.1%}"
        )
        click.echo(
            f"Prec@5     Lex={metrics.precision_at_5_lexical:.1%}"
            f" Sem={metrics.precision_at_5_semantic:.1%} Hyb={metrics.precision_at_5_hybrid:.1%}"
        )
        click.echo(
            f"MRR        Lex={metrics.mrr_lexical:.3f}"
            f" Sem={metrics.mrr_semantic:.3f} Hyb={metrics.mrr_hybrid:.3f}"
        )
        if metrics.notes:
            click.echo(f"Note:      {metrics.notes}")
    else:
        note = metrics.notes if metrics else "unknown"
        click.echo(f"[-] Retrieval unavailable: {note}")


@evaluate_group.command("validation")
@click.option("--limit", default=None, type=int)
def evaluate_validation_cmd(limit):
    """Evaluate validation accuracy (strong finding scenarios)."""
    _run_evaluate(offline_mode=True, ai_mode=False, scenario_ids=None,
                  category="D", limit=limit, verbose=True, output_json=False, save=None)


@evaluate_group.command("reports")
@click.option("--limit", default=None, type=int)
def evaluate_reports_cmd(limit):
    """Evaluate report quality across all scenarios."""
    _run_evaluate(offline_mode=True, ai_mode=False, scenario_ids=None,
                  category=None, limit=limit, verbose=True, output_json=False, save=None)


@evaluate_group.command("security")
def evaluate_security_cmd():
    """Evaluate security controls: injection resistance and secret redaction."""
    _run_evaluate(offline_mode=True, ai_mode=False, scenario_ids=None,
                  category="G", limit=None, verbose=True, output_json=False, save=None)


# ===========================================================================
# Phase 10: PENTRARE command group
# ===========================================================================


@cli.group("pentrare", invoke_without_command=True)
@click.pass_context
def pentrare_group(ctx):
    """Pentrare controlled synthetic benchmark (NOT real target testing).

    Equivalent to 'evaluate --offline'. Zero network traffic.
    """
    if ctx.invoked_subcommand is None:
        click.echo("[*] Use 'pentrare test' to run the controlled benchmark.")


@pentrare_group.command("test")
@click.option("--verbose", is_flag=True, default=False)
@click.option("--save", default=None)
@click.option("--json", "output_json", is_flag=True, default=False)
def pentrare_test_cmd(verbose, save, output_json):
    """Run the full PENTRARE controlled synthetic security benchmark.

    NOT a penetration test. Evaluates 25 offline scenarios with fixed
    ground truth. Reports FCR, FNR, Injection Resistance, Secret Redaction,
    and PASS/WARN/FAIL verdict.
    """
    _run_evaluate(offline_mode=True, ai_mode=False, scenario_ids=None,
                  category=None, limit=None, verbose=verbose,
                  output_json=output_json, save=save or "evaluation_report.md")


# ===========================================================================
# Phase 10: DOCTOR command
# ===========================================================================


@cli.command("doctor")
def doctor_cmd():
    """System health diagnostic.

    Checks Python, dependencies, database, knowledge base, vector store,
    embedding model, Gemini key, configuration, and submodule integrity.
    Returns PASS / WARN / FAIL for each item.
    """
    import platform
    import subprocess as _subprocess

    items = []

    def _chk(label, passed, detail="", critical=True):
        status = "PASS" if passed else ("FAIL" if critical else "WARN")
        items.append((label, status, detail))
        return passed

    click.echo("=" * 60)
    click.echo(" Agentic Security Researcher - System Health Check")
    click.echo("=" * 60)
    click.echo("")

    py_ver = platform.python_version()
    py_ok = tuple(int(x) for x in py_ver.split(".")[:2]) >= (3, 10)
    _chk("Python Version", py_ok, f"v{py_ver} (need >= 3.10)")

    for dep in ["click", "pydantic", "fastembed", "rank_bm25"]:
        try:
            __import__(dep)
            _chk(f"Dep: {dep}", True, "installed")
        except ImportError:
            _chk(f"Dep: {dep}", False, "NOT installed")

    try:
        settings = get_settings()
        db_exists = settings.database_path.exists()
        _chk("Database File", db_exists, str(settings.database_path))
        if db_exists:
            db = DatabaseManager(settings.database_path)
            with db.get_connection() as conn:
                doc_count = conn.execute(
                    "SELECT COUNT(*) FROM documents WHERE status='active'"
                ).fetchone()[0]
                chunk_count = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
            _chk("Knowledge Docs", doc_count >= 230, f"{doc_count} (expected 232)", critical=False)
            _chk("Knowledge Chunks", chunk_count >= 7800, f"{chunk_count} (expected 7817)", critical=False)
    except Exception as exc:
        _chk("Database", False, str(exc))

    try:
        settings = get_settings()
        vs = settings.vector_store_path
        if vs.exists():
            mb = vs.stat().st_size // (1024 * 1024)
            _chk("Vector Store", True, f"{mb} MB")
        else:
            _chk("Vector Store", False, "Missing - run knowledge ingest", critical=False)
    except Exception as exc:
        _chk("Vector Store", False, str(exc), critical=False)

    try:
        from app.knowledge.embeddings import EmbeddingGenerator
        gen = EmbeddingGenerator()
        vecs = gen.embed_texts(["health"])
        _chk("Embedding Model", len(vecs) > 0, "BAAI/bge-small-en-v1.5 OK")
    except Exception as exc:
        _chk("Embedding Model", False, str(exc), critical=False)

    try:
        settings = get_settings()
        key_info = "Configured" if settings.has_gemini_key else "Not set"
        _chk("Gemini API Key", settings.has_gemini_key, key_info, critical=False)
    except Exception as exc:
        _chk("Gemini API Key", False, str(exc), critical=False)

    try:
        settings = get_settings()
        pe_dir = settings.knowledge_dir / "PentestingEverything"
        if pe_dir.exists():
            proc = _subprocess.run(
                ["git", "-C", str(pe_dir), "status", "--porcelain"],
                capture_output=True, text=True, timeout=10,
            )
            clean = proc.returncode == 0 and not proc.stdout.strip()
            detail = "Clean (unmodified)" if clean else f"DIRTY: {proc.stdout.strip()[:60]}"
            _chk("PentestingEverything", clean, detail)
        else:
            _chk("PentestingEverything", False, f"Not found: {pe_dir}", critical=False)
    except Exception as exc:
        _chk("PentestingEverything", False, str(exc), critical=False)

    try:
        settings = get_settings()
        _chk("Configuration", True, f"env={settings.app_env}")
    except Exception as exc:
        _chk("Configuration", False, str(exc))

    click.echo("")
    any_fail = any_warn = False
    for label, status, detail in items:
        icon = {"PASS": "[PASS]", "WARN": "[WARN]", "FAIL": "[FAIL]"}[status]
        click.echo(f"  {icon:<8} {label:<36} {detail}")
        if status == "FAIL":
            any_fail = True
        elif status == "WARN":
            any_warn = True

    click.echo("")
    click.echo("=" * 60)
    if any_fail:
        click.echo("Overall: FAIL - one or more critical checks failed.")
    elif any_warn:
        click.echo("Overall: WARN - non-critical issues detected.")
    else:
        click.echo("Overall: PASS - all checks passed.")
    click.echo("=" * 60)


# ===========================================================================
# Phase 11: BACKUP & RESTORE commands
# ===========================================================================


@cli.command("backup")
@click.option("--dest", default=None, help="Custom destination directory for backup.")
def backup_cmd(dest):
    """Create an atomic backup of the database and vector store."""
    from app.storage.backup import create_backup
    from pathlib import Path

    click.echo("=" * 60)
    click.echo(" Agentic Security Researcher - Backup System")
    click.echo("=" * 60)
    click.echo("[*] Creating atomic database and vector store backup...")

    dest_path = Path(dest) if dest else None
    result = create_backup(destination_dir=dest_path)

    m = result["manifest"]
    click.echo(f"[+] Backup successfully created at: {result['backup_dir']}")
    click.echo(f"    Database Size:   {m['database']['size_bytes']} bytes")
    click.echo(f"    Active Docs:     {m['database']['active_documents']}")
    click.echo(f"    Total Chunks:    {m['database']['total_chunks']}")
    click.echo(f"    Vector Store:    {'Included' if m['vector_store']['exists'] else 'None'}")
    click.echo(f"    Manifest Status: {m['status']}")
    click.echo("=" * 60)


@cli.command("restore")
@click.argument("backup_path", type=click.Path(exists=True))
@click.option("--force", is_flag=True, default=False, help="Bypass non-critical warnings.")
def restore_cmd(backup_path, force):
    """Restore database and vector store from a backup directory."""
    from app.storage.backup import restore_backup
    from pathlib import Path

    click.echo("=" * 60)
    click.echo(" Agentic Security Researcher - Restore System")
    click.echo("=" * 60)
    click.echo(f"[*] Verifying and restoring backup from: {backup_path}")

    result = restore_backup(backup_dir=Path(backup_path), force=force)

    if not result.get("success"):
        click.echo(f"[-] Restore failed: {result.get('message')}")
        for err in result.get("errors", []):
            click.echo(f"    - {err}")
        sys.exit(1)

    click.echo(f"[+] Successfully restored database to: {result['restored_database']}")
    if result.get("restored_vector_store"):
        click.echo(f"[+] Successfully restored vector store to: {result['restored_vector_store']}")
    click.echo("=" * 60)


if __name__ == "__main__":
    cli()

