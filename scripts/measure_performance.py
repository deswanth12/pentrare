"""Performance benchmarking script for Phase 11.

Measures actual empirical latency for key operations:
- Application startup
- Knowledge status CLI
- Lexical search
- Semantic search
- Hybrid search
- Project context construction
- Project health calculation
- Evaluation benchmark run (25 scenarios)
"""

import time
import sys
from pathlib import Path

# Ensure project root in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.config import get_settings
from app.storage.database import DatabaseManager
from app.knowledge.retriever import KnowledgeRetriever
from app.evaluation.runner import run_evaluation
from app.evaluation.models import EvalRunConfig
from app.research.orchestrator import ResearchOrchestrator


def benchmark():
    results = {}

    # 1. Startup Time
    t0 = time.monotonic()
    settings = get_settings(reload=True)
    db = DatabaseManager(settings.database_path)
    t1 = time.monotonic()
    results["app_startup_ms"] = (t1 - t0) * 1000.0

    # 2. Knowledge Status Query
    t0 = time.monotonic()
    stats = db.get_knowledge_stats()
    t1 = time.monotonic()
    results["knowledge_status_ms"] = (t1 - t0) * 1000.0

    # 3. Retriever setup
    retriever = KnowledgeRetriever(db, auto_load_vectors=True)

    # 4. Lexical Search
    t0 = time.monotonic()
    lex_res = retriever.search("SQL injection authentication bypass", limit=5, mode="lexical")
    t1 = time.monotonic()
    results["lexical_search_ms"] = (t1 - t0) * 1000.0

    # 5. Semantic Search
    t0 = time.monotonic()
    sem_res = retriever.search("SQL injection authentication bypass", limit=5, mode="semantic")
    t1 = time.monotonic()
    results["semantic_search_ms"] = (t1 - t0) * 1000.0

    # 6. Hybrid Search
    t0 = time.monotonic()
    hyb_res = retriever.search("SQL injection authentication bypass", limit=5, mode="hybrid")
    t1 = time.monotonic()
    results["hybrid_search_ms"] = (t1 - t0) * 1000.0

    # 7. Project Context & Health (create temporary project)
    proj_name = f"Perf Test Project {int(time.time() * 1000)}"
    proj = db.create_project(proj_name, description="Temporary benchmark project")
    pid = proj["id"]
    db.add_asset(pid, name="api.local", asset_type="api", scope_status="IN_SCOPE")
    db.add_objective(pid, title="Test Auth", priority="HIGH")

    orchestrator = ResearchOrchestrator(db, retriever)

    from app.research.context import ProjectContextBuilder, evaluate_project_health

    builder = ProjectContextBuilder(db=db, retriever=retriever)

    t0 = time.monotonic()
    proj_ctx = builder.build_context(pid)
    t1 = time.monotonic()
    results["context_construction_ms"] = (t1 - t0) * 1000.0

    t0 = time.monotonic()
    health = evaluate_project_health(proj_ctx)
    t1 = time.monotonic()
    results["health_calculation_ms"] = (t1 - t0) * 1000.0

    # 8. Evaluation Benchmark (25 scenarios)
    eval_config = EvalRunConfig(offline_mode=True)
    t0 = time.monotonic()
    report = run_evaluation(eval_config)
    t1 = time.monotonic()
    results["eval_benchmark_ms"] = (t1 - t0) * 1000.0
    results["eval_benchmark_scenarios"] = report.metrics.total_scenarios

    # Clean up perf test project
    with db.get_connection() as conn:
        conn.execute("DELETE FROM projects WHERE id = ?;", (pid,))

    print("=" * 60)
    print(" Performance Benchmark Results (Measured)")
    print("=" * 60)
    for k, v in results.items():
        if isinstance(v, float):
            print(f"  {k:<32} {v:8.2f} ms")
        else:
            print(f"  {k:<32} {v}")
    print("=" * 60)

    return results

if __name__ == "__main__":
    benchmark()
