"""Phase 10 Evaluation & Productization package.

Provides a deterministic, offline-capable benchmark for the
Agentic Security Researcher pipeline.

Components:
    models   – Pydantic models for scenarios, results, and metrics.
    datasets – Benchmark registry and scenario loader.
    metrics  – Deterministic metric calculators.
    graders  – Rule-based graders (+ optional supplemental LLM judge).
    runner   – End-to-end evaluation pipeline.
    reports  – Markdown / JSON evaluation report formatter.
"""

BENCHMARK_VERSION = "1.0"
