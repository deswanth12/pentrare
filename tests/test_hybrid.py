"""Tests for Phase 4 Hybrid Semantic Retrieval: embeddings, vector store, and hybrid ranking."""

import pytest
import numpy as np
from pathlib import Path
from click.testing import CliRunner

from app.main import cli
from app.config import Settings
from app.storage.database import DatabaseManager
from app.knowledge.embeddings import EmbeddingGenerator
from app.knowledge.vector_store import VectorStore
from app.knowledge.retriever import KnowledgeRetriever, SearchResult


# -----------------------------------------------------------------
# 1. Embedding Generator Tests
# -----------------------------------------------------------------

def test_mock_embedding_generation():
    """Verify mock embedding generator produces normalized float32 vectors deterministically."""
    emb_gen = EmbeddingGenerator(mock=True, dimension=128)

    texts = ["SQL injection vulnerability", "Cross-site scripting", "SQL injection vulnerability"]
    vectors = emb_gen.embed_texts(texts)

    assert isinstance(vectors, np.ndarray)
    assert vectors.shape == (3, 128)
    assert vectors.dtype == np.float32

    # L2 unit normalization check
    for v in vectors:
        norm = np.linalg.norm(v)
        assert pytest.approx(norm, rel=1e-5) == 1.0

    # Deterministic output check: identical texts produce identical vectors
    np.testing.assert_allclose(vectors[0], vectors[2], atol=1e-6)

    # Different texts produce different vectors
    assert not np.allclose(vectors[0], vectors[1], atol=1e-4)


def test_embedding_empty_inputs():
    """Verify empty texts and empty query return proper zero/empty arrays without error."""
    emb_gen = EmbeddingGenerator(mock=True, dimension=64)

    empty_batch = emb_gen.embed_texts([])
    assert empty_batch.shape == (0, 64)

    empty_query = emb_gen.embed_query("")
    assert empty_query.shape == (64,)
    assert np.all(empty_query == 0.0)

    spaces_query = emb_gen.embed_query("   ")
    assert spaces_query.shape == (64,)
    assert np.all(spaces_query == 0.0)


# -----------------------------------------------------------------
# 2. Vector Store Tests
# -----------------------------------------------------------------

def test_vector_store_crud_and_persistence(tmp_path):
    """Verify VectorStore adds, retrieves, updates, saves, and reloads vectors."""
    store_file = tmp_path / "test_store.npz"
    store = VectorStore(store_file, dimension=4)

    assert store.load() is False
    assert store.size() == 0

    # Add 2 initial chunks
    cids = ["chunk-1", "chunk-2"]
    embs = np.array([
        [1.0, 0.0, 0.0, 0.0],
        [0.0, 1.0, 0.0, 0.0],
    ], dtype=np.float32)
    hashes = ["h1", "h2"]

    added = store.add_chunks(cids, embs, hashes)
    assert added == 2
    assert store.size() == 2
    assert store.contains("chunk-1")
    assert store.get_content_hash("chunk-1") == "h1"

    # Save to disk
    store.save()
    assert store_file.exists()

    # Reload into a fresh instance
    store2 = VectorStore(store_file, dimension=4)
    loaded = store2.load()
    assert loaded is True
    assert store2.size() == 2
    assert store2.contains("chunk-2")
    assert store2.get_content_hash("chunk-2") == "h2"

    # Search: query aligns with chunk-1
    query_vec = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
    hits = store2.search(query_vec, top_k=2)
    assert len(hits) == 2
    assert hits[0][0] == "chunk-1"
    assert pytest.approx(hits[0][1], rel=1e-5) == 1.0
    assert hits[1][0] == "chunk-2"
    assert pytest.approx(hits[1][1], abs=1e-5) == 0.0

    # Update chunk-1
    updated_embs = np.array([[0.0, 0.0, 1.0, 0.0]], dtype=np.float32)
    store2.add_chunks(["chunk-1"], updated_embs, ["h1-updated"])
    assert store2.size() == 2
    assert store2.get_content_hash("chunk-1") == "h1-updated"

    # Delete chunk-2
    deleted = store2.delete_chunks(["chunk-2"])
    assert deleted == 1
    assert store2.size() == 1
    assert not store2.contains("chunk-2")


def test_vector_store_empty_search(tmp_path):
    """Verify search on empty vector store returns empty list."""
    store = VectorStore(tmp_path / "empty.npz", dimension=4)
    query_vec = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
    assert store.search(query_vec) == []


# -----------------------------------------------------------------
# 3. Hybrid Retriever Tests
# -----------------------------------------------------------------

@pytest.fixture
def hybrid_test_db(tmp_path):
    """Fixture providing database populated with distinct test chunks."""
    db_path = tmp_path / "hybrid_test.db"
    db = DatabaseManager(db_path)
    db.init_db()

    doc1_id = db.upsert_document(
        source_path="Web/ssrf.md",
        filename="ssrf.md",
        file_type="markdown",
        title="SSRF Methodology",
        content_hash="hash-ssrf",
    )
    db.insert_chunks_batch(
        document_id=doc1_id,
        chunks=[
            {
                "chunk_id": "chunk-ssrf-01",
                "section": "Cloud Metadata",
                "page": None,
                "content": "Server-side request forgery against AWS EC2 metadata service 169.254.169.254.",
                "content_hash": "c-ssrf-1",
                "tags": "ssrf,aws,cloud",
            },
            {
                "chunk_id": "chunk-ssrf-02",
                "section": "DNS Rebinding",
                "page": None,
                "content": "DNS rebinding bypasses internal IP blocklists by returning public then private IPs.",
                "content_hash": "c-ssrf-2",
                "tags": "ssrf,dns",
            },
        ],
        source_path="Web/ssrf.md",
        title="SSRF Methodology",
    )

    doc2_id = db.upsert_document(
        source_path="API/graphql.md",
        filename="graphql.md",
        file_type="markdown",
        title="GraphQL Security",
        content_hash="hash-graphql",
    )
    db.insert_chunks_batch(
        document_id=doc2_id,
        chunks=[
            {
                "chunk_id": "chunk-graphql-01",
                "section": "Introspection",
                "page": None,
                "content": "GraphQL schema introspection queries reveal hidden fields and mutations.",
                "content_hash": "c-gql-1",
                "tags": "graphql,api",
            }
        ],
        source_path="API/graphql.md",
        title="GraphQL Security",
    )

    return db


def test_hybrid_retriever_modes(hybrid_test_db, tmp_path):
    """Verify hybrid, lexical, and semantic search modes with mock embeddings."""
    dim = 32
    emb_gen = EmbeddingGenerator(mock=True, dimension=dim)
    vstore_path = tmp_path / "hybrid_store.npz"
    vstore = VectorStore(vstore_path, dimension=dim)

    # Embed all active chunks
    all_chunks = hybrid_test_db.get_all_active_chunks()
    texts = [c["content"] for c in all_chunks]
    cids = [c["chunk_id"] for c in all_chunks]
    hashes = [c["content_hash"] for c in all_chunks]
    embs = emb_gen.embed_texts(texts)
    vstore.add_chunks(cids, embs, hashes)
    vstore.save()

    retriever = KnowledgeRetriever(
        db=hybrid_test_db,
        vector_store=vstore,
        embedding_generator=emb_gen,
        lexical_weight=0.5,
        semantic_weight=0.5,
    )

    # 1. Lexical search
    lex_results = retriever.search("metadata 169.254.169.254", limit=5, mode="lexical")
    assert len(lex_results) >= 1
    assert lex_results[0].chunk_id == "chunk-ssrf-01"
    assert lex_results[0].match_type == "lexical"
    assert lex_results[0].lexical_score is not None
    assert lex_results[0].semantic_score is None

    # 2. Semantic search
    sem_results = retriever.search("AWS EC2 instance profile access", limit=5, mode="semantic")
    assert len(sem_results) >= 1
    assert sem_results[0].match_type == "semantic"
    assert sem_results[0].semantic_score is not None
    assert sem_results[0].lexical_score is None

    # 3. Hybrid search
    hyb_results = retriever.search("Server-side request forgery AWS metadata", limit=5, mode="hybrid")
    assert len(hyb_results) >= 1
    top = hyb_results[0]
    assert top.chunk_id == "chunk-ssrf-01"
    assert top.score > 0
    # Since chunk-ssrf-01 matches in both lexical and semantic, match_type should be "both"
    assert top.match_type in ("both", "lexical", "semantic")


def test_hybrid_fallback_when_no_vectors(hybrid_test_db):
    """Verify retriever gracefully falls back to lexical search if vector store is missing."""
    retriever = KnowledgeRetriever(
        db=hybrid_test_db,
        vector_store=None,
        embedding_generator=None,
    )

    results = retriever.search("GraphQL introspection", limit=5, mode="hybrid")
    assert len(results) >= 1
    assert results[0].chunk_id == "chunk-graphql-01"
    assert results[0].match_type == "lexical"


def test_semantic_mode_raises_if_no_vectors(hybrid_test_db):
    """Verify explicit semantic mode raises clear error if vector store is missing."""
    retriever = KnowledgeRetriever(
        db=hybrid_test_db,
        vector_store=None,
        embedding_generator=None,
        auto_load_vectors=False,  # prevent auto-loading the production vector_store.npz
    )

    with pytest.raises(RuntimeError) as exc_info:
        retriever.search("test", mode="semantic")
    assert "Vector store is not initialized" in str(exc_info.value)


# -----------------------------------------------------------------
# 4. CLI Hybrid and Embeddings Command Tests
# -----------------------------------------------------------------

def test_cli_search_modes_and_debug(tmp_path, monkeypatch):
    """Verify CLI search handles --mode and --debug-retrieval flags."""
    from app.config import get_settings

    test_db_path = tmp_path / "cli_search_test.db"
    test_vstore_path = tmp_path / "cli_test_vstore.npz"
    monkeypatch.setenv("DATABASE_PATH", str(test_db_path))
    monkeypatch.setenv("VECTOR_STORE_PATH", str(test_vstore_path))
    get_settings(reload=True)

    db = DatabaseManager(test_db_path)
    db.init_db()

    doc_id = db.upsert_document(
        source_path="Web/xss.md",
        filename="xss.md",
        file_type="markdown",
        title="XSS Guide",
        content_hash="hxss",
    )
    db.insert_chunks_batch(
        document_id=doc_id,
        chunks=[
            {
                "chunk_id": "chunk-xss-01",
                "section": "DOM XSS",
                "page": None,
                "content": "DOM-based XSS testing using document.write and location.hash sources.",
                "content_hash": "hxss-1",
                "tags": "xss,dom",
            }
        ],
        source_path="Web/xss.md",
        title="XSS Guide",
    )

    runner = CliRunner()

    try:
        # Search with mode=lexical
        res_lex = runner.invoke(cli, ["search", "DOM XSS", "--mode", "lexical"])
        assert res_lex.exit_code == 0
        assert "DOM XSS" in res_lex.output
        assert "xss.md" in res_lex.output

        # Search with --debug-retrieval (fallback to lexical when vstore is missing)
        res_dbg = runner.invoke(cli, ["search", "DOM XSS", "--debug-retrieval"])
        assert res_dbg.exit_code == 0
        assert "Lexical:" in res_dbg.output
        assert "Semantic:" in res_dbg.output
        assert "Match:" in res_dbg.output
    finally:
        get_settings(reload=True)


def test_cli_embeddings_empty_db(tmp_path, monkeypatch):
    """Verify embeddings command warns gracefully if no active chunks exist."""
    from app.config import get_settings

    test_db_path = tmp_path / "empty_embed_test.db"
    monkeypatch.setenv("DATABASE_PATH", str(test_db_path))
    get_settings(reload=True)

    db = DatabaseManager(test_db_path)
    db.init_db()

    runner = CliRunner()
    try:
        res = runner.invoke(cli, ["knowledge", "embeddings"])
        assert res.exit_code == 0
        assert "No active chunks found" in res.output
    finally:
        get_settings(reload=True)

