"""Tests for local search and BM25 retriever."""

import pytest
from app.storage.database import DatabaseManager
from app.knowledge.retriever import KnowledgeRetriever


@pytest.fixture
def populated_test_db(tmp_path):
    """Fixture providing database populated with indexed test chunks."""
    db_path = tmp_path / "search_test.db"
    db = DatabaseManager(db_path)
    db.init_db()

    # Insert test documents and chunks
    doc1_id = db.upsert_document(
        source_path="LLM/prompt_injection.md",
        filename="prompt_injection.md",
        file_type="markdown",
        title="Prompt Injection Defenses",
        content_hash="h1",
    )
    db.insert_chunks_batch(
        document_id=doc1_id,
        chunks=[
            {
                "chunk_id": "chunk-llm-01",
                "section": "Direct Injections",
                "page": None,
                "content": "Direct prompt injection occurs when untrusted user inputs manipulate model instructions.",
                "content_hash": "h1-1",
                "tags": "llm,prompt-injection",
            },
            {
                "chunk_id": "chunk-llm-02",
                "section": "Indirect Injections",
                "page": None,
                "content": "Indirect prompt injection occurs when external web pages or emails contain poisoned commands.",
                "content_hash": "h1-2",
                "tags": "llm,prompt-injection,indirect",
            },
        ],
        source_path="LLM/prompt_injection.md",
        title="Prompt Injection Defenses",
    )

    doc2_id = db.upsert_document(
        source_path="API/auth_bypass.md",
        filename="auth_bypass.md",
        file_type="markdown",
        title="API Authentication Testing",
        content_hash="h2",
    )
    db.insert_chunks_batch(
        document_id=doc2_id,
        chunks=[
            {
                "chunk_id": "chunk-api-01",
                "section": "JWT Validation",
                "page": None,
                "content": "Testing for algorithm none and weak secret keys in JWT signature verification.",
                "content_hash": "h2-1",
                "tags": "api,jwt,authentication",
            }
        ],
        source_path="API/auth_bypass.md",
        title="API Authentication Testing",
    )

    return db


def test_retriever_search_matches(populated_test_db):
    """Verify search returns matching methodology chunks with valid metadata."""
    retriever = KnowledgeRetriever(populated_test_db)
    results = retriever.search("prompt injection", limit=5)

    assert len(results) >= 1
    top_result = results[0]
    assert "prompt injection" in top_result.content.lower()
    assert top_result.source_file == "prompt_injection.md"
    assert top_result.source_path == "LLM/prompt_injection.md"
    assert top_result.score > 0


def test_retriever_distinct_queries(populated_test_db):
    """Verify different domain queries match appropriate domain documents."""
    retriever = KnowledgeRetriever(populated_test_db)

    api_results = retriever.search("JWT validation algorithm", limit=5)
    assert len(api_results) >= 1
    assert "JWT" in api_results[0].content


def test_retriever_empty_query(populated_test_db):
    """Verify empty query returns empty list without error."""
    retriever = KnowledgeRetriever(populated_test_db)
    assert retriever.search("") == []
    assert retriever.search("   ") == []
