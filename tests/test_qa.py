"""Tests for Phase 3 grounded question answering, context building, and Gemini integration."""

from unittest.mock import MagicMock
import pytest
from app.config import Settings
from app.storage.database import DatabaseManager
from app.knowledge.retriever import SearchResult
from app.knowledge.context import ContextBuilder, ContextItem
from app.agent.qa import GroundedQAService
from app.agent.prompts import RAG_SYSTEM_PROMPT


@pytest.fixture
def mock_search_results():
    """Fixture providing sample search results for testing."""
    return [
        SearchResult(
            chunk_id="chunk-01",
            source_file="Prompt Injection.md",
            source_path="LLM Security Assessment/Prompt Injection.md",
            title="Prompt Injection Testing",
            section="Direct vs Indirect",
            page=None,
            score=1.85,
            content="Direct prompt injection occurs when user input alters instructions.",
        ),
        SearchResult(
            chunk_id="chunk-02",
            source_file="API Security.pdf",
            source_path="API Pentesting/API Security.pdf",
            title="API Pentesting Guide",
            section="JWT Validation",
            page=14,
            score=1.42,
            content="Check if JWT header contains alg=none parameter.",
        ),
    ]


def test_context_builder_formatting(mock_search_results):
    """Verify context builder outputs structured source blocks with metadata."""
    builder = ContextBuilder(max_sources=5, max_chars=5000)
    context_text, items = builder.build_context(mock_search_results)

    assert len(items) == 2
    assert "SOURCE [1]" in context_text
    assert "knowledge/PentestingEverything/LLM Security Assessment/Prompt Injection.md" in context_text
    assert "Section: Direct vs Indirect" in context_text
    assert "SOURCE [2]" in context_text
    assert "Page: 14" in context_text
    assert items[0].index == 1
    assert items[1].page == 14


def test_context_builder_truncation(mock_search_results):
    """Verify context builder respects max_chars and truncates appropriately."""
    # Set a tiny character limit
    builder = ContextBuilder(max_sources=5, max_chars=250)
    context_text, items = builder.build_context(mock_search_results)

    assert len(items) <= 2
    assert len(context_text) <= 400


def test_context_builder_empty():
    """Verify context builder handles empty search results without error."""
    builder = ContextBuilder()
    context_text, items = builder.build_context([])

    assert len(items) == 0
    assert "No relevant security methodology documents" in context_text


def test_qa_service_sources_only(tmp_path, mock_search_results):
    """Verify ask() with sources_only=True returns retrieved sources without calling Gemini."""
    db = DatabaseManager(tmp_path / "qa_test.db")
    db.init_db()

    mock_retriever = MagicMock()
    mock_retriever.search.return_value = mock_search_results

    qa_service = GroundedQAService(
        db=db,
        retriever=mock_retriever,
        settings=Settings(gemini_api_key=None),
    )

    result = qa_service.ask("What is prompt injection?", sources_only=True)

    assert result["sources_only"] is True
    assert result["model"] is None
    assert len(result["sources"]) == 2
    assert result["sources"][0].source_file == "Prompt Injection.md"
    assert result["answer"] == ""


def test_qa_service_missing_api_key(tmp_path, mock_search_results):
    """Verify ask() raises helpful ValueError when GEMINI_API_KEY is not set."""
    db = DatabaseManager(tmp_path / "qa_test.db")
    db.init_db()

    mock_retriever = MagicMock()
    mock_retriever.search.return_value = mock_search_results

    qa_service = GroundedQAService(
        db=db,
        retriever=mock_retriever,
        settings=Settings(gemini_api_key=None),
    )

    with pytest.raises(ValueError) as exc_info:
        qa_service.ask("What is prompt injection?", sources_only=False)

    assert "GEMINI_API_KEY is not configured" in str(exc_info.value)


def test_qa_service_with_mocked_gemini(tmp_path, mock_search_results):
    """Verify ask() calls Gemini client with system instruction and context."""
    db = DatabaseManager(tmp_path / "qa_test.db")
    db.init_db()

    mock_retriever = MagicMock()
    mock_retriever.search.return_value = mock_search_results

    mock_genai_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = (
        "Prompt injection occurs when attacker input overrides system instructions [Source 1].\n\n"
        "Sources:\n[1] knowledge/PentestingEverything/LLM Security Assessment/Prompt Injection.md"
    )
    mock_genai_client.models.generate_content.return_value = mock_response

    qa_service = GroundedQAService(
        db=db,
        retriever=mock_retriever,
        settings=Settings(gemini_api_key="mock-key-for-test", gemini_model="gemini-2.5-flash"),
        genai_client=mock_genai_client,
    )

    result = qa_service.ask("What is prompt injection?", sources_only=False)

    assert result["sources_only"] is False
    assert result["model"] == "gemini-2.5-flash"
    assert "Prompt injection occurs" in result["answer"]
    assert len(result["sources"]) == 2

    # Verify generate_content call arguments
    mock_genai_client.models.generate_content.assert_called_once()
    call_kwargs = mock_genai_client.models.generate_content.call_args.kwargs
    assert call_kwargs["model"] == "gemini-2.5-flash"
    assert "RESEARCHER QUESTION:" in call_kwargs["contents"]
    assert "RETRIEVED REFERENCE MATERIAL" in call_kwargs["contents"]
    assert call_kwargs["config"].system_instruction == RAG_SYSTEM_PROMPT


def test_qa_service_api_error_handling(tmp_path, mock_search_results):
    """Verify ask() catches Gemini API exceptions and raises clean error messages."""
    db = DatabaseManager(tmp_path / "qa_test.db")
    db.init_db()

    mock_retriever = MagicMock()
    mock_retriever.search.return_value = mock_search_results

    mock_genai_client = MagicMock()
    mock_genai_client.models.generate_content.side_effect = Exception("RESOURCE_EXHAUSTED: rate limit exceeded")

    qa_service = GroundedQAService(
        db=db,
        retriever=mock_retriever,
        settings=Settings(gemini_api_key="mock-key"),
        genai_client=mock_genai_client,
    )

    with pytest.raises(RuntimeError) as exc_info:
        qa_service.ask("test query")

    assert "rate limit or quota exceeded" in str(exc_info.value)
