"""Grounded question-answering service connecting local retrieval with Gemini."""

from typing import List, Dict, Any, Optional
from google import genai
from google.genai import types

from app.config import get_settings, Settings
from app.storage.database import DatabaseManager
from app.knowledge.retriever import KnowledgeRetriever, SearchResult
from app.knowledge.context import ContextBuilder, ContextItem
from app.agent.prompts import RAG_SYSTEM_PROMPT, build_rag_user_prompt


class GroundedQAService:
    """Orchestrates grounded question-answering using local retrieval and Gemini."""

    def __init__(
        self,
        db: DatabaseManager,
        retriever: Optional[KnowledgeRetriever] = None,
        context_builder: Optional[ContextBuilder] = None,
        settings: Optional[Settings] = None,
        genai_client: Optional[Any] = None,
    ):
        self.db = db
        self.settings = settings or get_settings()
        self.retriever = retriever or KnowledgeRetriever(db)
        self.context_builder = context_builder or ContextBuilder(
            max_sources=self.settings.rag_max_sources,
            max_chars=self.settings.rag_max_chars,
        )
        self._genai_client = genai_client

    def _get_client(self) -> Any:
        """Initialize or return Google GenAI client safely."""
        if self._genai_client is not None:
            return self._genai_client

        if not self.settings.has_gemini_key:
            raise ValueError(
                "GEMINI_API_KEY is not configured. "
                "Set GEMINI_API_KEY in your .env file or environment, "
                "or run with --sources-only to inspect retrieved knowledge without calling Gemini."
            )

        try:
            return genai.Client(api_key=self.settings.gemini_api_key)
        except Exception as e:
            raise RuntimeError(f"Failed to initialize Gemini client: {e}")

    def ask(
        self,
        question: str,
        max_sources: Optional[int] = None,
        sources_only: bool = False,
    ) -> Dict[str, Any]:
        """Perform grounded retrieval and generate an evidence-backed answer."""
        clean_question = question.strip()
        if not clean_question:
            raise ValueError("Question cannot be empty.")

        limit = max_sources or self.settings.rag_max_sources

        # 1. Local Retrieval
        search_results: List[SearchResult] = self.retriever.search(clean_question, limit=limit)

        # 2. Context Building
        context_text, context_items = self.context_builder.build_context(
            results=search_results,
            max_sources=limit,
            max_chars=self.settings.rag_max_chars,
        )

        if sources_only:
            return {
                "question": clean_question,
                "sources": context_items,
                "answer": "",
                "model": None,
                "sources_only": True,
            }

        # 3. Gemini LLM Reasoning
        client = self._get_client()
        user_prompt = build_rag_user_prompt(clean_question, context_text)

        try:
            response = client.models.generate_content(
                model=self.settings.gemini_model,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=RAG_SYSTEM_PROMPT,
                    temperature=0.2,
                ),
            )
            answer_text = response.text if hasattr(response, "text") and response.text else ""
        except Exception as e:
            error_msg = str(e)
            if "API_KEY" in error_msg.upper() or "AUTHENTICATION" in error_msg.upper():
                raise RuntimeError("Gemini API authentication failed. Please verify your GEMINI_API_KEY.")
            elif "RESOURCE_EXHAUSTED" in error_msg.upper() or "QUOTA" in error_msg.upper():
                raise RuntimeError("Gemini API rate limit or quota exceeded. Please try again shortly.")
            else:
                raise RuntimeError(f"Gemini API request failed: {error_msg}")

        return {
            "question": clean_question,
            "sources": context_items,
            "answer": answer_text,
            "model": self.settings.gemini_model,
            "sources_only": False,
        }
