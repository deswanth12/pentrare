"""Research planner service — uses hybrid knowledge retrieval + Gemini to produce structured plans.

Safety constraints:
- Does NOT perform autonomous scanning, exploitation, or target interaction.
- Retrieved documents are treated as DATA ONLY (prompt injection defense).
- The researcher performs all active testing.
- Output is a planning aid — all hypotheses remain UNTESTED.
"""

import json
import re
from typing import Any, List, Optional

from app.agent.prompts import RESEARCH_PLANNING_SYSTEM_PROMPT, build_research_planning_prompt
from app.config import get_settings, Settings
from app.knowledge.context import ContextBuilder
from app.knowledge.retriever import KnowledgeRetriever
from app.research.models import ResearchPlan
from app.storage.database import DatabaseManager


class ResearchPlanner:
    """Generates structured research plans from an objective using local knowledge + Gemini.

    The planner reuses the existing KnowledgeRetriever (no second retrieval system).
    Gemini is called to convert retrieved knowledge into a structured plan.
    All AI output is clearly labelled as AI ANALYSIS, not evidence or findings.
    """

    def __init__(
        self,
        db: DatabaseManager,
        retriever: Optional[KnowledgeRetriever] = None,
        settings: Optional[Settings] = None,
        genai_client: Optional[Any] = None,
    ):
        self.db = db
        self.settings = settings or get_settings()
        self.retriever = retriever or KnowledgeRetriever(db)
        self._genai_client = genai_client
        self._context_builder = ContextBuilder(
            max_sources=self.settings.rag_max_sources,
            max_chars=self.settings.rag_max_chars,
        )

    def _get_client(self) -> Any:
        if self._genai_client is not None:
            return self._genai_client
        if not self.settings.has_gemini_key:
            return None
        from google import genai
        return genai.Client(api_key=self.settings.gemini_api_key)

    def plan(
        self,
        project_id: int,
        objective: str,
        knowledge_limit: int = 8,
    ) -> ResearchPlan:
        """Generate a structured research plan for a research objective.

        Steps:
        1. Search local knowledge base with hybrid retrieval.
        2. Build context from retrieved chunks.
        3. If Gemini available, call it to generate a structured plan.
        4. Return ResearchPlan (planning aid only — no findings, no evidence).
        """
        objective = objective.strip()
        if not objective:
            raise ValueError("Research objective cannot be empty.")

        # Step 1: Retrieve relevant knowledge (existing hybrid retriever)
        search_results = self.retriever.search(objective, limit=knowledge_limit, mode="hybrid")

        # Step 2: Build context
        context_text, context_items = self._context_builder.build_context(
            results=search_results,
            max_sources=knowledge_limit,
            max_chars=self.settings.rag_max_chars,
        )
        knowledge_sources = [
            f"{item.full_source_path} — {item.section}" for item in context_items
        ]

        # Step 3: Call Gemini if key available
        client = self._get_client()
        if client is None:
            return ResearchPlan(
                project_id=project_id,
                objective_title=objective,
                knowledge_sources=knowledge_sources,
                warning=(
                    "GEMINI_API_KEY not configured. "
                    "Knowledge sources retrieved, but AI planning unavailable. "
                    "Configure GEMINI_API_KEY for structured plan generation."
                ),
            )

        from google.genai import types
        user_prompt = build_research_planning_prompt(objective, context_text)

        try:
            response = client.models.generate_content(
                model=self.settings.gemini_model,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=RESEARCH_PLANNING_SYSTEM_PROMPT,
                    temperature=0.1,
                ),
            )
            raw_text = response.text if hasattr(response, "text") and response.text else "{}"
        except Exception as e:
            return ResearchPlan(
                project_id=project_id,
                objective_title=objective,
                knowledge_sources=knowledge_sources,
                warning=f"Gemini API error: {e}",
            )

        # Step 4: Parse JSON response (handle markdown code fences)
        data = _extract_json(raw_text)

        return ResearchPlan(
            project_id=project_id,
            objective_title=objective,
            relevant_concepts=_safe_list(data.get("relevant_concepts")),
            suggested_hypotheses=_safe_list(data.get("suggested_hypotheses")),
            evidence_needed=_safe_list(data.get("evidence_needed")),
            validation_questions=_safe_list(data.get("validation_questions")),
            potential_finding_categories=_safe_list(data.get("potential_finding_categories")),
            knowledge_sources=knowledge_sources,
        )


def _extract_json(text: str) -> dict:
    """Extract a JSON object from a response that may contain markdown code fences."""
    # Try markdown code block first
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        text = match.group(1)
    else:
        # Find the first { ... } block
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1:
            text = text[start : end + 1]
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {}


def _safe_list(value: Any) -> List[str]:
    """Safely coerce a value to a list of strings."""
    if isinstance(value, list):
        return [str(x) for x in value]
    if isinstance(value, str):
        return [value] if value.strip() else []
    return []
