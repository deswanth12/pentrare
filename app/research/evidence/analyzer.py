"""AI Evidence Analyzer service for Phase 7.

Analyzes normalized evidence artifacts and factual observations using Gemini
or deterministic heuristics. Strictly enforces:
- Prompt injection defense: artifact content is untrusted data.
- Distinction: RAW ARTIFACT != OBSERVATION != HYPOTHESIS != FINDING.
- Does NOT declare confirmed vulnerabilities.
"""

import json
import re
from typing import Any, Dict, List, Optional

from app.agent.prompts import EVIDENCE_ANALYSIS_SYSTEM_PROMPT, build_evidence_analysis_prompt
from app.config import get_settings, Settings
from app.knowledge.retriever import KnowledgeRetriever
from app.research.models import NormalizedEvidence


class EvidenceAnalyzer:
    """Analyzes normalized evidence artifacts and extracts technical interpretations."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        genai_client: Optional[Any] = None,
        retriever: Optional[KnowledgeRetriever] = None,
    ):
        self.settings = settings or get_settings()
        self._genai_client = genai_client
        self.retriever = retriever

    def _get_client(self) -> Optional[Any]:
        if self._genai_client is not None:
            return self._genai_client
        if not self.settings.has_gemini_key:
            return None
        from google import genai
        return genai.Client(api_key=self.settings.gemini_api_key)

    def analyze(
        self,
        normalized: Any,
        hypotheses: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Analyze evidence and produce structured technical interpretation.

        Returns a dictionary matching:
        {
            "summary": str,
            "key_observations": List[str],
            "technical_context": str,
            "relevance_to_hypotheses": str,
            "missing_aspects": List[str]
        }
        """
        if isinstance(normalized, str):
            raise NotImplementedError("Evidence analyzer for raw strings will be implemented in Phase 8.")

        client = self._get_client()

        # If offline or no Gemini key, use deterministic analysis
        if client is None:
            return self._deterministic_analyze(normalized, hypotheses)

        obs_text = "\n".join(f"- [{o.category.value}] {o.statement}" for o in normalized.observations)
        sec_text = "\n\n".join(f"[{k.upper()}]:\n{v[:1500]}" for k, v in normalized.sections.items())
        hyp_text = ""
        if hypotheses:
            hyp_text = "\n".join(f"- [ID:{h.get('id')}] {h.get('title')}: {h.get('description', '')}" for h in hypotheses)

        user_prompt = build_evidence_analysis_prompt(
            artifact_type=normalized.artifact_type.value,
            observations_text=obs_text,
            sections_text=sec_text,
            hypotheses_text=hyp_text,
        )

        from google.genai import types

        try:
            response = client.models.generate_content(
                model=self.settings.gemini_model,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=EVIDENCE_ANALYSIS_SYSTEM_PROMPT,
                    temperature=0.2,
                ),
            )
            raw_text = response.text if hasattr(response, "text") and response.text else "{}"
            data = _extract_json(raw_text)
            if not data or "summary" not in data:
                return self._deterministic_analyze(normalized, hypotheses)
            return data
        except Exception:
            return self._deterministic_analyze(normalized, hypotheses)

    def _deterministic_analyze(
        self,
        normalized: NormalizedEvidence,
        hypotheses: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Deterministic, rule-based fallback analysis without calling external LLM."""
        key_obs = [o.statement for o in normalized.observations[:10]]
        summary = f"Artifact '{normalized.title}' contains {len(normalized.observations)} verified technical observation(s)."

        tech_context = (
            f"Parsed as {normalized.artifact_type.value}. "
            f"Observations indicate static structural data with metadata {normalized.metadata}."
        )

        relevance = "Evidence provides concrete technical observations. Further multi-session testing required."
        if hypotheses:
            first_h = hypotheses[0]
            relevance = (
                f"Observations may be relevant to hypothesis '{first_h.get('title')}', "
                f"but do not alone confirm a vulnerability without validation."
            )

        missing = [
            "Independent reproduction in alternative user session/role",
            "Proof of authorization boundary enforcement or lack thereof",
        ]

        return {
            "summary": summary,
            "key_observations": key_obs,
            "technical_context": tech_context,
            "relevance_to_hypotheses": relevance,
            "missing_aspects": missing,
        }


def _extract_json(text: str) -> dict:
    """Extract a JSON object from text that may contain markdown code fences."""
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        text = match.group(1)
    else:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1:
            text = text[start : end + 1]
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {}
