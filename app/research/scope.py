"""Scope analyzer interface."""

from typing import Dict, Any
from app.agent.state import ScopeItem


class ScopeAnalyzer:
    """Extracts in-scope, out-of-scope, restrictions, rate limits, and reporting requirements."""

    def analyze(self, scope_text: str) -> ScopeItem:
        """Parse scope text. (Implemented in Phase 6)"""
        raise NotImplementedError("Scope analyzer will be implemented in Phase 6.")
