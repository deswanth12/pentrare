"""Architecture analyzer interface."""

from typing import List, Dict, Any
from app.agent.state import ArchitectureComponent


class ArchitectureAnalyzer:
    """Analyzes architecture diagrams, specifications, code, and traces to identify trust boundaries."""

    def analyze(self, raw_input: str) -> List[ArchitectureComponent]:
        """Analyze system architecture. (Implemented in Phase 7)"""
        raise NotImplementedError("Architecture analyzer will be implemented in Phase 7.")
