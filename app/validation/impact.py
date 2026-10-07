"""Factual impact assessor interface."""

from typing import Dict, Any
from app.agent.state import Finding


class ImpactAnalyzer:
    """Assesses observed vs potential impact across CIA and privilege boundaries without exaggeration."""

    def assess_impact(self, finding: Finding) -> Dict[str, Any]:
        """Assess technical impact. (Implemented in Phase 9)"""
        raise NotImplementedError("Impact analyzer will be implemented in Phase 9.")
