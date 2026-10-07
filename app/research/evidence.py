"""Evidence analyzer interface."""

from typing import Dict, Any
from app.agent.state import EvidenceItem


class EvidenceAnalyzer:
    """Analyzes raw HTTP traffic, code, logs, and traces without fabricating evidence."""

    def analyze(self, raw_evidence: str, evidence_type: str = "GENERIC") -> EvidenceItem:
        """Analyze researcher evidence. (Implemented in Phase 8)"""
        raise NotImplementedError("Evidence analyzer will be implemented in Phase 8.")
