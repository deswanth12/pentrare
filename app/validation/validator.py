"""Finding validator interface."""

from typing import Dict, Any
from app.agent.state import Finding, FindingClassification


class FindingValidator:
    """Validates suspected findings and attempts to rigorously falsify claims."""

    def validate(self, finding: Finding) -> Finding:
        """Validate and classify finding. (Implemented in Phase 9)"""
        raise NotImplementedError("Finding validator will be implemented in Phase 9.")
