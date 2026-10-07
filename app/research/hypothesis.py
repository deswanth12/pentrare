"""Research planner interface."""

from typing import List
from app.agent.state import ScopeItem, ResearchItem, ArchitectureComponent


class ResearchPlanner:
    """Generates non-autonomous structured research checklists based on scope and architecture."""

    def generate_plan(
        self,
        scope: ScopeItem,
        components: List[ArchitectureComponent],
    ) -> List[ResearchItem]:
        """Generate structured research checklist. (Implemented in Phase 7)"""
        raise NotImplementedError("Research planner will be implemented in Phase 7.")
