"""Context builder module for converting retrieval results into structured LLM context."""

from typing import List, Tuple, Optional
from pydantic import BaseModel, Field

from app.knowledge.retriever import SearchResult


class ContextItem(BaseModel):
    """Structured representation of a source item formatted for the LLM."""
    index: int
    source_file: str
    source_path: str
    title: str
    section: str
    page: Optional[int] = None
    score: float
    content: str

    @property
    def full_source_path(self) -> str:
        """Formatted source path relative to repository root."""
        return f"knowledge/PentestingEverything/{self.source_path}"


class ContextBuilder:
    """Formats, truncates, and organizes retrieved search results for grounded LLM reasoning."""

    def __init__(self, max_sources: int = 5, max_chars: int = 12000):
        self.max_sources = max_sources
        self.max_chars = max_chars

    def build_context(
        self,
        results: List[SearchResult],
        max_sources: Optional[int] = None,
        max_chars: Optional[int] = None,
    ) -> Tuple[str, List[ContextItem]]:
        """Construct structured context text and item list from search results.
        
        Enforces maximum source count and total character limits.
        """
        limit_sources = max_sources if max_sources is not None else self.max_sources
        limit_chars = max_chars if max_chars is not None else self.max_chars

        if not results:
            return "No relevant security methodology documents were found in the local knowledge base.", []

        selected_results = results[:limit_sources]
        context_items: List[ContextItem] = []
        blocks: List[str] = []
        total_chars = 0

        for i, res in enumerate(selected_results, start=1):
            item = ContextItem(
                index=i,
                source_file=res.source_file,
                source_path=res.source_path,
                title=res.title,
                section=res.section,
                page=res.page,
                score=res.score,
                content=res.content,
            )

            page_info = f"\nPage: {item.page}" if item.page is not None else ""
            block = (
                f"SOURCE [{item.index}]\n"
                f"File: {item.full_source_path}\n"
                f"Document: {item.title}\n"
                f"Section: {item.section}{page_info}\n"
                f"Relevance Score: {item.score}\n"
                f"Content:\n{item.content}\n"
            )

            # Check character limit
            if total_chars + len(block) > limit_chars and context_items:
                remaining_chars = limit_chars - total_chars
                if remaining_chars > 200:
                    truncated_content = item.content[: remaining_chars - 100] + "... [TRUNCATED DUE TO CONTEXT LIMIT]"
                    block = (
                        f"SOURCE [{item.index}]\n"
                        f"File: {item.full_source_path}\n"
                        f"Document: {item.title}\n"
                        f"Section: {item.section}{page_info}\n"
                        f"Relevance Score: {item.score}\n"
                        f"Content:\n{truncated_content}\n"
                    )
                    blocks.append(block)
                    context_items.append(item)
                break

            blocks.append(block)
            context_items.append(item)
            total_chars += len(block)

        context_text = "\n---\n".join(blocks)
        return context_text, context_items
