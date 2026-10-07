"""Tests for document chunking, deterministic IDs, deduplication, and tagging."""

from app.knowledge.parser import ParsedDocument, ParsedSection
from app.knowledge.chunker import DocumentChunker, KnowledgeChunk


def test_chunk_small_sections():
    """Verify small sections remain intact as individual coherent chunks."""
    doc = ParsedDocument(
        source_path="LLM Security/mcp_boundaries.md",
        filename="mcp_boundaries.md",
        file_type="markdown",
        title="MCP Boundaries",
        sections=[
            ParsedSection(title="Section 1", content="Short summary of tool boundaries."),
            ParsedSection(title="Section 2", content="Second short summary of caller verification."),
        ],
        content_hash="test-hash-1",
        raw_text="dummy",
    )

    chunker = DocumentChunker(max_chunk_size=1200)
    chunks = chunker.chunk(doc)

    assert len(chunks) == 2
    assert chunks[0].section == "Section 1"
    assert chunks[1].section == "Section 2"
    assert "mcp" in chunks[0].tags.lower()


def test_deterministic_chunk_ids():
    """Verify that chunk IDs are deterministic across multiple chunking passes."""
    doc = ParsedDocument(
        source_path="API/auth.md",
        filename="auth.md",
        file_type="markdown",
        title="API Authentication",
        sections=[
            ParsedSection(title="JWT Verification", content="Inspect signature validation algorithm."),
        ],
        content_hash="hash-123",
        raw_text="dummy",
    )

    chunker = DocumentChunker()
    pass1 = chunker.chunk(doc)
    pass2 = chunker.chunk(doc)

    assert pass1[0].chunk_id == pass2[0].chunk_id
    assert pass1[0].content_hash == pass2[0].content_hash


def test_chunk_deduplication():
    """Verify duplicate content within a document is skipped."""
    doc = ParsedDocument(
        source_path="Web/duplicate_sections.md",
        filename="duplicate_sections.md",
        file_type="markdown",
        title="Duplicates Test",
        sections=[
            ParsedSection(title="First Copy", content="Identical methodology content repeated."),
            ParsedSection(title="Second Copy", content="Identical methodology content repeated."),
        ],
        content_hash="hash-dup",
        raw_text="dummy",
    )

    chunker = DocumentChunker()
    chunks = chunker.chunk(doc)

    assert len(chunks) == 1
    assert chunks[0].section == "First Copy"


def test_large_section_splitting():
    """Verify sections exceeding max_chunk_size are split by paragraphs."""
    p1 = "Paragraph one discussing initial vulnerability reconnaissance. " * 15
    p2 = "Paragraph two discussing active evidence gathering steps. " * 15
    p3 = "Paragraph three discussing impact assessment boundaries. " * 15

    large_content = f"{p1}\n\n{p2}\n\n{p3}"

    doc = ParsedDocument(
        source_path="Recon/large_doc.md",
        filename="large_doc.md",
        file_type="markdown",
        title="Large Recon Guide",
        sections=[ParsedSection(title="Deep Recon", content=large_content)],
        content_hash="hash-large",
        raw_text=large_content,
    )

    chunker = DocumentChunker(max_chunk_size=500)
    chunks = chunker.chunk(doc)

    assert len(chunks) >= 3
    for c in chunks:
        assert len(c.content) > 0
        assert c.section == "Deep Recon"
