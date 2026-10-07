"""Tests for document parsers (Markdown, TXT, HTML, PDF) and text cleaning."""

import io
from pathlib import Path
from app.knowledge.parser import DocumentParser, clean_text, ParsedDocument


SAMPLE_PDF_BYTES = b"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj
4 0 obj << /Length 53 >> stream
BT
/F1 12 Tf
100 100 Td
(Security Lab PDF Test) Tj
ET
endstream endobj
5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000244 00000 n 
0000000348 00000 n 
trailer << /Size 6 /Root 1 0 R >>
startxref
427
%%EOF"""


def test_clean_text():
    """Verify text cleaning removes excessive newlines and control characters while preserving code."""
    dirty = "Line 1  \r\n\r\n\r\n\r\nLine 2\x00\x07   \n```python\n# code\n```\n\n\n"
    cleaned = clean_text(dirty)
    assert "\r" not in cleaned
    assert "\x00" not in cleaned
    assert "\n\n\n" not in cleaned
    assert "Line 1\n\nLine 2\n```python\n# code\n```" == cleaned


def test_parse_markdown_with_frontmatter(tmp_path):
    """Verify Markdown parsing extracts YAML frontmatter title, headings, and ignores code comments."""
    md_content = """---
title: "LLM Agent Security Assessment"
tags: [ai, agent, mcp]
---

# Introduction
Overview of testing AI agent systems.

## Tool Authorization
Inspect if tool execution enforces server-side validation.

```bash
# This is a comment inside code that should not become a heading
curl -X POST https://api.example.com/tool/exec -d '{"param": 1}'
```

### Potential Impact
Privilege escalation across tools.
"""
    file_path = tmp_path / "agent_security.md"
    file_path.write_text(md_content, encoding="utf-8")

    parser = DocumentParser()
    doc = parser.parse(file_path, base_dir=tmp_path)

    assert doc.title == "LLM Agent Security Assessment"
    assert doc.file_type == "markdown"
    assert doc.source_path == "agent_security.md"
    assert len(doc.sections) >= 3

    section_titles = [s.title for s in doc.sections]
    assert "Introduction" in section_titles
    assert "Tool Authorization" in section_titles
    assert "Potential Impact" in section_titles

    # Verify code block comment was NOT treated as a heading
    assert not any("This is a comment" in s.title for s in doc.sections)


def test_parse_text(tmp_path):
    """Verify plain text parsing separates paragraphs and extracts title."""
    txt_content = """Active Directory Security Notes

Section one describes Kerberoasting methodologies and SPN discovery.

Section two describes AS-REP roasting against pre-authentication disabled accounts.
"""
    file_path = tmp_path / "ad_notes.txt"
    file_path.write_text(txt_content, encoding="utf-8")

    parser = DocumentParser()
    doc = parser.parse(file_path, base_dir=tmp_path)

    assert "Active Directory Security Notes" in doc.title
    assert doc.file_type == "text"
    assert len(doc.sections) == 3


def test_parse_html(tmp_path):
    """Verify HTML parsing extracts title and headings while stripping script and nav tags."""
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>API Penetration Guide</title>
    <script>alert('noise');</script>
</head>
<body>
    <nav><a href="/">Home</a></nav>
    <h1>REST API Security</h1>
    <p>Examine authentication tokens and rate limits.</p>
    <h2>GraphQL Introspection</h2>
    <p>Check if schema introspection is enabled on production endpoints.</p>
</body>
</html>
"""
    file_path = tmp_path / "guide.html"
    file_path.write_text(html_content, encoding="utf-8")

    parser = DocumentParser()
    doc = parser.parse(file_path, base_dir=tmp_path)

    assert doc.title == "API Penetration Guide"
    assert doc.file_type == "html"
    assert not any("alert('noise')" in s.content for s in doc.sections)
    assert len(doc.sections) >= 2


def test_parse_pdf(tmp_path):
    """Verify PDF parsing extracts pages and text content."""
    pdf_path = tmp_path / "sample.pdf"
    pdf_path.write_bytes(SAMPLE_PDF_BYTES)

    parser = DocumentParser()
    doc = parser.parse(pdf_path, base_dir=tmp_path)

    assert doc.file_type == "pdf"
    assert len(doc.sections) >= 1
    assert doc.sections[0].page == 1
    assert "Security Lab PDF Test" in doc.sections[0].content


def test_parse_encoding_fallback(tmp_path):
    """Verify non-UTF8 encoded file with CP1252 bytes parses without crash."""
    file_path = tmp_path / "encoded.txt"
    # Write bytes with Windows-1252 copyright symbol and accented chars
    file_path.write_bytes(b"Special characters: \xa9 2026 Rese\xe1rch Lab\n\nParagraph 2 content.")

    parser = DocumentParser()
    doc = parser.parse(file_path, base_dir=tmp_path)

    assert doc.file_type == "text"
    assert len(doc.sections) >= 1
