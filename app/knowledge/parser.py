"""Document parsers and text cleaning for Markdown, TXT, RST, HTML, and PDF."""

import re
import hashlib
from html.parser import HTMLParser
from pathlib import Path
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

import pypdf


class ParsedSection(BaseModel):
    """A distinct structural section of a parsed document."""
    title: str = "General"
    content: str
    page: Optional[int] = None


class ParsedDocument(BaseModel):
    """Normalized structured document model extracted by parsers."""
    source_path: str
    filename: str
    file_type: str
    title: str
    sections: List[ParsedSection] = Field(default_factory=list)
    content_hash: str
    raw_text: str


def clean_text(text: str) -> str:
    """Clean text while preserving commands, code, URLs, security terminology, and headings."""
    if not text:
        return ""

    # Replace null bytes and non-printable control characters (preserve \n, \t, \r)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

    # Normalize carriage returns
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Strip trailing whitespace on each line
    lines = [line.rstrip() for line in text.split("\n")]
    text = "\n".join(lines)

    # Collapse excessive blank lines (more than 2 consecutive newlines)
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


class _HTMLTextExtractor(HTMLParser):
    """HTML Parser that preserves headings and technical content while stripping markup."""

    def __init__(self):
        super().__init__()
        self.sections: List[ParsedSection] = []
        self._current_heading: str = "Overview"
        self._current_text: List[str] = []
        self._skip_depth: int = 0
        self._in_pre: bool = False
        self._in_heading: bool = False
        self._heading_buffer: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[tuple]):
        tag_lower = tag.lower()
        if tag_lower in ("script", "style", "nav", "footer", "header", "noscript"):
            self._skip_depth += 1
        elif tag_lower in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self._flush_section()
            self._in_heading = True
            self._heading_buffer = []
        elif tag_lower in ("pre", "code"):
            self._in_pre = True
        elif tag_lower in ("p", "div", "br", "tr", "li"):
            self._current_text.append("\n")

    def handle_endtag(self, tag: str):
        tag_lower = tag.lower()
        if tag_lower in ("script", "style", "nav", "footer", "header", "noscript"):
            if self._skip_depth > 0:
                self._skip_depth -= 1
        elif tag_lower in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self._in_heading = False
            heading_text = "".join(self._heading_buffer).strip()
            if heading_text:
                self._current_heading = heading_text
        elif tag_lower in ("pre", "code"):
            self._in_pre = False
        elif tag_lower in ("p", "div"):
            self._current_text.append("\n")

    def handle_data(self, data: str):
        if self._skip_depth > 0:
            return
        if self._in_heading:
            self._heading_buffer.append(data)
        else:
            self._current_text.append(data)

    def _flush_section(self):
        content = "".join(self._current_text).strip()
        if content:
            cleaned = clean_text(content)
            if cleaned:
                self.sections.append(
                    ParsedSection(title=self._current_heading, content=cleaned)
                )
        self._current_text = []

    def get_sections(self) -> List[ParsedSection]:
        self._flush_section()
        return self.sections


class DocumentParser:
    """Dispatches document files to specialized format parsers."""

    def parse(self, file_path: Path, base_dir: Optional[Path] = None) -> ParsedDocument:
        """Parse document and return structured sections and metadata."""
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"Document file not found: {file_path}")

        # Compute source path relative to knowledge directory or base
        if base_dir:
            try:
                rel_path = file_path.relative_to(base_dir).as_posix()
            except ValueError:
                rel_path = file_path.name
        else:
            rel_path = file_path.name

        ext = file_path.suffix.lower()

        if ext in (".md", ".markdown", ".mdx"):
            return self._parse_markdown(file_path, rel_path)
        elif ext in (".txt", ".rst"):
            return self._parse_text(file_path, rel_path, ext)
        elif ext in (".html", ".htm"):
            return self._parse_html(file_path, rel_path)
        elif ext == ".pdf":
            return self._parse_pdf(file_path, rel_path)
        else:
            raise ValueError(f"Unsupported file format: {ext}")

    def _read_text_safely(self, file_path: Path) -> str:
        """Read text with UTF-8 first, falling back to Latin-1/CP1252 with error substitution."""
        try:
            return file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                return file_path.read_text(encoding="cp1252")
            except UnicodeDecodeError:
                return file_path.read_text(encoding="latin-1", errors="replace")

    def _parse_markdown(self, file_path: Path, rel_path: str) -> ParsedDocument:
        raw_content = self._read_text_safely(file_path)
        content_hash = hashlib.sha256(raw_content.encode("utf-8", errors="replace")).hexdigest()

        # Extract title from YAML frontmatter or first H1
        title = file_path.stem
        body = raw_content

        # Check frontmatter
        fm_match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", raw_content, re.DOTALL)
        if fm_match:
            fm_text, body = fm_match.groups()
            title_match = re.search(r"^title:\s*[\"']?(.*?)[\"']?\s*$", fm_text, re.MULTILINE)
            if title_match:
                title = title_match.group(1).strip()

        # Split into sections based on Markdown headings (#, ##, ###, ####)
        # Avoid splitting if inside fenced code blocks
        sections: List[ParsedSection] = []
        current_title = title
        current_lines: List[str] = []
        in_code_block = False

        for line in body.split("\n"):
            stripped = line.strip()
            if stripped.startswith("```"):
                in_code_block = not in_code_block

            heading_match = re.match(r"^(#{1,4})\s+(.+)$", stripped)
            if not in_code_block and heading_match:
                # Save previous section if content exists
                prev_content = clean_text("\n".join(current_lines))
                if prev_content:
                    sections.append(ParsedSection(title=current_title, content=prev_content))
                    current_lines = []

                current_title = heading_match.group(2).strip()
                # If document title wasn't set from frontmatter, first # heading can be document title
                if title == file_path.stem and heading_match.group(1) == "#":
                    title = current_title
            else:
                current_lines.append(line)

        final_content = clean_text("\n".join(current_lines))
        if final_content:
            sections.append(ParsedSection(title=current_title, content=final_content))

        # Fallback if no sections were generated
        if not sections and clean_text(raw_content):
            sections.append(ParsedSection(title=title, content=clean_text(raw_content)))

        return ParsedDocument(
            source_path=rel_path,
            filename=file_path.name,
            file_type="markdown",
            title=title,
            sections=sections,
            content_hash=content_hash,
            raw_text=raw_content,
        )

    def _parse_text(self, file_path: Path, rel_path: str, ext: str) -> ParsedDocument:
        raw_content = self._read_text_safely(file_path)
        content_hash = hashlib.sha256(raw_content.encode("utf-8", errors="replace")).hexdigest()

        # Determine title from first non-empty line
        lines = [line.strip() for line in raw_content.split("\n") if line.strip()]
        title = lines[0][:80] if lines else file_path.stem

        # Split on double newlines / large paragraph breaks
        cleaned = clean_text(raw_content)
        paragraphs = [p.strip() for p in cleaned.split("\n\n") if p.strip()]

        sections: List[ParsedSection] = []
        for i, para in enumerate(paragraphs):
            section_title = f"{title} - Section {i + 1}" if len(paragraphs) > 1 else title
            sections.append(ParsedSection(title=section_title, content=para))

        return ParsedDocument(
            source_path=rel_path,
            filename=file_path.name,
            file_type="text" if ext == ".txt" else "rst",
            title=title,
            sections=sections,
            content_hash=content_hash,
            raw_text=raw_content,
        )

    def _parse_html(self, file_path: Path, rel_path: str) -> ParsedDocument:
        raw_content = self._read_text_safely(file_path)
        content_hash = hashlib.sha256(raw_content.encode("utf-8", errors="replace")).hexdigest()

        title_match = re.search(r"<title>(.*?)</title>", raw_content, re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip() if title_match else file_path.stem

        extractor = _HTMLTextExtractor()
        try:
            extractor.feed(raw_content)
            sections = extractor.get_sections()
        except Exception:
            # Fallback simple tag strip on parse errors
            plain = clean_text(re.sub(r"<[^>]+>", " ", raw_content))
            sections = [ParsedSection(title=title, content=plain)]

        return ParsedDocument(
            source_path=rel_path,
            filename=file_path.name,
            file_type="html",
            title=title,
            sections=sections,
            content_hash=content_hash,
            raw_text=raw_content,
        )

    def _parse_pdf(self, file_path: Path, rel_path: str) -> ParsedDocument:
        # Read binary bytes for deterministic content hash
        file_bytes = file_path.read_bytes()
        content_hash = hashlib.sha256(file_bytes).hexdigest()

        reader = pypdf.PdfReader(file_path)
        title = file_path.stem
        # Check metadata for title
        if reader.metadata and reader.metadata.title:
            extracted_title = str(reader.metadata.title).strip()
            if extracted_title and len(extracted_title) < 120:
                title = extracted_title

        sections: List[ParsedSection] = []
        full_text_parts: List[str] = []

        for i, page in enumerate(reader.pages):
            try:
                page_text = page.extract_text() or ""
                cleaned = clean_text(page_text)
                if cleaned:
                    sections.append(
                        ParsedSection(
                            title=f"Page {i + 1}",
                            content=cleaned,
                            page=i + 1,
                        )
                    )
                    full_text_parts.append(cleaned)
            except Exception:
                # Continue reading subsequent pages if an individual page has rendering issues
                continue

        raw_text = "\n\n".join(full_text_parts)
        return ParsedDocument(
            source_path=rel_path,
            filename=file_path.name,
            file_type="pdf",
            title=title,
            sections=sections,
            content_hash=content_hash,
            raw_text=raw_text,
        )
