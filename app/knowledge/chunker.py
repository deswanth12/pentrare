"""Document chunker for semantic and structure-aware chunk generation."""

import re
import hashlib
from typing import List, Dict, Any, Set, Optional
from pydantic import BaseModel, Field

from .parser import ParsedDocument, ParsedSection


class KnowledgeChunk(BaseModel):
    """Structured knowledge chunk model."""
    chunk_id: str
    source_file: str
    source_path: str
    title: str
    section: str
    page: Optional[int] = None
    content: str
    content_hash: str
    tags: str = ""


# Security domain keywords for tagging
SECURITY_TAG_KEYWORDS = [
    "prompt-injection",
    "indirect-prompt-injection",
    "mcp",
    "rag",
    "llm",
    "agent",
    "active-directory",
    "kerberos",
    "api",
    "rest",
    "graphql",
    "jwt",
    "oauth",
    "sqli",
    "sql-injection",
    "xss",
    "ssrf",
    "csrf",
    "idor",
    "rce",
    "command-injection",
    "file-upload",
    "path-traversal",
    "deserialization",
    "authorization",
    "authentication",
    "privilege-escalation",
    "bypass",
    "cloud",
    "aws",
    "azure",
    "kubernetes",
    "container",
    "docker",
    "recon",
    "subdomain",
    "port-scan",
]


class DocumentChunker:
    """Splits parsed documents into semantic, coherent chunks with deterministic IDs."""

    def __init__(self, max_chunk_size: int = 1200, chunk_overlap: int = 150):
        self.max_chunk_size = max_chunk_size
        self.chunk_overlap = chunk_overlap

    def chunk(self, doc: ParsedDocument) -> List[KnowledgeChunk]:
        """Split a ParsedDocument into structured KnowledgeChunk items."""
        chunks: List[KnowledgeChunk] = []
        seen_hashes: Set[str] = set()

        tags = self._extract_tags(doc)

        chunk_idx = 0
        for section in doc.sections:
            section_chunks = self._chunk_section(section, doc, tags, chunk_idx, seen_hashes)
            chunks.extend(section_chunks)
            chunk_idx += len(section_chunks)

        return chunks

    def _extract_tags(self, doc: ParsedDocument) -> str:
        """Derive relevant security tags from path, title, and file type."""
        found_tags: Set[str] = set()

        # Add path parts as tags
        path_parts = doc.source_path.lower().replace("\\", "/").split("/")
        for part in path_parts[:-1]:  # exclude filename
            clean_part = re.sub(r"[^a-z0-9_-]", "", part.replace(" ", "-"))
            if clean_part and len(clean_part) > 2:
                found_tags.add(clean_part)

        # Keyword matching in title and source path
        text_corpus = f"{doc.source_path} {doc.title}".lower()
        for kw in SECURITY_TAG_KEYWORDS:
            kw_term = kw.replace("-", " ")
            if kw in text_corpus or kw_term in text_corpus:
                found_tags.add(kw)

        return ",".join(sorted(found_tags))

    def _generate_chunk_id(
        self, source_path: str, section: str, index: int, content_snippet: str
    ) -> str:
        """Create a 16-character deterministic chunk ID."""
        raw_key = f"{source_path}:{section}:{index}:{content_snippet}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]

    def _chunk_section(
        self,
        section: ParsedSection,
        doc: ParsedDocument,
        base_tags: str,
        start_idx: int,
        seen_hashes: Set[str],
    ) -> List[KnowledgeChunk]:
        """Process an individual section into one or more chunks."""
        text = section.content.strip()
        if not text:
            return []

        section_chunks: List[KnowledgeChunk] = []

        # If section is within max_chunk_size, retain as a single coherent chunk
        if len(text) <= self.max_chunk_size:
            c_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if c_hash not in seen_hashes:
                seen_hashes.add(c_hash)
                chunk_id = self._generate_chunk_id(doc.source_path, section.title, start_idx, text[:64])
                section_chunks.append(
                    KnowledgeChunk(
                        chunk_id=chunk_id,
                        source_file=doc.filename,
                        source_path=doc.source_path,
                        title=doc.title,
                        section=section.title,
                        page=section.page,
                        content=text,
                        content_hash=c_hash,
                        tags=base_tags,
                    )
                )
            return section_chunks

        # Otherwise, split by paragraphs
        paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
        current_part: List[str] = []
        current_len = 0
        sub_idx = 0

        for para in paragraphs:
            # If a single paragraph exceeds max_chunk_size, split on sentences/lines
            if len(para) > self.max_chunk_size:
                # Flush existing buffer
                if current_part:
                    buf_text = "\n\n".join(current_part).strip()
                    c_hash = hashlib.sha256(buf_text.encode("utf-8")).hexdigest()
                    if c_hash not in seen_hashes:
                        seen_hashes.add(c_hash)
                        cid = self._generate_chunk_id(doc.source_path, section.title, start_idx + sub_idx, buf_text[:64])
                        section_chunks.append(
                            KnowledgeChunk(
                                chunk_id=cid,
                                source_file=doc.filename,
                                source_path=doc.source_path,
                                title=doc.title,
                                section=section.title,
                                page=section.page,
                                content=buf_text,
                                content_hash=c_hash,
                                tags=base_tags,
                            )
                        )
                        sub_idx += 1
                    current_part = []
                    current_len = 0

                # Split large paragraph
                lines = para.split("\n")
                line_buf: List[str] = []
                line_len = 0
                for line in lines:
                    if line_len + len(line) + 1 > self.max_chunk_size and line_buf:
                        l_text = "\n".join(line_buf).strip()
                        c_hash = hashlib.sha256(l_text.encode("utf-8")).hexdigest()
                        if c_hash not in seen_hashes:
                            seen_hashes.add(c_hash)
                            cid = self._generate_chunk_id(doc.source_path, section.title, start_idx + sub_idx, l_text[:64])
                            section_chunks.append(
                                KnowledgeChunk(
                                    chunk_id=cid,
                                    source_file=doc.filename,
                                    source_path=doc.source_path,
                                    title=doc.title,
                                    section=section.title,
                                    page=section.page,
                                    content=l_text,
                                    content_hash=c_hash,
                                    tags=base_tags,
                                )
                            )
                            sub_idx += 1
                        line_buf = [line]
                        line_len = len(line)
                    else:
                        line_buf.append(line)
                        line_len += len(line) + 1

                if line_buf:
                    current_part = line_buf
                    current_len = line_len
                continue

            # Standard paragraph accumulation
            if current_len + len(para) + 2 > self.max_chunk_size and current_part:
                buf_text = "\n\n".join(current_part).strip()
                c_hash = hashlib.sha256(buf_text.encode("utf-8")).hexdigest()
                if c_hash not in seen_hashes:
                    seen_hashes.add(c_hash)
                    cid = self._generate_chunk_id(doc.source_path, section.title, start_idx + sub_idx, buf_text[:64])
                    section_chunks.append(
                        KnowledgeChunk(
                            chunk_id=cid,
                            source_file=doc.filename,
                            source_path=doc.source_path,
                            title=doc.title,
                            section=section.title,
                            page=section.page,
                            content=buf_text,
                            content_hash=c_hash,
                            tags=base_tags,
                        )
                    )
                    sub_idx += 1
                current_part = [para]
                current_len = len(para)
            else:
                current_part.append(para)
                current_len += len(para) + 2

        if current_part:
            buf_text = "\n\n".join(current_part).strip()
            c_hash = hashlib.sha256(buf_text.encode("utf-8")).hexdigest()
            if c_hash not in seen_hashes:
                seen_hashes.add(c_hash)
                cid = self._generate_chunk_id(doc.source_path, section.title, start_idx + sub_idx, buf_text[:64])
                section_chunks.append(
                    KnowledgeChunk(
                        chunk_id=cid,
                        source_file=doc.filename,
                        source_path=doc.source_path,
                        title=doc.title,
                        section=section.title,
                        page=section.page,
                        content=buf_text,
                        content_hash=c_hash,
                        tags=base_tags,
                    )
                )

        return section_chunks
