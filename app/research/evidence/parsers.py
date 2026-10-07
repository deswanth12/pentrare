"""Evidence artifact parsers for Phase 7.

Extracts normalized content and factual observations from researcher-supplied
artifacts. Zero network access, zero code execution, zero request replay.
"""

import abc
import csv
import io
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.research.evidence.normalizer import clean_observation_statement, redact_secrets
from app.research.models import (
    ArtifactType,
    NormalizedEvidence,
    Observation,
    ObservationCategory,
)


class ArtifactParser(abc.ABC):
    """Abstract base class for static evidence artifact parsers."""

    artifact_type: ArtifactType = ArtifactType.UNKNOWN

    @abc.abstractmethod
    def supports(self, path: Optional[Path], content: str) -> bool:
        """Return True if this parser can process the given artifact."""
        pass

    @abc.abstractmethod
    def parse(
        self,
        path: Optional[Path],
        content: str,
        project_id: int = 0,
    ) -> NormalizedEvidence:
        """Parse raw content into normalized sections and factual observations."""
        pass


class HTTPParser(ArtifactParser):
    """Parses raw HTTP request and/or response text.

    CRITICAL SAFETY:
    - Never generates, sends, or replays network requests.
    - Only inspects the static text provided by the researcher.
    """

    artifact_type = ArtifactType.HTTP

    def supports(self, path: Optional[Path], content: str) -> bool:
        if path and path.suffix.lower() in (".http", ".req", ".resp"):
            return True
        first_line = content.strip().splitlines()[0] if content.strip() else ""
        # Check for HTTP response: HTTP/1.1 200 OK or HTTP/2 200
        if re.match(r"^HTTP/[0-9\.]+\s+\d{3}", first_line, re.IGNORECASE):
            return True
        # Check for HTTP request: GET /path HTTP/1.1
        if re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+\S+\s+HTTP/", first_line, re.IGNORECASE):
            return True
        return False

    def parse(
        self,
        path: Optional[Path],
        content: str,
        project_id: int = 0,
    ) -> NormalizedEvidence:
        redacted_content, is_redacted, _ = redact_secrets(content)
        lines = redacted_content.splitlines()
        observations: List[Observation] = []
        sections: Dict[str, str] = {}
        metadata: Dict[str, Any] = {}

        # Detect Request vs Response vs Both
        is_request = False
        is_response = False
        status_code = None
        method = None
        url = None
        headers: Dict[str, str] = {}
        body = ""

        # Check start line
        first_line = lines[0].strip() if lines else ""
        req_match = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+(HTTP/[0-9\.]+)", first_line, re.IGNORECASE)
        resp_match = re.match(r"^(HTTP/[0-9\.]+)\s+(\d{3})\s*(.*)", first_line, re.IGNORECASE)

        if req_match:
            is_request = True
            method, url, proto = req_match.groups()
            metadata["method"] = method.upper()
            metadata["url"] = url
            metadata["protocol"] = proto
            observations.append(
                Observation(
                    id=0,
                    artifact_id=0,
                    project_id=project_id,
                    category=ObservationCategory.HTTP_REQUEST,
                    statement=clean_observation_statement(f"HTTP Request: {method.upper()} {url} {proto}."),
                    source_location="line 1",
                    confidence="HIGH",
                )
            )
        elif resp_match:
            is_response = True
            proto, code_str, status_text = resp_match.groups()
            status_code = int(code_str)
            metadata["status_code"] = status_code
            metadata["status_text"] = status_text
            metadata["protocol"] = proto
            observations.append(
                Observation(
                    id=0,
                    artifact_id=0,
                    project_id=project_id,
                    category=ObservationCategory.HTTP_RESPONSE,
                    statement=clean_observation_statement(f"HTTP Response: status code {status_code} ({status_text.strip() or 'OK'})."),
                    source_location="line 1",
                    confidence="HIGH",
                )
            )

        # Parse headers and body separation
        header_lines = []
        body_lines = []
        in_body = False
        for i, line in enumerate(lines[1:], start=2):
            if not in_body:
                if line.strip() == "":
                    in_body = True
                    continue
                header_lines.append((i, line))
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            else:
                body_lines.append(line)

        sections["headers"] = "\n".join(f"{line[1]}" for line in header_lines)
        body = "\n".join(body_lines)
        sections["body"] = body[:5000]  # bounded body snapshot

        # Extract notable headers
        notable_headers = ["content-type", "server", "authorization", "set-cookie", "location", "access-control-allow-origin"]
        for k in notable_headers:
            if k in headers:
                metadata[f"header_{k}"] = headers[k]
                observations.append(
                    Observation(
                        id=0,
                        artifact_id=0,
                        project_id=project_id,
                        category=ObservationCategory.HEADER,
                        statement=clean_observation_statement(f"Header '{k}': {headers[k]}."),
                        source_location="headers",
                        confidence="HIGH",
                    )
                )

        # Body analysis (JSON probe)
        if body.strip():
            metadata["body_size_bytes"] = len(body.encode("utf-8"))
            observations.append(
                Observation(
                    id=0,
                    artifact_id=0,
                    project_id=project_id,
                    category=ObservationCategory.METADATA,
                    statement=clean_observation_statement(f"Body length is {len(body.encode('utf-8'))} bytes."),
                    source_location="body",
                    confidence="HIGH",
                )
            )
            # Check if JSON
            try:
                parsed_json = json.loads(body)
                if isinstance(parsed_json, dict):
                    keys = list(parsed_json.keys())[:10]
                    observations.append(
                        Observation(
                            id=0,
                            artifact_id=0,
                            project_id=project_id,
                            category=ObservationCategory.JSON_FIELD,
                            statement=clean_observation_statement(f"Response body is valid JSON with keys: {', '.join(keys)}."),
                            source_location="body (json)",
                            confidence="HIGH",
                        )
                    )
            except Exception:
                pass

        title = f"HTTP {'Response ' + str(status_code) if is_response else ('Request ' + str(method) if is_request else 'Traffic')}"
        summary = f"Parsed HTTP artifact: {title} with {len(header_lines)} headers and {len(body_lines)} body lines."

        return NormalizedEvidence(
            artifact_type=ArtifactType.HTTP,
            title=title,
            summary=summary,
            sections=sections,
            observations=observations,
            metadata=metadata,
            source_reference=str(path.name) if path else "raw_http",
            is_redacted=is_redacted,
        )


class HARParser(ArtifactParser):
    """Parses HTTP Archive (.har) JSON files.

    CRITICAL SAFETY:
    - Never replays entries. Zero network calls.
    - Treats all HAR data as untrusted input.
    """

    artifact_type = ArtifactType.HAR

    def supports(self, path: Optional[Path], content: str) -> bool:
        if path and path.suffix.lower() == ".har":
            return True
        if '"log"' in content and '"entries"' in content and content.strip().startswith("{"):
            return True
        return False

    def parse(
        self,
        path: Optional[Path],
        content: str,
        project_id: int = 0,
    ) -> NormalizedEvidence:
        redacted_content, is_redacted, _ = redact_secrets(content)
        observations: List[Observation] = []
        sections: Dict[str, str] = {}
        metadata: Dict[str, Any] = {}

        try:
            har_data = json.loads(redacted_content)
        except Exception as e:
            return NormalizedEvidence(
                artifact_type=ArtifactType.HAR,
                title="Malformed HAR File",
                summary=f"Failed to parse HAR JSON: {e}",
                sections={"error": str(e)},
                observations=[
                    Observation(
                        id=0,
                        artifact_id=0,
                        project_id=project_id,
                        category=ObservationCategory.ERROR,
                        statement="HAR file contains malformed JSON.",
                        source_location="root",
                        confidence="HIGH",
                    )
                ],
                metadata={"error": str(e)},
                source_reference=str(path.name) if path else "raw_har",
                is_redacted=is_redacted,
            )

        log = har_data.get("log", {})
        creator = log.get("creator", {}).get("name", "Unknown")
        entries = log.get("entries", [])
        metadata["creator"] = creator
        metadata["entry_count"] = len(entries)

        observations.append(
            Observation(
                id=0,
                artifact_id=0,
                project_id=project_id,
                category=ObservationCategory.METADATA,
                statement=clean_observation_statement(f"HAR capture created by {creator} containing {len(entries)} entry/entries."),
                source_location="log.entries",
                confidence="HIGH",
            )
        )

        entry_summaries: List[str] = []
        # Bounded iteration: inspect up to 15 entries
        for idx, entry in enumerate(entries[:15], start=1):
            req = entry.get("request", {})
            resp = entry.get("response", {})
            method = req.get("method", "GET")
            url = req.get("url", "")
            status = resp.get("status", 0)
            mime_type = resp.get("content", {}).get("mimeType", "")
            body_size = resp.get("content", {}).get("size", 0)

            statement = f"Entry {idx}: {method} {url} returned HTTP {status} ({mime_type}, {body_size} bytes)."
            entry_summaries.append(statement)

            observations.append(
                Observation(
                    id=0,
                    artifact_id=0,
                    project_id=project_id,
                    category=ObservationCategory.HTTP_RESPONSE if status else ObservationCategory.HTTP_REQUEST,
                    statement=clean_observation_statement(statement),
                    source_location=f"entries[{idx-1}]",
                    confidence="HIGH",
                )
            )

        sections["entries_summary"] = "\n".join(entry_summaries)
        title = f"HAR Capture ({len(entries)} entries)"
        summary = f"HAR capture file with {len(entries)} recorded HTTP transactions."

        return NormalizedEvidence(
            artifact_type=ArtifactType.HAR,
            title=title,
            summary=summary,
            sections=sections,
            observations=observations,
            metadata=metadata,
            source_reference=str(path.name) if path else "har_archive",
            is_redacted=is_redacted,
        )


class JSONParser(ArtifactParser):
    """Parses JSON data files and extracts structural schema observations."""

    artifact_type = ArtifactType.JSON

    def supports(self, path: Optional[Path], content: str) -> bool:
        if path and path.suffix.lower() == ".json":
            return True
        c = content.strip()
        return (c.startswith("{") and c.endswith("}")) or (c.startswith("[") and c.endswith("]"))

    def parse(
        self,
        path: Optional[Path],
        content: str,
        project_id: int = 0,
    ) -> NormalizedEvidence:
        redacted_content, is_redacted, _ = redact_secrets(content)
        observations: List[Observation] = []
        sections: Dict[str, str] = {}
        metadata: Dict[str, Any] = {}

        try:
            data = json.loads(redacted_content)
        except Exception as e:
            return NormalizedEvidence(
                artifact_type=ArtifactType.JSON,
                title="Malformed JSON",
                summary=f"Failed to parse JSON: {e}",
                sections={"error": str(e)},
                observations=[
                    Observation(
                        id=0,
                        artifact_id=0,
                        project_id=project_id,
                        category=ObservationCategory.ERROR,
                        statement="Artifact contains invalid or unparseable JSON.",
                        source_location="root",
                        confidence="HIGH",
                    )
                ],
                metadata={"error": str(e)},
                source_reference=str(path.name) if path else "raw_json",
                is_redacted=is_redacted,
            )

        if isinstance(data, dict):
            top_keys = list(data.keys())
            metadata["root_type"] = "object"
            metadata["top_keys"] = top_keys[:25]
            observations.append(
                Observation(
                    id=0,
                    artifact_id=0,
                    project_id=project_id,
                    category=ObservationCategory.JSON_FIELD,
                    statement=clean_observation_statement(f"JSON root object contains {len(top_keys)} key(s): {', '.join(top_keys[:15])}."),
                    source_location="root",
                    confidence="HIGH",
                )
            )
            # Check nested keys and types
            for k in top_keys[:10]:
                val = data[k]
                v_type = type(val).__name__
                observations.append(
                    Observation(
                        id=0,
                        artifact_id=0,
                        project_id=project_id,
                        category=ObservationCategory.JSON_FIELD,
                        statement=clean_observation_statement(f"Key '{k}' has type '{v_type}'."),
                        source_location=f"$.{k}",
                        confidence="HIGH",
                    )
                )

        elif isinstance(data, list):
            metadata["root_type"] = "array"
            metadata["array_length"] = len(data)
            observations.append(
                Observation(
                    id=0,
                    artifact_id=0,
                    project_id=project_id,
                    category=ObservationCategory.JSON_FIELD,
                    statement=clean_observation_statement(f"JSON root array contains {len(data)} element(s)."),
                    source_location="root",
                    confidence="HIGH",
                )
            )

        sections["formatted"] = json.dumps(data, indent=2)[:4000]
        title = f"JSON Data ({metadata.get('root_type', 'value')})"
        summary = f"Parsed JSON artifact with root {metadata.get('root_type')}."

        return NormalizedEvidence(
            artifact_type=ArtifactType.JSON,
            title=title,
            summary=summary,
            sections=sections,
            observations=observations,
            metadata=metadata,
            source_reference=str(path.name) if path else "json_file",
            is_redacted=is_redacted,
        )


class LogParser(ArtifactParser):
    """Parses application and system log files."""

    artifact_type = ArtifactType.LOG

    def supports(self, path: Optional[Path], content: str) -> bool:
        if path and path.suffix.lower() in (".log", ".out", ".err"):
            return True
        # Check for standard log timestamp formats
        first_lines = "\n".join(content.strip().splitlines()[:5])
        if re.search(r"\b(INFO|WARN|WARNING|ERROR|FATAL|DEBUG|CRITICAL)\b", first_lines):
            if re.search(r"\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}|[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}", first_lines):
                return True
        return False

    def parse(
        self,
        path: Optional[Path],
        content: str,
        project_id: int = 0,
    ) -> NormalizedEvidence:
        redacted_content, is_redacted, _ = redact_secrets(content)
        lines = redacted_content.splitlines()
        observations: List[Observation] = []
        sections: Dict[str, str] = {}
        metadata: Dict[str, Any] = {}

        total_lines = len(lines)
        metadata["total_lines"] = total_lines

        # Count levels
        levels_count: Dict[str, int] = {}
        errors_found: List[str] = []

        for idx, line in enumerate(lines, start=1):
            for level in ("ERROR", "FATAL", "CRITICAL", "WARN", "WARNING", "INFO", "DEBUG"):
                if re.search(rf"\b{level}\b", line):
                    levels_count[level] = levels_count.get(level, 0) + 1
                    if level in ("ERROR", "FATAL", "CRITICAL") and len(errors_found) < 5:
                        errors_found.append(f"Line {idx}: {line.strip()[:150]}")
                    break

        metadata["levels"] = levels_count
        observations.append(
            Observation(
                id=0,
                artifact_id=0,
                project_id=project_id,
                category=ObservationCategory.LOG_EVENT,
                statement=clean_observation_statement(f"Log contains {total_lines} line(s) with counts: {levels_count}."),
                source_location="summary",
                confidence="HIGH",
            )
        )

        for err_statement in errors_found:
            observations.append(
                Observation(
                    id=0,
                    artifact_id=0,
                    project_id=project_id,
                    category=ObservationCategory.ERROR,
                    statement=clean_observation_statement(f"Log event: {err_statement}"),
                    source_location="error_lines",
                    confidence="HIGH",
                )
            )

        sections["sample"] = "\n".join(lines[:50])
        title = f"Log Artifact ({total_lines} lines)"
        summary = f"Application log file with {levels_count.get('ERROR', 0)} error(s) and {levels_count.get('WARN', 0)} warning(s)."

        return NormalizedEvidence(
            artifact_type=ArtifactType.LOG,
            title=title,
            summary=summary,
            sections=sections,
            observations=observations,
            metadata=metadata,
            source_reference=str(path.name) if path else "log_file",
            is_redacted=is_redacted,
        )


class SourceCodeParser(ArtifactParser):
    """Parses source code snippets and extracts structural code observations."""

    artifact_type = ArtifactType.SOURCE_CODE

    EXTENSIONS = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".java": "java",
        ".go": "go",
        ".php": "php",
        ".rb": "ruby",
        ".cs": "csharp",
        ".c": "c",
        ".cpp": "cpp",
        ".sh": "bash",
        ".sql": "sql",
    }

    def supports(self, path: Optional[Path], content: str) -> bool:
        if path and path.suffix.lower() in self.EXTENSIONS:
            return True
        return False

    def parse(
        self,
        path: Optional[Path],
        content: str,
        project_id: int = 0,
    ) -> NormalizedEvidence:
        redacted_content, is_redacted, _ = redact_secrets(content)
        lines = redacted_content.splitlines()
        observations: List[Observation] = []
        sections: Dict[str, str] = {}
        metadata: Dict[str, Any] = {}

        lang = self.EXTENSIONS.get(path.suffix.lower() if path else "", "code")
        metadata["language"] = lang
        metadata["line_count"] = len(lines)

        observations.append(
            Observation(
                id=0,
                artifact_id=0,
                project_id=project_id,
                category=ObservationCategory.METADATA,
                statement=clean_observation_statement(f"Source code written in {lang} ({len(lines)} lines)."),
                source_location="file",
                confidence="HIGH",
            )
        )

        # Detect imports
        imports = [line.strip() for line in lines if line.strip().startswith(("import ", "from ", "const ", "require(", "#include"))]
        if imports:
            observations.append(
                Observation(
                    id=0,
                    artifact_id=0,
                    project_id=project_id,
                    category=ObservationCategory.CODE_PATTERN,
                    statement=clean_observation_statement(f"Imports / dependencies detected: {', '.join(imports[:8])}."),
                    source_location="imports",
                    confidence="HIGH",
                )
            )

        # Detect notable security-relevant code patterns (without asserting vulnerability)
        notable_patterns = [
            (r"(?i)\bjwt\.decode\s*\([^,]+,\s*(?:verify=False|options=\{.*?verify_signature.*?False)", "JWT signature verification disabled flag"),
            (r"(?i)\bverify\s*=\s*False\b", "SSL / TLS verification disabled (verify=False)"),
            (r"(?i)(exec|eval|system|popen)\s*\(", "Dynamic execution function call (eval/exec/system)"),
            (r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*?\+\s*[a-zA-Z_]", "String concatenation in SQL statement"),
            (r"(?i)dangerouslySetInnerHTML", "React dangerouslySetInnerHTML property usage"),
        ]

        for pat, desc in notable_patterns:
            for idx, line in enumerate(lines, start=1):
                if re.search(pat, line):
                    observations.append(
                        Observation(
                            id=0,
                            artifact_id=0,
                            project_id=project_id,
                            category=ObservationCategory.CODE_PATTERN,
                            statement=clean_observation_statement(f"Code pattern observed: {desc} at line {idx}."),
                            source_location=f"line {idx}",
                            confidence="MEDIUM",
                        )
                    )
                    break

        sections["code_sample"] = "\n".join(lines[:80])
        title = f"{lang.title()} Source Code ({len(lines)} lines)"
        summary = f"{lang.title()} source code file with {len(observations)} structural observation(s)."

        return NormalizedEvidence(
            artifact_type=ArtifactType.SOURCE_CODE,
            title=title,
            summary=summary,
            sections=sections,
            observations=observations,
            metadata=metadata,
            source_reference=str(path.name) if path else "code_snippet",
            is_redacted=is_redacted,
        )


class ConfigParser(ArtifactParser):
    """Parses configuration files (.ini, .env, .yaml, .conf, .toml)."""

    artifact_type = ArtifactType.CONFIGURATION

    def supports(self, path: Optional[Path], content: str) -> bool:
        if path and path.suffix.lower() in (".ini", ".env", ".yaml", ".yml", ".conf", ".toml", ".properties"):
            return True
        return False

    def parse(
        self,
        path: Optional[Path],
        content: str,
        project_id: int = 0,
    ) -> NormalizedEvidence:
        redacted_content, is_redacted, _ = redact_secrets(content)
        lines = redacted_content.splitlines()
        observations: List[Observation] = []
        sections: Dict[str, str] = {}
        metadata: Dict[str, Any] = {}

        keys: List[str] = []
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(("#", ";")) or not stripped:
                continue
            if "=" in stripped:
                k = stripped.split("=", 1)[0].strip()
                keys.append(k)
            elif ":" in stripped and not stripped.startswith("http"):
                k = stripped.split(":", 1)[0].strip()
                keys.append(k)

        metadata["key_count"] = len(keys)
        metadata["keys"] = keys[:30]

        observations.append(
            Observation(
                id=0,
                artifact_id=0,
                project_id=project_id,
                category=ObservationCategory.CONFIGURATION,
                statement=clean_observation_statement(f"Configuration file contains {len(keys)} defined key(s)."),
                source_location="file",
                confidence="HIGH",
            )
        )

        # Detect debug flags
        for idx, line in enumerate(lines, start=1):
            if re.search(r"(?i)\bdebug\s*[:=]\s*(true|1|on)\b", line):
                observations.append(
                    Observation(
                        id=0,
                        artifact_id=0,
                        project_id=project_id,
                        category=ObservationCategory.CONFIGURATION,
                        statement=clean_observation_statement("Configuration sets debug flag to enabled/true."),
                        source_location=f"line {idx}",
                        confidence="HIGH",
                    )
                )
                break

        sections["config_sample"] = "\n".join(lines[:60])
        title = f"Configuration ({len(keys)} keys)"
        summary = f"Configuration artifact containing {len(keys)} settings."

        return NormalizedEvidence(
            artifact_type=ArtifactType.CONFIGURATION,
            title=title,
            summary=summary,
            sections=sections,
            observations=observations,
            metadata=metadata,
            source_reference=str(path.name) if path else "config_file",
            is_redacted=is_redacted,
        )


class CSVParser(ArtifactParser):
    """Parses tabular CSV artifacts."""

    artifact_type = ArtifactType.CSV

    def supports(self, path: Optional[Path], content: str) -> bool:
        if path and path.suffix.lower() == ".csv":
            return True
        return False

    def parse(
        self,
        path: Optional[Path],
        content: str,
        project_id: int = 0,
    ) -> NormalizedEvidence:
        redacted_content, is_redacted, _ = redact_secrets(content)
        observations: List[Observation] = []
        sections: Dict[str, str] = {}
        metadata: Dict[str, Any] = {}

        try:
            reader = csv.reader(io.StringIO(redacted_content))
            rows = list(reader)
            if rows:
                headers = rows[0]
                metadata["columns"] = headers
                metadata["row_count"] = len(rows) - 1

                observations.append(
                    Observation(
                        id=0,
                        artifact_id=0,
                        project_id=project_id,
                        category=ObservationCategory.METADATA,
                        statement=clean_observation_statement(f"CSV contains {len(headers)} column(s) and {len(rows)-1} data row(s)."),
                        source_location="header",
                        confidence="HIGH",
                    )
                )
                observations.append(
                    Observation(
                        id=0,
                        artifact_id=0,
                        project_id=project_id,
                        category=ObservationCategory.METADATA,
                        statement=clean_observation_statement(f"Column headers: {', '.join(headers[:12])}."),
                        source_location="row 1",
                        confidence="HIGH",
                    )
                )
        except Exception as e:
            metadata["error"] = str(e)

        sections["sample"] = "\n".join(redacted_content.splitlines()[:20])
        title = f"CSV Table ({metadata.get('row_count', 0)} rows)"
        summary = f"CSV tabular dataset with {len(metadata.get('columns', []))} columns."

        return NormalizedEvidence(
            artifact_type=ArtifactType.CSV,
            title=title,
            summary=summary,
            sections=sections,
            observations=observations,
            metadata=metadata,
            source_reference=str(path.name) if path else "csv_data",
            is_redacted=is_redacted,
        )


class MarkdownParser(ArtifactParser):
    """Parses Markdown technical writeups and evidence notes."""

    artifact_type = ArtifactType.MARKDOWN

    def supports(self, path: Optional[Path], content: str) -> bool:
        if path and path.suffix.lower() in (".md", ".markdown", ".mdown"):
            return True
        lines = content.strip().splitlines()[:10]
        if any(line.strip().startswith(("# ", "## ", "### ")) for line in lines):
            return True
        return False

    def parse(
        self,
        path: Optional[Path],
        content: str,
        project_id: int = 0,
    ) -> NormalizedEvidence:
        redacted_content, is_redacted, _ = redact_secrets(content)
        lines = redacted_content.splitlines()
        observations: List[Observation] = []
        sections: Dict[str, str] = {}
        metadata: Dict[str, Any] = {}

        headings: List[Tuple[int, str]] = []
        code_blocks = 0
        in_code = False

        for idx, line in enumerate(lines, start=1):
            if line.strip().startswith("```"):
                in_code = not in_code
                if in_code:
                    code_blocks += 1
                continue
            if not in_code and line.strip().startswith(("#", "##", "###")):
                headings.append((idx, line.strip()))

        metadata["heading_count"] = len(headings)
        metadata["code_blocks"] = code_blocks

        observations.append(
            Observation(
                id=0,
                artifact_id=0,
                project_id=project_id,
                category=ObservationCategory.METADATA,
                statement=clean_observation_statement(f"Markdown document with {len(headings)} heading(s) and {code_blocks} code block(s)."),
                source_location="document",
                confidence="HIGH",
            )
        )

        for line_num, h_text in headings[:6]:
            observations.append(
                Observation(
                    id=0,
                    artifact_id=0,
                    project_id=project_id,
                    category=ObservationCategory.METADATA,
                    statement=clean_observation_statement(f"Section heading: '{h_text}'."),
                    source_location=f"line {line_num}",
                    confidence="HIGH",
                )
            )

        sections["headings"] = "\n".join(f"L{h[0]}: {h[1]}" for h in headings)
        sections["sample"] = "\n".join(lines[:40])
        title = headings[0][1].lstrip("#").strip() if headings else "Markdown Document"
        summary = f"Markdown document containing {len(headings)} sections and {code_blocks} code blocks."

        return NormalizedEvidence(
            artifact_type=ArtifactType.MARKDOWN,
            title=title,
            summary=summary,
            sections=sections,
            observations=observations,
            metadata=metadata,
            source_reference=str(path.name) if path else "markdown_note",
            is_redacted=is_redacted,
        )


class ImageParser(ArtifactParser):
    """Preserves image/screenshot metadata without requiring external OCR APIs."""

    artifact_type = ArtifactType.IMAGE

    def supports(self, path: Optional[Path], content: str) -> bool:
        if path and path.suffix.lower() in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg"):
            return True
        return False

    def parse(
        self,
        path: Optional[Path],
        content: str,
        project_id: int = 0,
    ) -> NormalizedEvidence:
        observations: List[Observation] = []
        metadata: Dict[str, Any] = {"ocr_status": "IMAGE_UNPROCESSED"}

        filename = path.name if path else "image_artifact"
        ext = path.suffix.lower().lstrip(".") if path else "image"
        metadata["format"] = ext

        observations.append(
            Observation(
                id=0,
                artifact_id=0,
                project_id=project_id,
                category=ObservationCategory.METADATA,
                statement=clean_observation_statement(f"Image artifact '{filename}' ({ext.upper()}) received (OCR: IMAGE_UNPROCESSED)."),
                source_location="image_metadata",
                confidence="HIGH",
            )
        )

        return NormalizedEvidence(
            artifact_type=ArtifactType.IMAGE,
            title=f"Image Artifact: {filename}",
            summary=f"Screenshot / image artifact ({ext.upper()}) preserved with metadata (OCR: IMAGE_UNPROCESSED).",
            sections={"status": "IMAGE_UNPROCESSED"},
            observations=observations,
            metadata=metadata,
            source_reference=filename,
            is_redacted=False,
        )


class TextParser(ArtifactParser):
    """Default fallback parser for plain text artifacts."""

    artifact_type = ArtifactType.TEXT

    def supports(self, path: Optional[Path], content: str) -> bool:
        return True  # Fallback handles all text

    def parse(
        self,
        path: Optional[Path],
        content: str,
        project_id: int = 0,
    ) -> NormalizedEvidence:
        redacted_content, is_redacted, _ = redact_secrets(content)
        lines = redacted_content.splitlines()
        observations: List[Observation] = []
        sections: Dict[str, str] = {}
        metadata: Dict[str, Any] = {}

        total_lines = len(lines)
        total_chars = len(redacted_content)
        metadata["line_count"] = total_lines
        metadata["char_count"] = total_chars

        observations.append(
            Observation(
                id=0,
                artifact_id=0,
                project_id=project_id,
                category=ObservationCategory.METADATA,
                statement=clean_observation_statement(f"Plain text artifact containing {total_lines} lines ({total_chars} characters)."),
                source_location="file",
                confidence="HIGH",
            )
        )

        # Extract non-empty sample lines
        non_empty = [l.strip() for l in lines if l.strip()]
        if non_empty:
            observations.append(
                Observation(
                    id=0,
                    artifact_id=0,
                    project_id=project_id,
                    category=ObservationCategory.METADATA,
                    statement=clean_observation_statement(f"First line: '{non_empty[0][:120]}'."),
                    source_location="line 1",
                    confidence="HIGH",
                )
            )

        sections["text_sample"] = "\n".join(lines[:50])
        title = f"Text Artifact ({total_lines} lines)"
        summary = f"Plain text evidence artifact with {total_lines} lines."

        return NormalizedEvidence(
            artifact_type=ArtifactType.TEXT,
            title=title,
            summary=summary,
            sections=sections,
            observations=observations,
            metadata=metadata,
            source_reference=str(path.name) if path else "text_file",
            is_redacted=is_redacted,
        )


class ParserRegistry:
    """Registry managing available artifact parsers in evaluation priority order."""

    def __init__(self):
        # Order matters: specialized parsers first, generic TextParser last
        self.parsers: List[ArtifactParser] = [
            HARParser(),
            HTTPParser(),
            JSONParser(),
            ImageParser(),
            LogParser(),
            SourceCodeParser(),
            ConfigParser(),
            CSVParser(),
            MarkdownParser(),
            TextParser(),
        ]

    def get_parser(self, path: Optional[Path], content: str) -> ArtifactParser:
        """Find the first matching parser for the artifact."""
        for parser in self.parsers:
            try:
                if parser.supports(path, content):
                    return parser
            except Exception:
                continue
        return TextParser()
