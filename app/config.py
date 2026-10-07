"""Configuration and environment management for Agentic Security Researcher."""

import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Base directory: root of agentic-security-researcher project
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env if present
load_dotenv(dotenv_path=BASE_DIR / ".env")


class Settings(BaseModel):
    """Application settings and path configurations."""

    gemini_api_key: Optional[str] = Field(
        default=None,
        repr=False,
        description="Google Gemini API key loaded from environment",
    )
    gemini_model: str = Field(
        default="gemini-2.5-flash",
        description="Google Gemini model identifier",
    )
    rag_max_sources: int = Field(
        default=5,
        description="Maximum number of retrieved sources to inject into context",
    )
    rag_max_chars: int = Field(
        default=12000,
        description="Maximum characters of context to send to Gemini",
    )
    app_env: str = Field(
        default="development",
        description="Runtime environment (development, testing, production)",
    )
    database_path: Path = Field(
        default_factory=lambda: BASE_DIR / "storage" / "researcher.db",
        description="Path to SQLite database file",
    )
    knowledge_dir: Path = Field(
        default_factory=lambda: BASE_DIR / "knowledge",
        description="Path to knowledge base root",
    )
    projects_dir: Path = Field(
        default_factory=lambda: BASE_DIR / "projects",
        description="Path to research projects workspaces",
    )
    reports_dir: Path = Field(
        default_factory=lambda: BASE_DIR / "reports",
        description="Path to generated reports directory",
    )
    embedding_model: str = Field(
        default="BAAI/bge-small-en-v1.5",
        description="Local dense embedding model identifier",
    )
    vector_store_path: Path = Field(
        default_factory=lambda: BASE_DIR / "storage" / "vector_store.npz",
        description="Path to local vector store (.npz) file",
    )
    lexical_weight: float = Field(
        default=0.5,
        description="Weight for lexical (BM25) score in hybrid fusion [0.0 - 1.0]",
    )
    semantic_weight: float = Field(
        default=0.5,
        description="Weight for semantic (cosine) score in hybrid fusion [0.0 - 1.0]",
    )
    log_level: str = Field(
        default="INFO",
        description="Application logging level",
    )

    def ensure_directories(self) -> None:
        """Create necessary system directories if they do not exist."""
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.vector_store_path.parent.mkdir(parents=True, exist_ok=True)
        self.knowledge_dir.mkdir(parents=True, exist_ok=True)
        self.projects_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    @property
    def has_gemini_key(self) -> bool:
        """Check if a Gemini API key is configured."""
        return bool(self.gemini_api_key and len(self.gemini_api_key.strip()) > 0)


_settings_instance: Optional[Settings] = None


def get_settings(reload: bool = False) -> Settings:
    """Get or initialize application settings."""
    global _settings_instance
    if _settings_instance is None or reload:
        load_dotenv(dotenv_path=BASE_DIR / ".env", override=reload)

        api_key = os.getenv("GEMINI_API_KEY")
        model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        try:
            max_sources = int(os.getenv("RAG_MAX_SOURCES", "5"))
        except ValueError:
            max_sources = 5
        try:
            max_chars = int(os.getenv("RAG_MAX_CHARS", "12000"))
        except ValueError:
            max_chars = 12000

        app_env = os.getenv("APP_ENV", "development")
        db_path_env = os.getenv("DATABASE_PATH")
        knowledge_env = os.getenv("KNOWLEDGE_DIR")
        projects_env = os.getenv("PROJECTS_DIR")
        reports_env = os.getenv("REPORTS_DIR")
        log_level = os.getenv("LOG_LEVEL", "INFO")

        embedding_model = os.getenv("EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5")
        vstore_env = os.getenv("VECTOR_STORE_PATH")
        try:
            lexical_weight = float(os.getenv("LEXICAL_WEIGHT", "0.5"))
        except ValueError:
            lexical_weight = 0.5
        try:
            semantic_weight = float(os.getenv("SEMANTIC_WEIGHT", "0.5"))
        except ValueError:
            semantic_weight = 0.5

        db_path = (
            Path(db_path_env)
            if db_path_env and Path(db_path_env).is_absolute()
            else BASE_DIR / (db_path_env or "storage/researcher.db")
        )
        vstore_path = (
            Path(vstore_env)
            if vstore_env and Path(vstore_env).is_absolute()
            else BASE_DIR / (vstore_env or "storage/vector_store.npz")
        )
        knowledge_path = (
            Path(knowledge_env)
            if knowledge_env and Path(knowledge_env).is_absolute()
            else BASE_DIR / (knowledge_env or "knowledge")
        )
        projects_path = (
            Path(projects_env)
            if projects_env and Path(projects_env).is_absolute()
            else BASE_DIR / (projects_env or "projects")
        )
        reports_path = (
            Path(reports_env)
            if reports_env and Path(reports_env).is_absolute()
            else BASE_DIR / (reports_env or "reports")
        )

        _settings_instance = Settings(
            gemini_api_key=api_key if api_key else None,
            gemini_model=model,
            rag_max_sources=max_sources,
            rag_max_chars=max_chars,
            app_env=app_env,
            database_path=db_path,
            embedding_model=embedding_model,
            vector_store_path=vstore_path,
            lexical_weight=lexical_weight,
            semantic_weight=semantic_weight,
            knowledge_dir=knowledge_path,
            projects_dir=projects_path,
            reports_dir=reports_path,
            log_level=log_level,
        )

    return _settings_instance
