"""Tests for configuration and environment handling."""

import os
from pathlib import Path
from app.config import Settings, get_settings, BASE_DIR


def test_settings_defaults():
    """Verify default settings initialization without API key requirement."""
    settings = Settings()
    assert settings.app_env == "development"
    assert settings.has_gemini_key is False
    assert settings.database_path == BASE_DIR / "storage" / "researcher.db"
    assert settings.vector_store_path == BASE_DIR / "storage" / "vector_store.npz"
    assert settings.embedding_model == "BAAI/bge-small-en-v1.5"
    assert settings.lexical_weight == 0.5
    assert settings.semantic_weight == 0.5
    assert settings.knowledge_dir == BASE_DIR / "knowledge"
    assert settings.projects_dir == BASE_DIR / "projects"
    assert settings.reports_dir == BASE_DIR / "reports"


def test_settings_with_api_key():
    """Verify has_gemini_key property when key is set."""
    settings = Settings(gemini_api_key="test-mock-key")
    assert settings.has_gemini_key is True


def test_settings_directory_creation(tmp_path):
    """Verify ensure_directories creates missing folders."""
    custom_settings = Settings(
        database_path=tmp_path / "custom_storage" / "test.db",
        knowledge_dir=tmp_path / "custom_knowledge",
        projects_dir=tmp_path / "custom_projects",
        reports_dir=tmp_path / "custom_reports",
    )
    custom_settings.ensure_directories()

    assert custom_settings.database_path.parent.exists()
    assert custom_settings.knowledge_dir.exists()
    assert custom_settings.projects_dir.exists()
    assert custom_settings.reports_dir.exists()


def test_get_settings_singleton():
    """Verify get_settings returns a consistent Settings instance."""
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2
