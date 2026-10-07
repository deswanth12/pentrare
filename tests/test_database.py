"""Tests for SQLite database schema and operations."""

import pytest
from app.storage.database import DatabaseManager


@pytest.fixture
def test_db(tmp_path):
    """Fixture providing an initialized SQLite database in a temporary folder."""
    db_file = tmp_path / "test_researcher.db"
    db = DatabaseManager(db_file)
    db.init_db()
    return db


def test_db_initialization(test_db):
    """Verify that all required tables are created during init_db."""
    with test_db.get_connection() as conn:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
        )
        tables = [row["name"] for row in cursor.fetchall()]

    assert "projects" in tables
    assert "research_items" in tables
    assert "evidence" in tables
    assert "findings" in tables
    assert "knowledge_chunks" in tables


def test_project_lifecycle(test_db):
    """Verify creating, listing, counting, and fetching projects."""
    assert test_db.get_project_count() == 0

    p1 = test_db.create_project("test-alpha", "First test engagement")
    assert p1["id"] is not None
    assert p1["name"] == "test-alpha"
    assert p1["description"] == "First test engagement"
    assert p1["status"] == "active"

    assert test_db.get_project_count() == 1

    fetched = test_db.get_project("test-alpha")
    assert fetched is not None
    assert fetched["id"] == p1["id"]

    # Listing
    projects = test_db.list_projects()
    assert len(projects) == 1
    assert projects[0]["name"] == "test-alpha"


def test_create_project_empty_name(test_db):
    """Verify error raised on empty project name."""
    with pytest.raises(ValueError):
        test_db.create_project("   ")


def test_create_project_duplicate(test_db):
    """Verify error raised on duplicate project name."""
    test_db.create_project("unique-target")
    with pytest.raises(Exception):
        test_db.create_project("unique-target")
