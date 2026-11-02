import pytest


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    """Every test gets its own empty cache: results never depend on what an earlier test (or the user) cached."""
    monkeypatch.setenv("SECURITYHUB_CACHE_DIR", str(tmp_path / "cache"))
