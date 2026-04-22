"""Observability tests: cache LRU semantics, metric counters, bounded size."""
from __future__ import annotations

from duckicelake.catalog import DuckLakeCatalog
from duckicelake.config import load_settings


def test_cache_evicts_lru_beyond_max():
    s = load_settings()
    c = DuckLakeCatalog(s)
    c._metadata_cache_max = 3        # tight cap for the test
    c.put_cached_metadata(["ns"], "a", 1, {"x": "a"})
    c.put_cached_metadata(["ns"], "b", 1, {"x": "b"})
    c.put_cached_metadata(["ns"], "c", 1, {"x": "c"})
    # touch 'a' to make 'b' oldest
    assert c.cached_metadata(["ns"], "a", 1)["x"] == "a"
    c.put_cached_metadata(["ns"], "d", 1, {"x": "d"})
    assert c.cached_metadata(["ns"], "b", 1) is None    # evicted
    assert c.cached_metadata(["ns"], "a", 1)["x"] == "a"
    assert c.cached_metadata(["ns"], "d", 1)["x"] == "d"
    # stats should count hits + misses
    st = c.metadata_cache_stats()
    assert st["size"] == 3
    assert st["max"] == 3
    assert st["hits"] >= 3
    assert st["misses"] >= 1


def test_cache_invalidation_drops_entry():
    s = load_settings()
    c = DuckLakeCatalog(s)
    c.put_cached_metadata(["ns"], "t", 1, {"v": 1})
    assert c.cached_metadata(["ns"], "t", 1) == {"v": 1}
    c.invalidate_metadata_cache(["ns"], "t")
    assert c.cached_metadata(["ns"], "t", 1) is None


def test_cache_snapshot_mismatch_is_miss():
    s = load_settings()
    c = DuckLakeCatalog(s)
    c.put_cached_metadata(["ns"], "t", 5, {"v": 5})
    # Same table, different snap id — must not return stale cached entry.
    assert c.cached_metadata(["ns"], "t", 7) is None
    assert c.cached_metadata(["ns"], "t", 5) == {"v": 5}
