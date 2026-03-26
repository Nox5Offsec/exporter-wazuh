"""Tests: AgentGroupCache — global.db (primary) and filesystem (fallback)."""

import os
import sqlite3
import threading

import pytest

from soc_exporter.agent_groups import AgentGroupCache


# ---------------------------------------------------------------------------
# DB / filesystem helpers
# ---------------------------------------------------------------------------

def _make_global_db(path: str, agents: list[tuple] = (), groups: dict = None, belongs: list[tuple] = None):
    """Create a minimal global.db at *path*.

    agents:  list of (id: int, name: str, group_col: str | None)
    groups:  {id: name}  — for belongs+group tables
    belongs: list of (id_group: int, id_agent: int)
    """
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE agent (
            id      INTEGER PRIMARY KEY,
            name    TEXT,
            "group" TEXT
        );
        CREATE TABLE "group" (
            id   INTEGER PRIMARY KEY,
            name TEXT
        );
        CREATE TABLE belongs (
            id_group INTEGER,
            id_agent INTEGER
        );
    """)
    if agents:
        conn.executemany(
            'INSERT INTO agent (id, name, "group") VALUES (?, ?, ?)',
            agents,
        )
    if groups:
        conn.executemany(
            'INSERT INTO "group" (id, name) VALUES (?, ?)',
            groups.items(),
        )
    if belongs:
        conn.executemany(
            "INSERT INTO belongs (id_group, id_agent) VALUES (?, ?)",
            belongs,
        )
    conn.commit()
    conn.close()


def _make_global_db_no_belongs(path: str, agents: list[tuple]):
    """Create a global.db with only the agent table (no belongs/group tables)."""
    conn = sqlite3.connect(path)
    conn.execute('CREATE TABLE agent (id INTEGER PRIMARY KEY, name TEXT, "group" TEXT)')
    conn.executemany('INSERT INTO agent (id, name, "group") VALUES (?, ?, ?)', agents)
    conn.commit()
    conn.close()


def _make_fs_cache(tmp_path, keys_content=None, groups: dict | None = None):
    """Build a cache pointing at filesystem fixtures (fallback path)."""
    keys_file  = tmp_path / "client.keys"
    groups_dir = tmp_path / "agent-groups"
    groups_dir.mkdir()

    if keys_content is not None:
        keys_file.write_text(keys_content)

    if groups:
        for agent_id, content in groups.items():
            (groups_dir / agent_id).write_text(content)

    return AgentGroupCache(
        global_db_path=str(tmp_path / "nonexistent.db"),   # force fallback
        client_keys_path=str(keys_file),
        agent_groups_dir=str(groups_dir),
        stop_event=threading.Event(),
    )


def _make_db_cache(tmp_path, **kwargs) -> AgentGroupCache:
    """Build a cache pointing at a global.db in tmp_path."""
    db_path = str(tmp_path / "global.db")
    _make_global_db(db_path, **kwargs)
    return AgentGroupCache(
        global_db_path=db_path,
        stop_event=threading.Event(),
    )


def _event(agent_name: str) -> dict:
    """Minimal enriched event as produced by Collector._enrich()."""
    return {"raw": {"agent": {"name": agent_name}}, "hostname": "manager"}


# ---------------------------------------------------------------------------
# Primary path: global.db → belongs + "group" tables
# ---------------------------------------------------------------------------

class TestReadFromGlobalDbBelongs:
    def test_single_group(self, tmp_path):
        cache = _make_db_cache(
            tmp_path,
            agents=[(1, "NB-TEC-FELIPE", None)],
            groups={10: "nox5-tecnica"},
            belongs=[(10, 1)],
        )
        cache.load_once()
        result = cache.get_for_batch([_event("NB-TEC-FELIPE")])
        assert result == [{"agent_name": "NB-TEC-FELIPE", "group_name": "nox5-tecnica"}]

    def test_multi_group_agent(self, tmp_path):
        cache = _make_db_cache(
            tmp_path,
            agents=[(1, "AGENT-A", None)],
            groups={10: "nox5-tecnica", 20: "default"},
            belongs=[(10, 1), (20, 1)],
        )
        cache.load_once()
        result = cache.get_for_batch([_event("AGENT-A")])
        assert len(result) == 2
        group_names = {e["group_name"] for e in result}
        assert group_names == {"nox5-tecnica", "default"}

    def test_multiple_agents(self, tmp_path):
        cache = _make_db_cache(
            tmp_path,
            agents=[(1, "AGENT-A", None), (2, "AGENT-B", None)],
            groups={10: "g1", 20: "g2"},
            belongs=[(10, 1), (20, 2)],
        )
        cache.load_once()
        result = cache.get_for_batch([_event("AGENT-A"), _event("AGENT-B")])
        names = {e["agent_name"] for e in result}
        assert names == {"AGENT-A", "AGENT-B"}

    def test_normalises_group_to_lowercase(self, tmp_path):
        cache = _make_db_cache(
            tmp_path,
            agents=[(1, "AGENT-A", None)],
            groups={10: "NOX5-TECNICA"},
            belongs=[(10, 1)],
        )
        cache.load_once()
        result = cache.get_for_batch([_event("AGENT-A")])
        assert result[0]["group_name"] == "nox5-tecnica"

    def test_strips_whitespace_from_group_name(self, tmp_path):
        cache = _make_db_cache(
            tmp_path,
            agents=[(1, "AGENT-A", None)],
            groups={10: "  nox5-tecnica  "},
            belongs=[(10, 1)],
        )
        cache.load_once()
        result = cache.get_for_batch([_event("AGENT-A")])
        assert result[0]["group_name"] == "nox5-tecnica"

    def test_skips_agent_id_zero(self, tmp_path):
        """Agent id 0 is the Wazuh manager itself — must not appear in output."""
        cache = _make_db_cache(
            tmp_path,
            agents=[(0, "wazuh-manager", None), (1, "AGENT-A", None)],
            groups={10: "g1"},
            belongs=[(10, 0), (10, 1)],
        )
        cache.load_once()
        result = cache.get_for_batch([_event("wazuh-manager"), _event("AGENT-A")])
        agent_names = {e["agent_name"] for e in result}
        assert "wazuh-manager" not in agent_names
        assert "AGENT-A" in agent_names

    def test_empty_belongs_table_falls_back_to_group_column(self, tmp_path):
        """If belongs exists but has no rows, fall back to agent."group" column."""
        db_path = str(tmp_path / "global.db")
        _make_global_db(
            db_path,
            agents=[(1, "AGENT-A", "nox5-tecnica")],
            groups={},
            belongs=[],
        )
        cache = AgentGroupCache(global_db_path=db_path, stop_event=threading.Event())
        cache.load_once()
        result = cache.get_for_batch([_event("AGENT-A")])
        assert result == [{"agent_name": "AGENT-A", "group_name": "nox5-tecnica"}]


# ---------------------------------------------------------------------------
# Primary path: global.db → agent."group" column fallback
# ---------------------------------------------------------------------------

class TestReadFromGlobalDbGroupColumn:
    def test_single_group(self, tmp_path):
        db_path = str(tmp_path / "global.db")
        _make_global_db_no_belongs(db_path, agents=[(1, "AGENT-A", "nox5-tecnica")])
        cache = AgentGroupCache(global_db_path=db_path, stop_event=threading.Event())
        cache.load_once()
        result = cache.get_for_batch([_event("AGENT-A")])
        assert result == [{"agent_name": "AGENT-A", "group_name": "nox5-tecnica"}]

    def test_multi_group_comma_separated(self, tmp_path):
        db_path = str(tmp_path / "global.db")
        _make_global_db_no_belongs(db_path, agents=[(1, "AGENT-A", "nox5-tecnica,default")])
        cache = AgentGroupCache(global_db_path=db_path, stop_event=threading.Event())
        cache.load_once()
        result = cache.get_for_batch([_event("AGENT-A")])
        assert len(result) == 2
        group_names = {e["group_name"] for e in result}
        assert group_names == {"nox5-tecnica", "default"}

    def test_normalises_group_to_lowercase(self, tmp_path):
        db_path = str(tmp_path / "global.db")
        _make_global_db_no_belongs(db_path, agents=[(1, "AGENT-A", "NOX5-TECNICA")])
        cache = AgentGroupCache(global_db_path=db_path, stop_event=threading.Event())
        cache.load_once()
        result = cache.get_for_batch([_event("AGENT-A")])
        assert result[0]["group_name"] == "nox5-tecnica"

    def test_skips_null_group(self, tmp_path):
        db_path = str(tmp_path / "global.db")
        _make_global_db_no_belongs(db_path, agents=[(1, "AGENT-A", None)])
        cache = AgentGroupCache(global_db_path=db_path, stop_event=threading.Event())
        cache.load_once()
        result = cache.get_for_batch([_event("AGENT-A")])
        assert result == []

    def test_returns_empty_when_db_unreadable(self, tmp_path):
        cache = AgentGroupCache(
            global_db_path=str(tmp_path / "missing.db"),
            stop_event=threading.Event(),
        )
        cache.load_once()
        # No exception; cache is empty
        result = cache.get_for_batch([_event("AGENT-A")])
        assert result == []


# ---------------------------------------------------------------------------
# Fallback path: filesystem (client.keys + queue/agent-groups/)
# ---------------------------------------------------------------------------

class TestReadFromFilesystem:
    def test_single_group(self, tmp_path):
        cache = _make_fs_cache(
            tmp_path,
            keys_content="001 AGENT-A any key1\n",
            groups={"001": "nox5-tecnica"},
        )
        cache.load_once()
        result = cache.get_for_batch([_event("AGENT-A")])
        assert result == [{"agent_name": "AGENT-A", "group_name": "nox5-tecnica"}]

    def test_multi_group_comma_separated(self, tmp_path):
        cache = _make_fs_cache(
            tmp_path,
            keys_content="001 AGENT-A any key1\n",
            groups={"001": "nox5-tecnica,default"},
        )
        cache.load_once()
        result = cache.get_for_batch([_event("AGENT-A")])
        group_names = {e["group_name"] for e in result}
        assert group_names == {"nox5-tecnica", "default"}

    def test_normalises_to_lowercase(self, tmp_path):
        cache = _make_fs_cache(
            tmp_path,
            keys_content="001 AGENT-A any key1\n",
            groups={"001": "NOX5-TECNICA"},
        )
        cache.load_once()
        result = cache.get_for_batch([_event("AGENT-A")])
        assert result[0]["group_name"] == "nox5-tecnica"

    def test_strips_whitespace(self, tmp_path):
        cache = _make_fs_cache(
            tmp_path,
            keys_content="001 AGENT-A any key1\n",
            groups={"001": "  nox5-tecnica  , default  "},
        )
        cache.load_once()
        result = cache.get_for_batch([_event("AGENT-A")])
        group_names = {e["group_name"] for e in result}
        assert group_names == {"nox5-tecnica", "default"}

    def test_skips_manager_id_000(self, tmp_path):
        cache = _make_fs_cache(
            tmp_path,
            keys_content="000 wazuh-manager any key0\n001 AGENT-A any key1\n",
            groups={"000": "default", "001": "g1"},
        )
        cache.load_once()
        result = cache.get_for_batch([_event("wazuh-manager"), _event("AGENT-A")])
        agent_names = {e["agent_name"] for e in result}
        assert "wazuh-manager" not in agent_names

    def test_returns_empty_when_keys_missing(self, tmp_path):
        cache = _make_fs_cache(tmp_path)  # no keys file, no group files
        cache.load_once()
        result = cache.get_for_batch([_event("AGENT-A")])
        assert result == []


# ---------------------------------------------------------------------------
# get_for_batch — shared behaviour (tested with global.db)
# ---------------------------------------------------------------------------

class TestGetForBatch:
    def test_deduplicates_same_pair_in_batch(self, tmp_path):
        cache = _make_db_cache(
            tmp_path,
            agents=[(1, "AGENT-A", None)],
            groups={10: "g1"},
            belongs=[(10, 1)],
        )
        cache.load_once()
        # Same agent appears in multiple events
        events = [_event("AGENT-A")] * 3
        result = cache.get_for_batch(events)
        assert len(result) == 1

    def test_only_includes_agents_present_in_batch(self, tmp_path):
        cache = _make_db_cache(
            tmp_path,
            agents=[(1, "AGENT-A", None), (2, "AGENT-B", None)],
            groups={10: "g1", 20: "g2"},
            belongs=[(10, 1), (20, 2)],
        )
        cache.load_once()
        result = cache.get_for_batch([_event("AGENT-A")])
        names = [e["agent_name"] for e in result]
        assert "AGENT-A" in names
        assert "AGENT-B" not in names

    def test_unknown_agent_silently_omitted(self, tmp_path):
        cache = _make_db_cache(
            tmp_path,
            agents=[(1, "AGENT-A", None)],
            groups={10: "g1"},
            belongs=[(10, 1)],
        )
        cache.load_once()
        result = cache.get_for_batch([_event("UNKNOWN")])
        assert result == []

    def test_ignores_malformed_events(self, tmp_path):
        cache = _make_db_cache(
            tmp_path,
            agents=[(1, "AGENT-A", None)],
            groups={10: "g1"},
            belongs=[(10, 1)],
        )
        cache.load_once()
        malformed = [
            {"raw": {}},
            {"raw": {"agent": {}}},
            {"raw": {"agent": {"name": ""}}},
            {"no_raw": True},
        ]
        assert cache.get_for_batch(malformed) == []

    def test_output_is_deterministic(self, tmp_path):
        cache = _make_db_cache(
            tmp_path,
            agents=[(1, "AGENT-A", None), (2, "AGENT-B", None)],
            groups={10: "g1", 20: "g2"},
            belongs=[(10, 1), (20, 2)],
        )
        cache.load_once()
        events = [_event("AGENT-B"), _event("AGENT-A")]
        assert cache.get_for_batch(events) == cache.get_for_batch(events)

    def test_returns_empty_list_when_cache_empty(self, tmp_path):
        cache = AgentGroupCache(
            global_db_path=str(tmp_path / "missing.db"),
            stop_event=threading.Event(),
        )
        cache.load_once()
        assert cache.get_for_batch([_event("AGENT-A")]) == []
