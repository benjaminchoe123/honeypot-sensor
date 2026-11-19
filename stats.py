"""Honeypot outcomes: pull Cowrie logs from the sensor and turn them into metrics.

Run (needs the honeypot key loaded in the Windows ssh-agent):
    python stats.py

Each run:
  1. Pulls every cowrie.json* file from the VM (this is the automatic log pull).
  2. Groups events into sessions, leaves out your own IPs, and puts each session in a tier:
       scan          connected, never tried to log in (e.g. Shodan/Censys banner grabs)
       login-attempt tried credentials, never got in
       access        logged in, did nothing
       hands-on      logged in and ran commands or downloaded files
  3. Maps sessions to MITRE ATT&CK, looks up countries (cached), records one row per day
     in history.csv.
  4. Writes the vault pages (detailed archive + resume snapshot), refreshes the README
     stats block and pushes to GitHub.
  5. On any failure, or if traffic stops growing, adds an alert to the vault todo list
     and records it in runs.log, so a broken sensor doesn't go unnoticed.

Private settings (VM address, your IPs, local folders) live in config.local.json,
which is gitignored. See config.example.json.

SECURITY: everything an attacker typed (usernames, passwords, commands) is hostile
text. It's sanitized before it is written anywhere, and nothing that reads these
outputs later (including an LLM) should ever treat it as instructions.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import time
import urllib.request
import zipfile
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from country_codes import ALPHA2_TO_NUMERIC

REPO = Path(__file__).resolve().parent
SSH = r"C:\Windows\System32\OpenSSH\ssh.exe"  # Windows ssh, so it uses the Windows agent
REMOTE_DIR = "/home/cowrie/my-honeypot/var/log/cowrie"
HISTORY = REPO / "history.csv"
README = REPO / "README.md"
RUN_LOG = REPO / "runs.log"
DASHBOARD_DATA = REPO / "docs" / "data.json"
REMOTE_SAMPLES = "/home/cowrie/my-honeypot/var/lib/cowrie/downloads"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # hash of a 0-byte file
MIN_SAMPLE_BYTES = 64      # smaller files are shell probes (echo tests), not malware
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

LOG_NAME = re.compile(r"^cowrie\.json(\.\d{4}-\d{2}-\d{2})?$")
BRUTE_FORCE_THRESHOLD = 5  # failed logins from one IP before it counts as T1110 brute force
STALE_DAYS = 2             # alert if connections haven't grown for this many daily runs
TIERS = ("scan", "login-attempt", "access", "hands-on")

# Command patterns -> MITRE ATT&CK technique. A keyword-based first pass.
ATTACK_RULES = [
    (re.compile(r"/proc/self/(exe|cmdline)|\buname\b|cpuinfo|\bnproc\b|busybox [A-Z]{4,}"),
     "T1082 System Information Discovery"),
    (re.compile(r"\b(wget|curl|tftp|ftpget)\b"), "T1105 Ingress Tool Transfer"),
    (re.compile(r"\bchmod\b"), "T1222.002 Linux File Permissions Modification"),
    (re.compile(r"\brm -rf\b|history -c|unset HISTFILE"), "T1070 Indicator Removal"),
    (re.compile(r"authorized_keys"), "T1098.004 SSH Authorized Keys"),
    (re.compile(r"\bcrontab\b|/etc/cron"), "T1053.003 Cron"),
]


# ---------------------------------------------------------------- config & pull

@dataclass
class Config:
    host: str
    own_ips: set
    log_dir: Path
    vault_dir: Path
    key: str
    backup_dir: Path | None = None

    @property
    def stats_page(self) -> Path:
        return self.vault_dir / "03-resources" / "Honeypot-Stats.md"

    @property
    def resume_page(self) -> Path:
        return self.vault_dir / "03-resources" / "Honeypot-Resume.md"

    @property
    def todo(self) -> Path:
        return self.vault_dir / "todo.md"

    @property
    def geo_cache(self) -> Path:
        return self.log_dir / "geo-cache.json"


def load_config(path: Path = REPO / "config.local.json") -> Config:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return Config(
        host=raw["host"],
        own_ips=set(raw.get("own_ips", [])),
        log_dir=Path(raw["log_dir"]),
        vault_dir=Path(raw["vault_dir"]),
        key=raw.get("ssh_key", str(Path.home() / ".ssh" / "honeypot")),
        backup_dir=Path(raw["backup_dir"]) if raw.get("backup_dir") else None,
    )


def backup_logs(log_dir: Path, backup_dir: Path) -> Path:
    """Zip every cowrie.json* into one archive in a cloud-synced folder (e.g. OneDrive).

    Overwritten each run; the sync service's version history keeps older copies.
    Written to a temp name first, so a crash never leaves a half-written backup.
    """
    backup_dir.mkdir(parents=True, exist_ok=True)
    target, tmp = backup_dir / "cowrie-logs.zip", backup_dir / "cowrie-logs.zip.tmp"
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(log_dir.glob("cowrie.json*")):
            zf.write(path, path.name)
    tmp.replace(target)
    return target


def pull_logs(cfg: Config) -> None:
    """Stream the log folder over SSH as a tarball and extract only cowrie.json* files."""
    cmd = [SSH, "-i", cfg.key, "-p", "22222", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
           cfg.host, f"sudo tar -czf - -C {REMOTE_DIR} ."]
    data = subprocess.run(cmd, capture_output=True, check=True, timeout=180).stdout
    cfg.log_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for member in tf.getmembers():
            name = member.name.removeprefix("./")
            if member.isfile() and LOG_NAME.match(name):
                member.name = name
                tf.extract(member, cfg.log_dir, filter="data")  # 'data' filter blocks path tricks


def parse_sample_sizes(listing: str) -> dict:
    """`find -printf '%f %s\\n'` output -> {sha256: bytes}. Lines that aren't 'sha256 size' are dropped."""
    sizes = {}
    for line in listing.splitlines():
        parts = line.split()
        if len(parts) == 2 and _SHA256.match(parts[0]) and parts[1].isdigit():
            sizes[parts[0]] = int(parts[1])
    return sizes


def pull_sample_sizes(cfg: Config) -> dict:
    """File sizes of captured samples on the VM (Cowrie doesn't log size). Cached between runs."""
    cache = cfg.log_dir / "sample-sizes.json"
    try:
        sizes = json.loads(cache.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        sizes = {}
    cmd = [SSH, "-i", cfg.key, "-p", "22222", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", cfg.host,
           f"sudo find {REMOTE_SAMPLES} -maxdepth 1 -type f -printf '%f %s\\n'"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=60).stdout
    sizes.update(parse_sample_sizes(out))
    cache.write_text(json.dumps(sizes, indent=0), encoding="utf-8")
    return sizes


# ---------------------------------------------------------------- parsing

def load_sessions(log_dir: Path, own_ips: set) -> dict:
    """Read every log line once and group events by session id.

    Dedupe on the raw line: Cowrie's "uuid" field is the SENSOR's id (the same on
    every event), so it can't identify an event.
    """
    seen, sessions = set(), {}
    for path in sorted(log_dir.glob("cowrie.json*")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line in seen:
                continue
            seen.add(line)
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue  # truncated line from a log being written
            if not isinstance(ev, dict) or ev.get("src_ip") in own_ips:
                continue
            s = sessions.setdefault(ev.get("session"), {
                "ip": ev.get("src_ip"), "protocol": ev.get("protocol", "?"),
                "start": ev.get("timestamp", ""), "login_ok": False, "failed_logins": 0,
                "creds": [], "commands": [], "downloads": [], "events": 0,
            })
            s["events"] += 1
            eid = ev.get("eventid", "")
            if eid in ("cowrie.login.success", "cowrie.login.failed"):
                s["creds"].append((str(ev.get("username", "")), str(ev.get("password", ""))))
                if eid.endswith("success"):
                    s["login_ok"] = True
                else:
                    s["failed_logins"] += 1
            elif eid == "cowrie.command.input":
                s["commands"].append(str(ev.get("input", "")))
            elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
                # Uploads are files pushed over SCP/SFTP, mostly by SSH bots. Same evidence, other channel.
                s["downloads"].append({"url": str(ev.get("url", "")), "sha256": str(ev.get("shasum", "")),
                                       "kind": "upload" if eid.endswith("upload") else "download"})
    return sessions


def tier(s: dict) -> str:
    """How far did this session get? (See TIERS.)"""
    if s["commands"] or s["downloads"]:
        return "hands-on"
    if s["login_ok"]:
        return "access"
    if s["creds"]:
        return "login-attempt"
    return "scan"


def brute_force_ips(sessions: dict) -> set:
    """IPs with at least BRUTE_FORCE_THRESHOLD failed logins across all their sessions."""
    failures = Counter()
    for s in sessions.values():
        failures[s["ip"]] += s["failed_logins"]
    return {ip for ip, n in failures.items() if n >= BRUTE_FORCE_THRESHOLD}


def techniques(s: dict, brute_ips: set) -> set:
    found = set()
    if s["login_ok"]:
        found.add("T1078 Valid Accounts")
    if s["ip"] in brute_ips and s["failed_logins"]:
        found.add("T1110 Brute Force")
    if s["commands"]:
        found.add("T1059.004 Unix Shell")
    text = "\n".join(s["commands"])
    found.update(t for pattern, t in ATTACK_RULES if pattern.search(text))
    return found


_URL = re.compile(r"\b(?:https?|ftp|tftp)://\S+")
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")


def campaign_id(s: dict) -> str | None:
    """Fingerprint of a session's command script, so repeat runs of one campaign group together.

    Download servers rotate between bots of the same campaign, so URLs and IPs are
    replaced with placeholders before hashing. Sessions without commands get None.
    """
    if not s["commands"]:
        return None
    return hashlib.sha256(normalized_script(s).encode()).hexdigest()[:8]


def normalized_script(s: dict) -> str:
    """The session's commands with URLs and IPs replaced by placeholders, whitespace collapsed."""
    return "\n".join(" ".join(_IP.sub("<ip>", _URL.sub("<url>", c)).split()) for c in s["commands"])


# Behavior tags for a campaign's (normalized) command script, in priority order.
# Tags are fixed labels, so no attacker text ever reaches the public page through them.
_MINERS = r"xmrig|minerd|kinsing|kdevtmpfsi|c3pool|nanopool|cryptonight|\bminer"
CAMPAIGN_TAG_RULES = [
    (re.compile(r"authorized_keys"), "adds SSH key"),
    (re.compile(rf"\b(pkill|killall|kill)\b[^\n]*({_MINERS})|({_MINERS})[^\n]*\b(pkill|killall|kill)\b"),
     "kills competing miners"),
    (re.compile(r"\b(wget|curl|tftp|ftpget)\b|<url>"), "downloads payload"),
    (re.compile(r"\bchpasswd\b|\bpasswd\b"), "changes password"),
    (re.compile(r"\bcrontab\b|/etc/cron|rc\.local|systemctl enable"), "sets up persistence"),
    (re.compile(r"history -c|unset HISTFILE|rm -rf? [^\n]*(log|history)|> ?/var/log"), "removes logs"),
    # Mirai-style: write+run a test file in folder after folder until one is writable and executable.
    (re.compile(r"([^\n]*>\s*/[\w/]*\.\w+\s*&&[^\n]*\n){3,}"), "hunts for writable folder"),
    (re.compile(r"\b(pkill|killall|kill -9)\b"), "kills processes"),
    (re.compile(r"chmod \+?x|chmod 7"), "makes file executable"),
    # Router/DVR CLIs: typing these breaks out of the vendor's restricted menu into a real shell.
    (re.compile(r"^(enable|system|linuxshell)$", re.M), "escapes restricted shell"),
    (re.compile(r"busybox (hostname )?[A-Z]{4,}|/proc/self/exe"), "fingerprints device"),
    (re.compile(r"sip:", re.I), "probes for VoIP (SIP)"),
]
_RECON = re.compile(r"\buname\b|cpuinfo|\bnproc\b|\blscpu\b|\bfree\b|\bwhoami\b|/proc/|\bid\b|\bw\b|\bps\b|\bdf\b")


def campaign_tags(script: str, limit: int = 3) -> list[str]:
    """1-3 plain-English behavior tags for a command script."""
    tags = [label for pattern, label in CAMPAIGN_TAG_RULES if pattern.search(script)]
    if not tags:
        tags = ["recon only"] if _RECON.search(script) else ["tests the shell"]
    return tags[:limit]


def is_interesting(s: dict) -> bool:
    """Decide whether a session deserves a closer human look (and, later, paid Claude analysis).

    `s` has: ip, protocol, start, login_ok, failed_logins, creds [(user, pw)],
    commands [str], downloads [{url, sha256}].

    TODO(Big Ben): write this rule. 5-10 lines.
    """
    return False


# ---------------------------------------------------------------- enrichment & metrics

def lookup_countries(ips: set, cache_path: Path) -> tuple[dict, dict, bool]:
    """IP -> country via ip-api.com's free batch API (no key; 100 IPs/request, 15 requests/min).

    Cached, so each IP is only looked up once. Cache values are {"country", "cc"}; entries in
    the old name-only format are looked up again so the map gets a country code.
    Returns (ip -> country name, country name -> ISO alpha-2, ok). Geo data is nice to
    have: on failure the run continues and those IPs count as unknown.
    """
    try:
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cache = {}
    missing = sorted(ip for ip in ips if ip and not isinstance(cache.get(ip), dict))
    ok = True
    for i in range(0, len(missing), 100):
        body = json.dumps([{"query": ip, "fields": "status,country,countryCode,query"}
                           for ip in missing[i:i + 100]]).encode()
        req = urllib.request.Request("http://ip-api.com/batch", data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                for row in json.load(resp):
                    if row.get("status") == "success":
                        cache[row["query"]] = {"country": row["country"], "cc": row.get("countryCode", "")}
        except (OSError, ValueError):
            ok = False
            break
        if i + 100 < len(missing):
            time.sleep(4.5)  # stay under 15 batch requests/minute
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(cache, indent=0), encoding="utf-8")
    names = {ip: v["country"] if isinstance(v, dict) else v for ip, v in cache.items()}
    codes = {v["country"]: v["cc"] for v in cache.values() if isinstance(v, dict) and v.get("cc")}
    return names, codes, ok


def atlas_id(alpha2: str) -> str | None:
    """ISO alpha-2 (what ip-api returns) -> the numeric id world-atlas uses, e.g. 'NL' -> '528'."""
    return ALPHA2_TO_NUMERIC.get((alpha2 or "").upper())


def _day(ts: str) -> str:
    return ts[:10] if ts else ""


def daily_activity(attackers: list, before: str | None = None) -> list:
    """Per UTC day: new attacker sessions and attacker IPs seen for the first time (not cumulative).

    Every day between the first and last session is listed, so a quiet day shows as 0, not a gap.
    Days on or after `before` (default: today, UTC) are left out: a day still in progress would
    look like a sudden drop in attacks.
    """
    before = before or f"{datetime.now(UTC):%Y-%m-%d}"
    sessions_per_day, first_seen = Counter(), {}
    for s in attackers:
        d = _day(s["start"])
        if not d or d >= before:
            continue
        sessions_per_day[d] += 1
        if d < first_seen.get(s["ip"], "9999"):
            first_seen[s["ip"]] = d
    if not sessions_per_day:
        return []
    new_ips = Counter(first_seen.values())
    start, end = datetime.fromisoformat(min(sessions_per_day)), datetime.fromisoformat(max(sessions_per_day))
    days = [(start + timedelta(days=i)).strftime("%Y-%m-%d") for i in range((end - start).days + 1)]
    return [{"date": d, "sessions": sessions_per_day[d], "new_ips": new_ips[d]} for d in days]


def is_real_sample(sha: str, sizes: dict) -> bool:
    """A captured file worth listing: a valid hash, not the empty file, not a tiny shell probe."""
    if not _SHA256.match(sha) or sha == EMPTY_SHA256:
        return False
    size = sizes.get(sha)
    return size is None or size >= MIN_SAMPLE_BYTES


def sample_details(ss: list, sizes: dict) -> list:
    """One row per real sample: first seen, how many sessions/IPs dropped it, size, how it arrived."""
    rows: dict[str, dict] = {}
    for s in ss:
        for d in s["downloads"]:
            sha = d["sha256"]
            if not is_real_sample(sha, sizes):
                continue
            r = rows.setdefault(sha, {"sha256": sha, "first_seen": "9999", "sessions": set(), "ips": set(),
                                      "size": sizes.get(sha), "kind": d.get("kind", "download"),
                                      "url": d["url"]})
            r["first_seen"] = min(r["first_seen"], _day(s["start"]) or "9999")
            r["sessions"].add(id(s))
            r["ips"].add(s["ip"])
    out = [{**r, "first_seen": r["first_seen"] if r["first_seen"] != "9999" else "",
            "sessions": len(r["sessions"]), "ips": len(r["ips"])} for r in rows.values()]
    return sorted(out, key=lambda r: (-r["ips"], -r["sessions"], r["first_seen"]))


def campaign_details(ss: list, top: int = 8) -> list:
    """Largest campaigns by unique source IP, with dates, size and behavior tags (never the commands)."""
    groups: dict[str, dict] = {}
    for s in ss:
        cid = campaign_id(s)
        if not cid:
            continue
        g = groups.setdefault(cid, {"id": cid, "ips": set(), "sessions": 0, "first_seen": "9999",
                                    "last_seen": "", "script": normalized_script(s)})
        g["ips"].add(s["ip"])
        g["sessions"] += 1
        d = _day(s["start"])
        if d:
            g["first_seen"], g["last_seen"] = min(g["first_seen"], d), max(g["last_seen"], d)
    ranked = sorted(groups.values(), key=lambda g: (-len(g["ips"]), -g["sessions"]))[:top]
    return [{"id": g["id"], "ips": len(g["ips"]), "sessions": g["sessions"],
             "first_seen": g["first_seen"] if g["first_seen"] != "9999" else "", "last_seen": g["last_seen"],
             "tags": campaign_tags(g["script"])} for g in ranked]


def summarize(sessions: dict, geo: dict, today: str | None = None,
              sizes: dict | None = None, codes: dict | None = None) -> dict:
    """Every number, computed once and shared by every output.

    geo: ip -> country name. codes: country name -> ISO alpha-2. sizes: sha256 -> bytes.
    """
    sizes, codes = sizes or {}, codes or {}
    ss = list(sessions.values())
    brute = brute_force_ips(sessions)
    tiers = Counter(tier(s) for s in ss)
    attackers = [s for s in ss if tier(s) != "scan"]
    attacker_ips = {s["ip"] for s in attackers}
    starts = sorted(s["start"] for s in ss if s["start"])
    first = datetime.fromisoformat(starts[0].replace("Z", "+00:00")) if starts else None
    techs = Counter(t for s in ss for t in techniques(s, brute))
    samples = {d["sha256"]: d["url"] or ("SCP/SFTP upload" if d.get("kind") == "upload" else "")
               for s in ss for d in s["downloads"] if is_real_sample(d["sha256"], sizes)}
    # Size campaigns by unique IPs, not sessions: one stuck bot retrying 15 times is one device.
    campaign_ips: dict[str, set] = {}
    for s in ss:
        if c := campaign_id(s):
            campaign_ips.setdefault(c, set()).add(s["ip"])
    campaigns = Counter({c: len(ips) for c, ips in campaign_ips.items()})
    # Countries by unique attacker IP: one noisy bot shouldn't make its country look like the main source.
    country_ips: dict[str, set] = {}
    for ip in attacker_ips:
        country_ips.setdefault(geo.get(ip, "Unknown"), set()).add(ip)
    return {
        "date": today or f"{datetime.now():%Y-%m-%d}",
        "days": (datetime.now(UTC) - first).days + 1 if first else 0,
        "events": sum(s["events"] for s in ss),
        "connections": len(ss),
        "all_ips": len({s["ip"] for s in ss}),
        "scans": tiers["scan"],
        "login_attempt": tiers["login-attempt"],
        "access": tiers["access"],
        "hands_on": tiers["hands-on"],
        "campaigns": len(campaigns),
        "top_campaign_ips": max(campaigns.values(), default=0),
        "attacker_sessions": len(attackers),
        "attacker_ips": len(attacker_ips),
        "countries": len({geo[ip] for ip in attacker_ips if ip in geo}),
        "ssh": sum(s["protocol"] == "ssh" for s in attackers),
        "telnet": sum(s["protocol"] == "telnet" for s in attackers),
        "login_attempts": sum(len(s["creds"]) for s in ss),
        "logins_ok": sum(s["login_ok"] for s in ss),
        "samples": len(samples),
        "techniques": len(techs),
        "interesting": sum(is_interesting(s) for s in ss),
        # below: detail for the pages, not saved to history.csv
        "_techs": techs,
        "_creds": Counter(c for s in ss for c in s["creds"]),
        "_countries": Counter({c: len(ips) for c, ips in country_ips.items()}),  # unique attacker IPs
        "_country_sessions": Counter(geo.get(s["ip"], "Unknown") for s in attackers),
        "_country_codes": codes,
        "_tried_login": sum(bool(s["creds"]) for s in ss),
        "_daily": daily_activity(attackers),
        "_cmds": Counter(c for s in ss for c in s["commands"] if c.strip()),
        "_samples": samples,
        "_sample_details": sample_details(ss, sizes),
        "_campaigns": campaigns,
        "_campaign_details": campaign_details(ss),
        "_interesting": [s for s in ss if is_interesting(s)],
    }


HISTORY_FIELDS = ["date", "days", "events", "connections", "all_ips", "scans", "login_attempt",
                  "access", "hands_on", "campaigns", "top_campaign_ips", "attacker_sessions", "attacker_ips",
                  "countries", "ssh", "telnet", "login_attempts", "logins_ok", "samples", "techniques", "interesting"]


def update_history(m: dict, path: Path = HISTORY) -> list:
    """One row per day; a second run on the same day replaces that day's row.

    Rows from older schemas are kept; columns they don't have stay blank.
    """
    rows = []
    if path.exists():
        with path.open(newline="", encoding="utf-8") as f:
            rows = [r for r in csv.DictReader(f) if r.get("date") != m["date"]]
    rows.append({k: m[k] for k in HISTORY_FIELDS})
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=HISTORY_FIELDS, restval="", extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    return rows


def is_stale(history: list, days: int = STALE_DAYS) -> bool:
    """True if total connections haven't grown over the last `days` daily rows."""
    vals = [r.get("connections", "") for r in history[-(days + 1):]]
    return len(vals) == days + 1 and all(v != "" for v in vals) and len(set(vals)) == 1


# ---------------------------------------------------------------- rendering

_UNSAFE = str.maketrans({"`": "'", "|": "¦", "[": "(", "]": ")", "<": "‹", ">": "›",
                         "\n": " ", "\r": " ", "*": "∗", "#": "＃"})


def clean(text: object, limit: int = 90) -> str:
    """Make attacker text safe to show in Markdown: one line, no code/link/table/HTML syntax."""
    text = str(text).translate(_UNSAFE)
    return text[:limit] + ("…" if len(text) > limit else "")


def cred(u: str, p: str, limit: int = 30) -> str:
    """'user / password' for display, with empty values shown as (blank)."""
    return f"{clean(u, limit) or '(blank)'} / {clean(p, limit) or '(blank)'}"


def plural(n: int, word: str) -> str:
    if n != 1:
        word = word[:-1] + "ies" if word.endswith("y") and word[-2:-1] not in "aeiou" else word + "s"
    return f"{n:,} {word}"


def funnel_table(m: dict) -> list:
    return [
        "| Tier | Sessions | Meaning |", "|---|---|---|",
        f"| Scan | {m['scans']:,} | Connected, never tried to log in |",
        f"| Login attempt | {m['login_attempt']:,} | Tried credentials, never got in |",
        f"| Access | {m['access']:,} | Logged in, did nothing |",
        f"| Hands-on | {m['hands_on']:,} | Logged in and ran commands or downloaded files |",
    ]


def render_archive(m: dict) -> str:
    """One dated section for the detailed vault archive (Honeypot-Stats.md)."""
    out = [f"\n## Run {datetime.now():%Y-%m-%d %H:%M} (all-time totals)\n",
           f"{plural(m['connections'], 'connection')} from {plural(m['all_ips'], 'IP')}; "
           f"{plural(m['attacker_sessions'], 'attacker session')} from "
           f"{plural(m['attacker_ips'], 'attacker IP')} in {plural(m['countries'], 'country')}.\n"]
    out += funnel_table(m)
    out += ["", "**Top credentials tried**", ""]
    out += [f"- {cred(u, p, 30)} ({n})" for (u, p), n in m["_creds"].most_common(10)]
    out += ["", "**ATT&CK techniques observed (sessions)**", ""]
    out += [f"- {t} ({n})" for t, n in m["_techs"].most_common()]
    out += ["", "**Top commands** (attacker text, sanitized)", ""]
    out += [f"- {clean(c)} ({n})" for c, n in m["_cmds"].most_common(10)]
    out += ["", "**Captured samples (SHA-256)**: look up on VirusTotal, never run", ""]
    out += [f"- {h} from {clean(u, 60) or 'inline write'}" for h, u in m["_samples"].items()]
    out += ["", "**Interesting sessions**", ""]
    out += [f"- {s['start'][:19]} {s['ip']} {s['protocol']}: {len(s['commands'])} cmds, "
            f"{len(s['downloads'])} downloads" for s in m["_interesting"]]
    return "\n".join(out) + "\n"


def resume_bullets(m: dict) -> list:
    return [
        f"- Deployed a hardened SSH/Telnet honeypot on Google Cloud with egress filtering and isolated "
        f"admin access; recorded {plural(m['attacker_sessions'], 'attacker session')} from "
        f"{plural(m['attacker_ips'], 'unique IP')} across {plural(m['countries'], 'country')} "
        f"over {plural(m['days'], 'day')}, filtering out {m['scans']:,} scanner connections by "
        f"classifying sessions by attack depth.",
        f"- Clustered {plural(m['hands_on'], 'hands-on session')} into "
        f"{plural(m['campaigns'], 'distinct attack campaign')} by command fingerprint (largest: "
        f"{plural(m['top_campaign_ips'], 'source IP')}) and mapped behavior to "
        f"{plural(m['techniques'], 'MITRE ATT&CK technique')}, including Mirai-style Telnet botnet loaders.",
        f"- Built a tested Python pipeline (pytest, CI) that collects, classifies and publishes metrics "
        f"daily from {m['events']:,} logged events; [after writing one: documented the largest "
        f"campaigns in case studies with detection and prevention recommendations].",
    ]


def render_resume(m: dict, history: list) -> str:
    """The resume-ready page. Fully regenerated each run: it's a view of the data, not notes."""
    ready = m["days"] >= 14 and m["attacker_ips"] >= 100

    def share(n: int) -> str:
        return f"{100 * n / m['attacker_sessions']:.0f}%" if m["attacker_sessions"] else "0%"

    lines = [
        "---", "title: Honeypot Resume Snapshot", "type: resource",
        "tags: [honeypot, resume, metrics]", "created: 2026-11-05", f"updated: {m['date']}", "---", "",
        "# Honeypot: Resume Snapshot", "",
        "> Auto-generated by `stats.py` on every run. Hand edits get overwritten; copy text out of "
        "here instead. Detailed archive: [[03-resources/Honeypot-Stats]]. "
        "Project: [[01-projects/Honeypot-Sensor]].", "",
        f"**As of {m['date']}, after {plural(m['days'], 'day')} of collection.** "
        + ("✅ Enough data to use on the resume." if ready else
           "⏳ Not resume-ready yet: aim for at least 14 days and 100+ attacker IPs."), "",
        "## Headline numbers", "",
        "| Metric | Value |", "|---|---|",
        f"| Days running | {m['days']} |",
        f"| Attacker sessions (tried to log in or further) | {m['attacker_sessions']:,} |",
        f"| Unique attacker IPs | {m['attacker_ips']:,} |",
        f"| Countries | {m['countries']} |",
        f"| Successful logins | {m['logins_ok']:,} |",
        f"| Hands-on sessions (ran commands / downloads) | {m['hands_on']:,} |",
        f"| Distinct attack campaigns (command fingerprints) | {m['campaigns']:,} "
        f"(largest: {plural(m['top_campaign_ips'], 'source IP')}) |",
        f"| Malware samples captured | {m['samples']} |",
        f"| MITRE ATT&CK techniques observed | {m['techniques']} |",
        f"| Telnet / SSH split (attacker sessions) | {share(m['telnet'])} / {share(m['ssh'])} |",
        f"| Scanner connections filtered out | {m['scans']:,} |",
        f"| Events logged | {m['events']:,} |", "",
        "## Attack-depth funnel", "",
    ]
    lines += funnel_table(m)
    lines += ["", "## Resume bullets (filled with today's real numbers)", "",
              "**Internet-Facing Honeypot & Threat-Intel Sensor** | Google Cloud, Cowrie, Python, MITRE ATT&CK", ""]
    lines += resume_bullets(m)
    lines += ["", "## Interview talking points", "",
              "**Most-tried credentials** (shows why default passwords get devices owned):", ""]
    lines += [f"- {cred(u, p, 30)} ({n:,})" for (u, p), n in m["_creds"].most_common(5)]
    lines += ["", f"**ATT&CK techniques** (keyword-based first pass; brute force needs "
              f"{BRUTE_FORCE_THRESHOLD}+ failures from one IP):", ""]
    lines += [f"- {t} ({plural(n, 'session')})" for t, n in m["_techs"].most_common()]
    lines += ["", "**Top source countries** (where the attacking machine is, usually an infected "
              "device, not where the attacker lives):", ""]
    lines += [f"- {clean(c, 40)} ({plural(n, 'unique IP')})" for c, n in m["_countries"].most_common(5)]
    lines += ["", "## Growth over time", "",
              "| Date | Days | Attacker sessions | Attacker IPs | Hands-on | Countries | Samples |",
              "|---|---|---|---|---|---|---|"]
    lines += [f"| {r['date']} | {r.get('days', '')} | {r.get('attacker_sessions') or '-'} | "
              f"{r.get('attacker_ips') or '-'} | {r.get('hands_on') or '-'} | {r.get('countries', '')} | "
              f"{r.get('samples', '')} |" for r in history]
    return "\n".join(lines) + "\n"


def render_public(m: dict, history: list) -> str:
    """Aggregate-only stats for the public README: no attacker IPs, no raw commands."""
    lines = [f"_Last updated {m['date']} · {plural(m['days'], 'day')} of collection · "
             f"updated automatically every day._", "",
             "| Metric | Value |", "|---|---|",
             f"| Attacker sessions | {m['attacker_sessions']:,} |",
             f"| Unique attacker IPs | {m['attacker_ips']:,} |",
             f"| Countries | {m['countries']} |",
             f"| Successful logins | {m['logins_ok']:,} |",
             f"| Hands-on sessions | {m['hands_on']:,} |",
             f"| Distinct attack campaigns | {m['campaigns']:,} "
             f"(largest: {plural(m['top_campaign_ips'], 'source IP')}) |",
             f"| Malware samples captured | {m['samples']} |",
             f"| MITRE ATT&CK techniques observed | {m['techniques']} |",
             f"| Scanner connections filtered out | {m['scans']:,} |", "",
             "**Attack-depth funnel**", ""]
    lines += funnel_table(m)
    lines += ["", "**ATT&CK techniques observed** (sessions)", ""]
    lines += [f"- {t} ({n:,})" for t, n in m["_techs"].most_common()]
    lines += ["", "**Top source countries** (unique attacker IPs; location of the attacking machine, "
              "usually an infected device)", ""]
    lines += [f"- {clean(c, 40)} ({plural(n, 'unique IP')})" for c, n in m["_countries"].most_common(5)]
    lines += ["", "**Most-tried credentials**", ""]
    lines += [f"- {cred(u, p, 30)} ({n:,})" for (u, p), n in m["_creds"].most_common(5)]
    lines += ["", "<details><summary>Daily growth</summary>", "",
              "| Date | Attacker sessions | Attacker IPs | Hands-on | Countries | Samples |",
              "|---|---|---|---|---|---|"]
    lines += [f"| {r['date']} | {r.get('attacker_sessions') or '-'} | {r.get('attacker_ips') or '-'} | "
              f"{r.get('hands_on') or '-'} | {r.get('countries', '')} | {r.get('samples', '')} |"
              for r in history[-60:]]
    lines += ["", "</details>"]
    return "\n".join(lines)


HISTORY_CHART_FIELDS = ("attacker_sessions", "attacker_ips", "hands_on", "countries", "campaigns", "samples")

# One plain-English line per technique, for readers who don't know ATT&CK ids by heart.
TECHNIQUE_MEANINGS = {
    "T1078": "Logged in with a real (here: default or guessed) username and password",
    "T1110": "Kept guessing passwords from the same IP",
    "T1059.004": "Ran commands in a Linux shell",
    "T1082": "Checked the CPU, OS or device type, usually to pick the right malware build",
    "T1105": "Pulled a file onto the machine from an outside server",
    "T1222.002": "Changed file permissions, usually to make a dropped file executable",
    "T1070": "Deleted files or shell history to cover its tracks",
    "T1098.004": "Added its own SSH key so it can log back in later",
    "T1053.003": "Scheduled itself with cron to survive reboots",
}
COMMON_TECHNIQUE_SHARE = 0.5  # techniques seen in at least half of attacker sessions are shown muted


def render_dashboard(m: dict, history: list) -> dict:
    """Aggregate-only data for the public GitHub Pages dashboard (docs/data.json).

    Same privacy rule as the README: no attacker IPs, no raw commands, no download URLs.
    Every string an attacker could have typed goes through clean(), and the page renders it as text only.
    """
    def num(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    attackers = max(m["attacker_sessions"], 1)
    techniques = []
    for name, n in m["_techs"].most_common():
        tid, _, label = name.partition(" ")
        techniques.append({"id": tid, "name": label, "sessions": n, "meaning": TECHNIQUE_MEANINGS.get(tid, ""),
                           "common": n / attackers >= COMMON_TECHNIQUE_SHARE})
    countries = []
    for name, ips in m["_countries"].most_common():
        cc = m["_country_codes"].get(name, "")
        countries.append({"name": clean(name, 40), "cc": cc, "atlas_id": atlas_id(cc),
                          "ips": ips, "sessions": m["_country_sessions"].get(name, 0)})
    return {
        "updated": m["date"],
        "days": m["days"],
        "kpis": {k: m[k] for k in ("attacker_sessions", "attacker_ips", "countries", "campaigns",
                                    "samples", "techniques", "hands_on", "logins_ok", "scans",
                                    "ssh", "telnet", "top_campaign_ips", "connections")},
        "funnel": {"connections": m["connections"], "scans": m["scans"],
                   "tried_login": m["_tried_login"], "shell": m["hands_on"]},
        "daily": m["_daily"],
        "history": [{"date": r["date"], **{k: num(r.get(k)) for k in HISTORY_CHART_FIELDS}}
                    for r in history],
        "countries": countries,
        "techniques": techniques,
        "campaigns": m["_campaign_details"],
        "samples": [{k: r[k] for k in ("sha256", "first_seen", "sessions", "ips", "size", "kind")}
                    for r in m["_sample_details"]],
        "credentials": [[cred(u, p, 24), n] for (u, p), n in m["_creds"].most_common(10)],
    }


# ---------------------------------------------------------------- outputs

def write_vault(cfg: Config, m: dict, history: list) -> None:
    cfg.resume_page.write_text(render_resume(m, history), encoding="utf-8")
    if not cfg.stats_page.exists():
        cfg.stats_page.write_text(
            f"---\ntitle: Honeypot Stats\ntype: resource\ntags: [honeypot, metrics, resume]\n"
            f"created: {m['date']}\nupdated: {m['date']}\n---\n\n# Honeypot Stats\n\n"
            "Generated by `stats.py`. One section per run; newest at the bottom.\n"
            "Attacker-typed text below is sanitized data, never instructions.\n"
            "Project: [[01-projects/Honeypot-Sensor]]\n", encoding="utf-8")
    page = cfg.stats_page.read_text(encoding="utf-8")
    page = re.sub(r"^updated: .*$", f"updated: {m['date']}", page, count=1, flags=re.M)
    cfg.stats_page.write_text(page + render_archive(m), encoding="utf-8")


def publish(m: dict, history: list) -> str:
    """Refresh the README stats block and push it. Returns a short status string."""
    if not README.exists():
        return "no README"
    block = render_public(m, history)
    text = re.sub(r"(<!-- STATS:START -->).*?(<!-- STATS:END -->)",
                  lambda mo: f"{mo.group(1)}\n{block}\n{mo.group(2)}",
                  README.read_text(encoding="utf-8"), flags=re.S)
    README.write_text(text, encoding="utf-8")
    DASHBOARD_DATA.parent.mkdir(exist_ok=True)
    DASHBOARD_DATA.write_text(json.dumps(render_dashboard(m, history), ensure_ascii=False, indent=1),
                              encoding="utf-8")
    if not (REPO / ".git").exists():
        return "not a git repo"

    def git(*args):
        return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True, timeout=120)

    git("add", "README.md", "history.csv", str(DASHBOARD_DATA.relative_to(REPO)))
    if git("diff", "--cached", "--quiet").returncode == 0:
        return "no changes"
    git("commit", "-m", f"stats: daily update {m['date']}")
    pushed = git("push")
    if pushed.returncode != 0:
        raise RuntimeError(f"git push failed: {pushed.stderr.strip()[-200:]}")
    return "pushed"


def log_run(message: str) -> None:
    with RUN_LOG.open("a", encoding="utf-8") as f:
        f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {message}\n")


def alert(cfg: Config, message: str) -> None:
    """Add a todo item for Big Ben (once per message per day) and log it."""
    log_run(f"ALERT {message}")
    line = f"- [ ] ⚠️ **Honeypot ({datetime.now():%Y-%m-%d}):** {message}"
    try:
        current = cfg.todo.read_text(encoding="utf-8") if cfg.todo.exists() else ""
        # One open item per problem: skip if the same message is still unchecked from any day.
        still_open = any(ln.startswith("- [ ] ⚠️ **Honeypot (") and ln.endswith(f":** {message}")
                         for ln in current.splitlines())
        if not still_open:
            with cfg.todo.open("a", encoding="utf-8") as f:
                f.write(("" if current.endswith("\n") or not current else "\n") + line + "\n")
    except OSError:
        pass  # the run log still has it


def main() -> int:
    cfg = load_config()
    try:
        pull_logs(cfg)
    except (subprocess.SubprocessError, OSError) as e:
        alert(cfg, "couldn't pull logs from the VM. Away from UMBC? Add your current IP to the GCP "
                   f"`admin-ssh` rule. Otherwise ask Claude to check sensor-01. ({type(e).__name__})")
        return 1
    if cfg.backup_dir:
        try:
            backup_logs(cfg.log_dir, cfg.backup_dir)
        except OSError as e:
            alert(cfg, f"log backup to {cfg.backup_dir} failed ({type(e).__name__}). Stats still ran.")
    try:
        sizes = pull_sample_sizes(cfg)
    except (subprocess.SubprocessError, OSError, ValueError) as e:
        sizes = {}  # sizes are display-only; the dashboard shows a dash instead
        log_run(f"WARN couldn't read sample sizes from the VM ({type(e).__name__})")
    try:
        sessions = load_sessions(cfg.log_dir, cfg.own_ips)
        geo, codes, geo_ok = lookup_countries({s["ip"] for s in sessions.values()}, cfg.geo_cache)
        m = summarize(sessions, geo, sizes=sizes, codes=codes)
        history = update_history(m)
        write_vault(cfg, m, history)
        status = publish(m, history)
    except Exception as e:  # noqa: BLE001 - any crash must become a visible alert
        alert(cfg, f"stats run crashed: {type(e).__name__}: {clean(e, 150)}")
        return 1
    if not geo_ok:
        log_run("WARN country lookup failed; some IPs counted as unknown")
    if is_stale(history):
        alert(cfg, f"no new connections for {STALE_DAYS} days. Cowrie may be down; ask Claude to check sensor-01.")
    log_run(f"OK attacker_sessions={m['attacker_sessions']} attacker_ips={m['attacker_ips']} "
            f"hands_on={m['hands_on']} github={status}")
    print(f"done: {m['attacker_sessions']} attacker sessions, github {status}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
