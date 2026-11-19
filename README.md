# Honeypot Sensor: First-Party Threat Intelligence

[![CI](https://github.com/benjaminchoe123/honeypot-sensor/actions/workflows/ci.yml/badge.svg)](https://github.com/benjaminchoe123/honeypot-sensor/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

An internet-facing **SSH + Telnet honeypot** on Google Cloud that records real attackers, plus a
Python tool that turns raw logs into daily metrics mapped to **MITRE ATT&CK**. The numbers below
come from live data and update automatically every day.

**📊 Live dashboard: https://benjaminchoe123.github.io/honeypot-sensor/** (attack map, daily activity,
top campaigns, captured malware, ATT&CK techniques)

## Live stats

<!-- STATS:START -->
_Last updated 2026-11-18 · 13 days of collection · updated automatically every day._

| Metric | Value |
|---|---|
| Attacker sessions | 59,271 |
| Unique attacker IPs | 907 |
| Countries | 91 |
| Successful logins | 58,817 |
| Hands-on sessions | 56,655 |
| Distinct attack campaigns | 842 (largest: 86 source IPs) |
| Malware samples captured | 8 |
| MITRE ATT&CK techniques observed | 7 |
| Scanner connections filtered out | 5,434 |

**Attack-depth funnel**

| Tier | Sessions | Meaning |
|---|---|---|
| Scan | 5,434 | Connected, never tried to log in |
| Login attempt | 454 | Tried credentials, never got in |
| Access | 2,162 | Logged in, did nothing |
| Hands-on | 56,655 | Logged in and ran commands or downloaded files |

**ATT&CK techniques observed** (sessions)

- T1078 Valid Accounts (58,817)
- T1059.004 Unix Shell (56,655)
- T1082 System Information Discovery (50,983)
- T1222.002 Linux File Permissions Modification (1,138)
- T1110 Brute Force (419)
- T1070 Indicator Removal (189)
- T1105 Ingress Tool Transfer (69)

**Top source countries** (location of the attacking machine, usually an infected device)

- The Netherlands (40,861)
- France (7,019)
- United States (2,947)
- Philippines (2,225)
- China (1,880)

**Most-tried credentials**

- admin / admin (2,080)
- root / root (360)
- nobody / nobody (354)
- root / admin (244)
- admin /  (151)

<details><summary>Daily growth</summary>

| Date | Attacker sessions | Attacker IPs | Hands-on | Countries | Samples |
|---|---|---|---|---|---|
| 2026-11-05 | 5 | 4 | 4 | 3 | 1 |
| 2026-11-06 | 879 | 68 | 822 | 25 | 1 |
| 2026-11-07 | 5112 | 141 | 4970 | 39 | 1 |
| 2026-11-08 | 8964 | 215 | 8722 | 49 | 2 |
| 2026-11-09 | 12562 | 260 | 12212 | 53 | 2 |
| 2026-11-10 | 16936 | 319 | 16376 | 63 | 6 |
| 2026-11-11 | 21773 | 383 | 20966 | 68 | 6 |
| 2026-11-12 | 26057 | 460 | 25038 | 69 | 7 |
| 2026-11-15 | 43636 | 603 | 41967 | 76 | 8 |
| 2026-11-16 | 49446 | 653 | 47484 | 77 | 8 |
| 2026-11-17 | 55592 | 711 | 53339 | 80 | 8 |
| 2026-11-18 | 59271 | 907 | 56655 | 91 | 8 |

</details>
<!-- STATS:END -->

## How it works

```
 Internet bots/attackers
        │  port 22 (SSH), port 23 (Telnet)
        ▼
 ┌──────────────── GCP e2-micro (Ubuntu 24.04) ────────────────┐
 │ iptables NAT: 22→2222, 23→2223                              │
 │ Cowrie honeypot (unprivileged user, systemd) → cowrie.json  │
 │ Real admin SSH: separate high port, key-only, IP-allowlisted│
 │ Egress filter: only DNS/NTP/HTTP(S) out; everything else    │
 │ rejected, so a "compromised" box can't attack anyone        │
 └──────────────────────────────┬──────────────────────────────┘
                                │ daily, over SSH (key in ssh-agent)
                                ▼
 stats.py (Windows Task Scheduler, 9 PM)
   pull logs → group events into sessions → exclude own IPs
   → classify by attack depth → ATT&CK mapping → country lookup (cached)
   → history.csv → Obsidian notes + this README → git push
   → on failure or stalled traffic: alert to the operator's todo list
```

### Attack-depth tiers

Counting every TCP connection as an "attack" inflates the numbers, because research scanners like
Shodan and Censys connect constantly. Each session is classified by how far it got:

| Tier | Rule | Counted as an attack? |
|---|---|---|
| Scan | Connected, no login attempt | No (reported separately) |
| Login attempt | Tried credentials, never got in | Yes |
| Access | Logged in, did nothing | Yes |
| Hands-on | Logged in and ran commands or downloaded files | Yes |

T1110 Brute Force is only tagged when one IP has 5 or more failed logins, so a single failed attempt doesn't count.

## Design decisions

- **Cowrie, not T-Pot.** T-Pot needs about 8 GB of RAM. Cowrie runs on a free-tier VM and
  produces clean JSON.
- **Isolation first.** SSH port forwarding is disabled (so attackers can't use the sensor as a
  proxy), outbound traffic is allow-listed, the admin port is IP-restricted and key-only, and the
  VM is treated as disposable.
- **Fail-safe setup.** `cloud-init.sh` opens the admin port before moving SSH, and only redirects
  port 22 after Cowrie is confirmed running, so a partial failure can't lock the operator out.
- **Attacker text is hostile input.** Usernames, passwords and commands are sanitized before they
  reach any notes, and are never treated as instructions by downstream tooling (including LLMs).
- **Aggregates only in public.** This repo publishes counts, never attacker IPs or raw sessions.
- **Pull, don't push, from the sensor.** Collection runs on the operator's PC and pulls from the VM.
  The alternatives (pushing from the VM, or GitHub Actions connecting in) would put GitHub or SSH
  credentials on a machine built to be attacked, or open the admin port to the internet.
- **Failures are loud.** A failed pull, a crash, a failed push, or two days with no new
  connections adds an alert to the operator's task list, so a dead sensor can't go unnoticed.

## First observations

Within 4 minutes of going live, two IoT bots logged in over Telnet with `admin/admin` and ran a
Mirai-style loader. In order, they:
1. Tried to escape restricted router shells (`enable`, `system`, `ping ;sh`).
2. Fingerprinted the device (`busybox HISILICON`, `cat /proc/self/exe`) to choose a CPU-specific payload.
3. Searched about 12 directories for one that was writable and executable.
4. Tried three download methods (wget, tftp, ftpget). The egress filter blocked tftp.

ATT&CK: T1078 Valid Accounts, T1059.004 Unix Shell, T1082 System Information Discovery,
T1222.002 File Permissions Modification, T1105 Ingress Tool Transfer, T1070 Indicator Removal.

## Files

| File | Purpose |
|---|---|
| `cloud-init.sh` | First-boot setup for the VM (Cowrie, SSH move, firewall, egress filter) |
| `RUNBOOK.md` | Step-by-step deployment for Oracle Cloud or Google Cloud |
| `stats.py` | Log pull, sessions, attack-depth tiers, ATT&CK mapping, metrics, alerts, README update |
| `tests/` | pytest suite on synthetic Cowrie events (documentation-range IPs only) |
| `history.csv` | One row of metrics per day |
| `config.example.json` | Template for the private, gitignored `config.local.json` |

## Running it

```
cp config.example.json config.local.json   # fill in VM address, your IPs, local folders
pip install -e ".[dev]"                     # only for tests; stats.py is standard-library only
pytest -q && ruff check .
python stats.py
```

## Limitations (honest notes)

- The ATT&CK mapping is a keyword-based first pass, not full behavioral analysis.
- Country = location of the attacking machine (usually an infected device), not of the operator.
- A medium-interaction honeypot: skilled humans can recognize it, so the data is mostly automated bots.

## Roadmap

- [x] Attack-depth tiers, so scanners aren't counted as attacks
- [x] Failure and stalled-sensor alerts
- [x] Tests + CI
- [ ] Rule for flagging "interesting" sessions (successful login + commands/downloads)
- [ ] VirusTotal enrichment for captured samples
- [ ] Sigma detection rules generated from observed commands
- [ ] Flag attacker IPs not yet in public threat feeds (novel infrastructure)
- [ ] Weekly case-study write-ups
