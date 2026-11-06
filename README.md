# Honeypot Sensor: First-Party Threat Intelligence

An internet-facing **SSH + Telnet honeypot** on Google Cloud that records real attackers, plus a
Python tool that turns raw logs into daily metrics mapped to **MITRE ATT&CK**. The numbers below
come from live data and update automatically every day.

## Live stats

<!-- STATS:START -->
_Last updated 2026-11-05 · 1 day of collection · updated automatically every day._

| Metric | Value |
|---|---|
| Attacker sessions | 5 |
| Unique attacker IPs | 4 |
| Countries | 3 |
| Successful logins | 5 |
| Hands-on sessions | 4 |
| Malware samples captured | 1 |
| MITRE ATT&CK techniques observed | 6 |
| Scanner connections filtered out | 6 |

**Attack-depth funnel**

| Tier | Sessions | Meaning |
|---|---|---|
| Scan | 6 | Connected, never tried to log in |
| Login attempt | 0 | Tried credentials, never got in |
| Access | 1 | Logged in, did nothing |
| Hands-on | 4 | Logged in and ran commands or downloaded files |

**ATT&CK techniques observed** (sessions)

- T1078 Valid Accounts (5)
- T1059.004 Unix Shell (4)
- T1082 System Information Discovery (2)
- T1222.002 Linux File Permissions Modification (1)
- T1070 Indicator Removal (1)
- T1105 Ingress Tool Transfer (1)

**Top source countries** (location of the attacking machine, usually an infected device)

- India (3)
- United States (1)
- The Netherlands (1)

**Most-tried credentials**

- admin / admin (3)
- admin / changeme (1)
- root / admin (1)

<details><summary>Daily growth</summary>

| Date | Attacker sessions | Attacker IPs | Hands-on | Countries | Samples |
|---|---|---|---|---|---|
| 2026-11-05 | 5 | 4 | 4 | 3 | 1 |

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
   → ATT&CK mapping → country lookup (cached) → history.csv
   → Obsidian notes + this README → git push
```

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
| `stats.py` | Log pull, sessionizing, ATT&CK mapping, metrics, README update |
| `history.csv` | One row of metrics per day |

## Limitations (honest notes)

- The ATT&CK mapping is a keyword-based first pass, not full behavioral analysis.
- Country = location of the attacking machine (usually an infected device), not of the operator.
- A medium-interaction honeypot: skilled humans can recognize it, so the data is mostly automated bots.

## Roadmap

- [ ] Rule for flagging "interesting" sessions (successful login + commands/downloads)
- [ ] VirusTotal enrichment for captured samples
- [ ] Sigma detection rules generated from observed commands
- [ ] Flag attacker IPs not yet in public threat feeds (novel infrastructure)
- [ ] Weekly case-study write-ups
