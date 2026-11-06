# Case Study NN: <short title, e.g. "Mirai-style loader via Telnet default credentials">

**Date observed:** YYYY-MM-DD · **Protocol:** SSH / Telnet · **Tier:** hands-on
**Analyst:** <your name>

> Rule for publishing: no full attacker IPs (use the /24, e.g. `198.51.100.0/24`, or the
> country), no live download URLs (defang them: `hxxp://185[.]93[.]89[.]72/`), hashes are fine.

## 1. Summary (2-3 sentences)
What happened, who it probably was (bot or human, which family), and why it matters.

## 2. Timeline
| Time (UTC) | Action | What it means |
|---|---|---|
| 03:18:55 | Login `admin/admin` over Telnet | Default credentials, T1078.001 |
| | | |

## 3. ATT&CK mapping
| Technique | Evidence (command or event) |
|---|---|
| T1078 Valid Accounts | |

## 4. Payload analysis (static only, never run it)
- SHA-256:
- VirusTotal: detections X/Y, family label(s):
- What it would have done:

## 5. How I'd detect this in a real network
Describe it in plain words first, then (optional) as a Sigma rule idea:
e.g. "an alert when `busybox` is followed by `wget` or `tftp` and `chmod 777` within 10 seconds".

## 6. How to prevent it
e.g. change default credentials, disable Telnet, block outbound TFTP (my egress filter did this).

## 7. What I learned
One or two honest sentences. Interviewers like this section most.
