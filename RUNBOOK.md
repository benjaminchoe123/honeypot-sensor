# Honeypot Sensor: Go-Live Runbook

Files in this folder:
- `cloud-init.sh`: paste into Oracle at VM creation; the VM sets itself up on first boot
- `RUNBOOK.md`: this file

## 0. Before you start
- Oracle Cloud account created, with 2FA turned on for the console login
- Your public IP: search "what is my ip". You'll need it as `YOUR.IP/32`

## 1. Make an SSH key on your PC (PowerShell)
```
ssh-keygen -t ed25519 -f $HOME\.ssh\honeypot -C honeypot-admin
```
This creates `honeypot` (private: never share or upload) and `honeypot.pub` (the public key you give Oracle).

## 2. Create the VM (Oracle console -> Compute -> Instances -> Create instance)
| Setting | Value |
|---|---|
| Name | `sensor-01` |
| Image | **Canonical Ubuntu 24.04** |
| Shape | **VM.Standard.E2.1.Micro** (Always Free, AMD). Ampere A1 is also free but often "out of capacity" |
| Networking | create a new VCN + public subnet, **assign a public IPv4** |
| SSH keys | "Paste public key" -> contents of `honeypot.pub` |
| Advanced -> Management -> cloud-init | paste **all of** `cloud-init.sh` |

Click Create. Note the **public IP** once it's running.

## 3. Open the admin port, restricted to your IP only
Instance -> Subnet -> Security List -> **Add Ingress Rule**:
- Source CIDR `YOUR.IP/32`, TCP, destination port **22222**

Add one more: Source CIDR `0.0.0.0/0`, TCP, destination port **23** (telnet honeypot).

Leave the existing `0.0.0.0/0 port 22` rule as it is. That one is now the honeypot, and it should be open to everyone.

## 4. Wait about 10 minutes, then confirm setup worked
```
ssh -i $HOME\.ssh\honeypot -p 22222 ubuntu@<PUBLIC_IP>
cat /root/honeypot-setup-done 2>/dev/null || sudo cat /root/honeypot-setup-done
systemctl status cowrie --no-pager
```
If anything failed: `sudo tail -50 /var/log/cloud-init-output.log`, then send it to Claude.
**Can't connect on 22222?** Try plain `ssh -i ... ubuntu@<IP>` (port 22). If that works, the script stopped
before moving SSH; check the log above.

## 5. Watch the first attackers arrive (usually within minutes)
```
sudo tail -f /home/cowrie/my-honeypot/var/log/cowrie/cowrie.json | jq -c '{t:.timestamp, ip:.src_ip, ev:.eventid, u:.username, p:.password, cmd:.input}'
```
Ctrl+C to stop.

## 6. Safety checks (do these once)
- From the VM: `curl -m 5 telnet://example.com:25` should **fail** (egress blocked)
- `sudo iptables -L OUTPUT -n --line-numbers` should end with `REJECT`
- Never run anything from `var/lib/cowrie/downloads/`. Hash it, look it up, done.

## Known gotchas (researched 2026-11-04)
- **ufw does nothing on OCI Ubuntu**: the image uses iptables rules in `/etc/iptables/rules.v4`.
- **Never delete Oracle's `InstanceServices` iptables rules**: they keep the boot volume attached.
- **Idle reclaim:** Oracle may reclaim Always-Free VMs that sit nearly idle for 7 days. A honeypot
  gets constant traffic, but if the VM ever disappears, this is why.
- **Prompt injection:** attackers type whatever they want, and those commands will be fed to Claude
  by the pipeline. Treat every command and username as hostile text when integrating.

## Next (Claude, after go-live)
- Scheduled log pull: PC -> `scp -P 22222` -> `C:\Claude\threat-intel-pipeline\data\honeypot\`
- Merge `feature/honeypot-sensor` once it's tested on real logs
- Splunk Free + dashboards (after about 2 weeks of hand triage)

---

# Google Cloud version (use this if Oracle rejects the signup)

## G1. Sign up
- **cloud.google.com/free** -> "Get started for free"
- Use a **personal Gmail**, not your UMBC account (school Workspace accounts often block Cloud billing)
- Individual account, real name + card. You get **$300 in trial credit for 90 days**.

## G2. Set a budget alert FIRST (2 min)
Billing -> Budgets & alerts -> Create budget -> **$5/month**, email alerts at 50/90/100%.
The VM and 30GB standard disk are free, but the **public IPv4 address is not listed in the free tier**.
Expect about $3-4/month for it (covered by the trial credit for 90 days).

## G3. Make the SSH key (PowerShell)
```
ssh-keygen -t ed25519 -f $HOME\.ssh\honeypot -C honeypot-admin
```
The comment `honeypot-admin` becomes your login username on Google. **Keep it exactly that**: the script only allows that user.

## G4. Create the VM (Compute Engine -> VM instances -> Create instance)
Enable the Compute Engine API if asked.
| Setting | Value |
|---|---|
| Name | `sensor-01` |
| Region | **us-east1** (or us-central1 / us-west1; only these are free) |
| Machine type | **e2-micro** |
| Boot disk | **Ubuntu 24.04 LTS**, **Standard persistent disk**, 30 GB. Not "Balanced" (Balanced costs money) |
| Networking | external IPv4: ephemeral |
| Security -> Manage access -> Add SSH key | paste the contents of `honeypot.pub` |
| Advanced -> Management -> Automation -> Startup script | paste **all of** `cloud-init.sh` |

## G5. Firewall rule for your admin port
VPC network -> Firewall -> Create firewall rule:
- Name `admin-ssh`, direction Ingress, targets **All instances**, source `YOUR.IP/32`, TCP **22222**

Leave `default-allow-ssh` (port 22, open to all) alone. That's now the honeypot.

Create a second rule for the telnet honeypot:
- Name `honeypot-telnet`, Ingress, All instances, source `0.0.0.0/0`, TCP **23**

## G6. Check it (wait about 10 minutes)
```
ssh -i $HOME\.ssh\honeypot -p 22222 honeypot-admin@<EXTERNAL_IP>
systemctl status cowrie --no-pager
```
**Don't use the browser "SSH" button in the console after setup.** It connects on port 22, which is now the honeypot.
If you're locked out: delete the VM and recreate it. That takes 5 minutes, and nothing on it matters yet.
Setup log on Google: `sudo journalctl -u google-startup-scripts --no-pager | tail -50`
