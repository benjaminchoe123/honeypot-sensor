#!/bin/bash
# Cowrie SSH honeypot - first-boot setup for an Oracle Cloud (OCI) Ubuntu 24.04 VM.
#
# How to use: paste this whole file into
#   Create instance -> Show advanced options -> Management -> "Paste cloud-init script"
# It runs once, as root, on first boot. Progress log: /var/log/cloud-init-output.log
# Finished marker: /root/honeypot-setup-done
#
# End state:
#   port 22     -> Cowrie (fake SSH; this is what attackers hit)
#   port 22222  -> the real SSH, key-only, user "ubuntu" (the OCI security list must
#                  allow this port from YOUR IP only)
#   outbound    -> DNS, NTP, HTTP/HTTPS and OCI internal services only. Everything
#                  else is rejected, so a compromised box can't scan or attack others.
#
# Step order is chosen so a failure part-way never locks you out: the admin port
# opens before sshd moves, and port 22 is only redirected after Cowrie is running.
#
# Google Cloud: paste into Create instance -> Advanced -> Management -> Automation
# "Startup script". GCP re-runs startup scripts on EVERY boot, so the guard below
# makes later boots a no-op (the iptables rules are restored from rules.v4 instead).
set -euxo pipefail

[ -f /root/honeypot-setup-done ] && { echo "already set up"; exit 0; }

ADMIN_PORT=22222
# Login user for the real SSH:
#   Oracle -> "ubuntu"
#   Google -> the comment on your key, from: ssh-keygen ... -C honeypot-admin
ADMIN_USER=honeypot-admin
[ -d /home/ubuntu ] && ! [ -d "/home/${ADMIN_USER}" ] && ADMIN_USER=ubuntu
COWRIE_HOME=/home/cowrie/my-honeypot

# 1. Packages (Cowrie's native build deps from docs.cowrie.org, plus jq for triage)
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3-pip python3-venv libssl-dev libffi-dev build-essential \
  libpython3-dev python3-minimal jq iptables-persistent

# 2. Host firewall, inbound. OCI Ubuntu images ship iptables (not ufw) with a final
#    REJECT in INPUT, so these ACCEPTs are inserted at the top.
iptables -I INPUT 1 -p tcp --dport "${ADMIN_PORT}" -j ACCEPT   # real SSH (source limited by OCI security list)
iptables -I INPUT 1 -p tcp --dport 2222 -j ACCEPT              # Cowrie SSH (port 22 is redirected here)
iptables -I INPUT 1 -p tcp --dport 2223 -j ACCEPT              # Cowrie telnet (port 23 is redirected here)

# 3. Install Cowrie as an unprivileged user (it refuses to run as root)
id cowrie &>/dev/null || adduser --disabled-password --gecos "" cowrie
sudo -u cowrie -H bash -euxc "
  mkdir -p ${COWRIE_HOME} && cd ${COWRIE_HOME}
  python3 -m venv cowrie-env
  cowrie-env/bin/python -m pip install --upgrade pip
  cowrie-env/bin/python -m pip install cowrie==3.1.5   # pinned: the version verified on sensor-01
  [ -f etc/cowrie.cfg ] || cowrie-env/bin/cowrie init
"

# Override only the keys that matter; everything else keeps Cowrie's defaults.
cat > "${COWRIE_HOME}/etc/cowrie.cfg" <<'EOF'
[honeypot]
# Looks like a forgotten internal box; a little bait for the hands-on attackers
hostname = srv-db01

[ssh]
# CRITICAL: no port forwarding. Otherwise attackers can use the honeypot as a proxy
# to attack other people, which means abuse complaints and an account suspension.
forwarding = false

[telnet]
# Telnet is the busiest bot-scanned port (Mirai-style IoT botnets). Listens on 2223;
# port 23 is redirected here in step 6.
enabled = true

[output_jsonlog]
# Structured logs: what the pipeline and your jq triage read
enabled = true
EOF
chown cowrie:cowrie "${COWRIE_HOME}/etc/cowrie.cfg"

# 4. Run Cowrie as a service so it survives reboots and crashes
cat > /etc/systemd/system/cowrie.service <<EOF
[Unit]
Description=Cowrie SSH honeypot
After=network-online.target
Wants=network-online.target

[Service]
User=cowrie
Group=cowrie
WorkingDirectory=${COWRIE_HOME}
# Cowrie 3.x's "cowrie" wrapper has no -n (foreground) flag and daemonizes, which
# systemd can't supervise. Run twistd in the foreground directly, like Cowrie's
# Docker image does. Found on the first real GCP deploy, 2026-11-05.
ExecStart=${COWRIE_HOME}/cowrie-env/bin/twistd -n --umask=0022 --pidfile= cowrie
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now cowrie.service
sleep 15
systemctl is-active --quiet cowrie.service   # stop here (port 22 stays real SSH) if Cowrie didn't start

# 5. Move the real SSH to the admin port. Ubuntu 24.04 starts sshd through ssh.socket;
#    switch to the plain service so the Port setting below is what's used.
cat > /etc/ssh/sshd_config.d/10-honeypot-admin.conf <<EOF
Port ${ADMIN_PORT}
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers ${ADMIN_USER}
EOF
systemctl disable --now ssh.socket 2>/dev/null || true
systemctl enable ssh.service
systemctl restart ssh.service

# 6. Only now: send port 22 to Cowrie
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223

# 7. Restrict outbound traffic. APPEND, so Oracle's own InstanceServices rules (boot
#    volume, metadata) stay first; never delete those. Cowrie needs 80/443 to fetch
#    the malware attackers try to download (it saves the file and never runs it).
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -d 169.254.0.0/16 -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "EGRESS-BLOCKED "
iptables -A OUTPUT -j REJECT

# IPv6: the default OCI network has none, but block it anyway in case it gets enabled
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -A OUTPUT -j REJECT

netfilter-persistent save

date -Is > /root/honeypot-setup-done
echo "HONEYPOT SETUP COMPLETE"
