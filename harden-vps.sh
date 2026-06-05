#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# harden-vps.sh — first-boot hardening & setup for a vanilla Hetzner VPS
#
# Run as root on a fresh server, right after your first SSH login:
#
#     ssh root@<server-ip>
#     cd vps-setup && ./harden-vps.sh
#
# It prompts for the few things it needs — username, your SSH public key, a
# Tailscale auth key, and a Cloudflare Tunnel token — and re-asks if you give it
# something invalid. Everything else is fixed policy: every run produces the
# same hardened result. There are no flags or environment variables to set.
#
# What it does, in order:
#   1.  System update + base packages
#   2.  Non-root sudo user + your SSH key
#   3.  Tailscale  (brought up and VERIFIED before anything is locked down)
#   4.  SSH daemon hardening (key-only, no root login)
#   5.  fail2ban   (brute-force protection for SSH)
#   6.  UFW firewall — SSH restricted to the tailscale0 interface only
#   7.  cloudflared (Cloudflare Tunnel — expose services with no open ports)
#   8.  tmux       (persistent sessions config for the user)
#   9.  Unattended security upgrades
#
# Safety: the firewall is only locked to Tailscale AFTER Tailscale is confirmed
# connected. If Tailscale isn't up, public SSH is kept open so you can't get
# locked out. It's meant to run once, on a freshly provisioned box.
# ─────────────────────────────────────────────────────────────────────────────
# Fail fast: stop on any error (-e), any unset variable (-u), or any failed
# command in a pipe (pipefail). -E makes the ERR trap below also fire inside
# functions, so nothing fails silently.
set -Eeuo pipefail

LOG_FILE="/var/log/harden-vps.log"

log()  { echo ":: $*"; }
ok()   { echo "   [ok] $*"; }
warn() { echo "   [!] $*"; }
die()  { echo "✗ $*" >&2; exit 1; }

step=0
section() { step=$((step+1)); echo; log "[${step}] $*"; }

# If any command fails unexpectedly, print which line and command broke, then
# exit — instead of charging ahead in a half-configured state.
trap 'die "Failed at line ${LINENO}: ${BASH_COMMAND}"' ERR

# ── Preflight ────────────────────────────────────────────────────────────────
[[ "${EUID}" -eq 0 ]] || die "Run this as root (on a fresh Hetzner box: just \`ssh root@<ip>\`)."
command -v apt-get >/dev/null 2>&1 || die "This script targets Debian/Ubuntu (apt). Detected something else."
[[ -t 0 ]] || die "Run this interactively — it asks for a few values (username, SSH key, Tailscale key)."

# Send all output (stdout + stderr) to the terminal AND append it to a logfile
# via `tee`, so there's a full record of the run to look at afterwards.
exec > >(tee -a "${LOG_FILE}") 2>&1

echo "╭──────────────────────────────────────────────╮"
echo "│  Hetzner VPS hardening & setup                │"
echo "╰──────────────────────────────────────────────╯"
echo "   log: ${LOG_FILE}"

# ── What the script asks you for ─────────────────────────────────────────────
# These four are the only inputs. Each is prompted for when it's needed and
# re-asked on bad input. Nothing is read from the environment — every run is the
# same.
USERNAME=""
SSH_PUBLIC_KEY=""
TAILSCALE_AUTHKEY=""
CLOUDFLARED_TUNNEL_TOKEN=""

# ── Fixed policy ─────────────────────────────────────────────────────────────
# The hardening decisions are deliberately NOT configurable, so every run
# produces the same locked-down box. Edit these constants if you ever need to
# change the policy for ALL future runs.
SSH_PORT=22            # kept at 22 — the box is reached over Tailscale, not this port
PERMIT_ROOT_LOGIN=no   # no root SSH login
PASSWORD_AUTH=no       # key-only SSH (no passwords)
F2B_BANTIME=24h        # fail2ban: how long a ban lasts
F2B_FINDTIME=10m       # fail2ban: window for counting failures
F2B_MAXRETRY=3         # fail2ban: failures before a ban

is_true() { [[ "${1,,}" =~ ^(true|yes|1|y)$ ]]; }

# ask VAR "prompt text" [silent] — read a fresh value into VAR (overwrites it).
ask() {
  local var="$1" text="$2" silent="${3:-}" val
  if [[ "${silent}" == "silent" ]]; then read -rsp "   ${text}: " val; echo; else read -rp "   ${text}: " val; fi
  printf -v "${var}" '%s' "${val}"
}

# ask_retry "question" — yes/no prompt, defaults to No.
ask_retry() {
  local ans
  read -rp "   $1 [y/N] " ans
  [[ "${ans,,}" =~ ^(y|yes)$ ]]
}

# Username is referenced everywhere (section titles, AllowUsers…) so resolve it
# first. Re-asks until it's a valid Linux username.
echo
warn "── Non-root USERNAME ────────────────────────────────────────────────"
warn "What:  the login name for the everyday sudo account this script creates."
warn "Why:   you'll log in as this user; direct root SSH login is disabled."
warn "Pick:  anything you like — lowercase letters, digits, '-' and '_'."
while ! [[ "${USERNAME}" =~ ^[a-z_][a-z0-9_-]*$ ]]; do
  [[ -n "${USERNAME}" ]] && warn "Invalid username '${USERNAME}' — use lowercase letters, digits, '-' and '_'."
  ask USERNAME "Username for the non-root sudo account"
done

# Stop apt from opening interactive dialogs (e.g. "keep or replace this config
# file?") during the upgrade — it picks the safe default instead of hanging.
export DEBIAN_FRONTEND=noninteractive

# ═════════════════════════════════════════════════════════════════════════════
section "System update & base packages"
# ═════════════════════════════════════════════════════════════════════════════
apt-get update -qq
apt-get upgrade -y -qq
# Bare minimum: only the services the script configures. curl + CA certs are
# assumed already present (they are on stock images); Tailscale and cloudflared
# pull their own dependencies.
apt-get install -y -qq ufw fail2ban tmux unattended-upgrades >/dev/null
ok "Base packages installed"

# ═════════════════════════════════════════════════════════════════════════════
section "Non-root sudo user: ${USERNAME}"
# ═════════════════════════════════════════════════════════════════════════════
adduser --disabled-password --gecos "" "${USERNAME}"
ok "Created user '${USERNAME}'"
usermod -aG sudo "${USERNAME}"
ok "Added '${USERNAME}' to sudo group"

# Passwordless sudo: the account has no password (key-only SSH is the auth
# factor), so sudo doesn't prompt for one.
echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/90-${USERNAME}"
chmod 440 "/etc/sudoers.d/90-${USERNAME}"
visudo -cf "/etc/sudoers.d/90-${USERNAME}" >/dev/null || die "Generated sudoers file is invalid"
ok "Passwordless sudo enabled"

# Ask for the SSH public key (required). Re-asks until it looks like a public key.
echo
warn "── Your SSH PUBLIC key (required) ───────────────────────────────────"
warn "What:  the *public* half of your SSH keypair — the one-line .pub file."
warn "Why:   it's installed for '${USERNAME}' so you can authenticate over SSH."
warn "       Tailscale restricts WHERE ssh is reachable from; this key proves WHO"
warn "       you are. (The matching private key never leaves your laptop.)"
warn "Where: on your laptop run  cat ~/.ssh/id_ed25519.pub  and copy the line."
warn "       No keypair yet?  ssh-keygen -t ed25519  first, then copy the .pub."
while :; do
  ask SSH_PUBLIC_KEY "Paste your SSH public key (ssh-ed25519 / ssh-rsa / ecdsa-...)"
  [[ "${SSH_PUBLIC_KEY}" =~ ^(ssh-(ed25519|rsa)|ecdsa-) ]] && break
  warn "That doesn't look like a public key — it should start with ssh-ed25519 / ssh-rsa / ecdsa-. Try again."
done

# Install the key for the user (root keeps its existing keys, so this session stays up).
user_home="/home/${USERNAME}"
install -d -m 700 -o "${USERNAME}" -g "${USERNAME}" "${user_home}/.ssh"
auth="${user_home}/.ssh/authorized_keys"
echo "${SSH_PUBLIC_KEY}" > "${auth}"
chmod 600 "${auth}"; chown "${USERNAME}:${USERNAME}" "${auth}"
ok "Installed SSH key for ${USERNAME}"

# ═════════════════════════════════════════════════════════════════════════════
section "Tailscale"
# ═════════════════════════════════════════════════════════════════════════════
curl -fsSL https://tailscale.com/install.sh | sh
ok "Tailscale installed"
systemctl enable --now tailscaled >/dev/null 2>&1 || true

# Bring Tailscale up. If an auth key is rejected, say so and re-ask (or fall back
# to browser login). Loops until the box is actually on the tailnet.
echo
warn "── TAILSCALE auth key ───────────────────────────────────────────────"
warn "What:  a one-off key that joins THIS server to your private tailnet."
warn "Why:   Tailscale becomes the only network path to SSH — port 22 is later"
warn "       firewalled to the tailscale0 interface, so the box is never exposed"
warn "       to the public internet."
warn "Where: https://login.tailscale.com/admin/settings/keys → 'Generate auth key'"
warn "       (reusable or ephemeral is fine). Blank = log in via a browser URL"
warn "       this script prints instead."
while :; do
  if [[ -z "${TAILSCALE_AUTHKEY}" ]]; then
    ask TAILSCALE_AUTHKEY "Tailscale auth key (blank for browser login)" silent
  fi

  if [[ -n "${TAILSCALE_AUTHKEY}" ]]; then
    if tailscale up --authkey="${TAILSCALE_AUTHKEY}" --ssh; then
      break
    fi
    warn "Tailscale rejected that auth key (expired, wrong, or already used?)."
    TAILSCALE_AUTHKEY=""
    # loop re-asks for a fresh key
  else
    warn "Starting interactive Tailscale login — open the URL it prints and approve this machine."
    if tailscale up --ssh; then
      break
    fi
    warn "Interactive Tailscale login didn't complete."
    ask_retry "Try Tailscale login again?" || break
  fi
done

# Verify Tailscale is actually connected before we trust it for the firewall.
TS_CONNECTED="false"
TS_IP=""
if tailscale status >/dev/null 2>&1; then
  TS_IP="$(tailscale ip -4 2>/dev/null | head -n1 || true)"
  [[ -n "${TS_IP}" ]] && TS_CONNECTED="true"
fi
if is_true "${TS_CONNECTED}"; then
  ok "Tailscale is up — this machine is ${TS_IP}"
else
  warn "Could not confirm Tailscale connectivity. Public SSH will be kept OPEN as a safety net."
fi

# ═════════════════════════════════════════════════════════════════════════════
section "SSH daemon hardening"
# ═════════════════════════════════════════════════════════════════════════════
# Drop-in config so we never clobber the distro's sshd_config.
sshd_drop="/etc/ssh/sshd_config.d/99-hardening.conf"
install -d -m 755 /etc/ssh/sshd_config.d
cat > "${sshd_drop}" <<EOF
# Managed by harden-vps.sh — re-run the script to change these, not by hand.
Port ${SSH_PORT}
PermitRootLogin ${PERMIT_ROOT_LOGIN}
PasswordAuthentication ${PASSWORD_AUTH}
PubkeyAuthentication yes
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
AuthenticationMethods publickey
AllowUsers ${USERNAME} root
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 30
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
ok "Wrote ${sshd_drop}"

if sshd -t; then
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || systemctl restart ssh
  ok "SSH config valid and reloaded (root login: ${PERMIT_ROOT_LOGIN}, passwords: ${PASSWORD_AUTH})"
else
  rm -f "${sshd_drop}"
  die "sshd config test failed — reverted the drop-in so you keep your current session."
fi

# ═════════════════════════════════════════════════════════════════════════════
section "fail2ban (SSH brute-force protection)"
# ═════════════════════════════════════════════════════════════════════════════
cat > /etc/fail2ban/jail.local <<EOF
# Managed by harden-vps.sh
[DEFAULT]
bantime  = ${F2B_BANTIME}
findtime = ${F2B_FINDTIME}
maxretry = ${F2B_MAXRETRY}
backend  = systemd
# Only exempt loopback. Tailscale (100.64/10) is deliberately NOT ignored so
# brute-force attempts against sshd over the tailnet are throttled too — a
# compromised tailnet device shouldn't get unlimited SSH attempts. Key-only
# auth means legitimate logins won't trip the jail.
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port    = ${SSH_PORT}
EOF
systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban
ok "fail2ban active (ban ${F2B_BANTIME} after ${F2B_MAXRETRY} fails in ${F2B_FINDTIME})"

# ═════════════════════════════════════════════════════════════════════════════
section "UFW firewall"
# ═════════════════════════════════════════════════════════════════════════════
ufw --force reset >/dev/null
ufw default deny incoming  >/dev/null
ufw default allow outgoing >/dev/null

# Allow everything over the Tailscale interface — your trusted path in.
ufw allow in on tailscale0 comment 'Tailscale mesh' >/dev/null

if is_true "${TS_CONNECTED}"; then
  # SSH reachable ONLY through Tailscale — public port 22 stays invisible.
  ok "SSH locked to tailscale0 — public port ${SSH_PORT} is closed"
  SSH_EXPOSURE="Tailscale only"
else
  # Safety net: Tailscale unconfirmed, so keep public SSH open (key-only + fail2ban).
  ufw allow "${SSH_PORT}/tcp" comment 'SSH (public — Tailscale not confirmed)' >/dev/null
  warn "Tailscale wasn't confirmed — left public SSH OPEN so you aren't locked out."
  warn "Once Tailscale works: run 'tailscale up --ssh', then 'ufw delete allow ${SSH_PORT}/tcp'."
  SSH_EXPOSURE="Public (key-only + fail2ban)"
fi

ufw --force enable >/dev/null
ok "UFW enabled — default-deny inbound"

# ═════════════════════════════════════════════════════════════════════════════
section "cloudflared (Cloudflare Tunnel)"
# ═════════════════════════════════════════════════════════════════════════════
install -d -m 755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
  | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
  > /etc/apt/sources.list.d/cloudflared.list
apt-get update -qq
apt-get install -y -qq cloudflared >/dev/null
ok "cloudflared installed ($(cloudflared --version 2>/dev/null | head -n1))"

# A connector token is required — the tunnel is how services are exposed, with
# no open inbound ports. Re-asks until a token actually registers the service.
echo
warn "── CLOUDFLARE Tunnel token (required) ───────────────────────────────"
warn "What:  a connector token that links this box to a Cloudflare Tunnel."
warn "Why:   it lets you publish services through Cloudflare with NO open inbound"
warn "       ports — the firewall stays default-deny."
warn "Where: Cloudflare Zero Trust → Networks → Tunnels → create/pick a tunnel →"
warn "       'Install connector' → copy the token out of the shown"
warn "       'cloudflared service install <TOKEN>' command."
while :; do
  [[ -z "${CLOUDFLARED_TUNNEL_TOKEN}" ]] && ask CLOUDFLARED_TUNNEL_TOKEN "Cloudflare Tunnel token" silent
  # `service install` decodes the token locally and registers the service.
  if [[ -n "${CLOUDFLARED_TUNNEL_TOKEN}" ]] && cloudflared service install "${CLOUDFLARED_TUNNEL_TOKEN}" >/dev/null 2>&1; then
    systemctl enable --now cloudflared >/dev/null 2>&1 || true
    ok "cloudflared tunnel service installed and running"
    break
  fi
  warn "That tunnel token was empty or rejected (malformed or revoked?) — try again."
  CLOUDFLARED_TUNNEL_TOKEN=""
done
CF_STATUS="Tunnel service running (token-based)"

# ═════════════════════════════════════════════════════════════════════════════
section "tmux (persistent sessions)"
# ═════════════════════════════════════════════════════════════════════════════
user_home="/home/${USERNAME}"
tmux_conf="${user_home}/.tmux.conf"
cat > "${tmux_conf}" <<'EOF'
# ── tmux: keep long-running work alive across SSH drops ──────────────────────
set -g default-terminal "tmux-256color"
set -g history-limit 50000
set -g mouse on                 # scroll & select with the mouse
set -g base-index 1             # windows start at 1
setw -g pane-base-index 1
set -g renumber-windows on
set -sg escape-time 10
set -g status-interval 5
set -g status-style "bg=colour236,fg=colour250"
set -g status-left  " #[bold]#S #[default]"
set -g status-right " %Y-%m-%d %H:%M "
set -g status-right-length 40

# Reattach hint: `tmux attach` or `tmux a -t <name>`
# New named session:  tmux new -s work
# Detach:             Ctrl-b then d
EOF
chown "${USERNAME}:${USERNAME}" "${tmux_conf}"
ok "Wrote ${tmux_conf}"

# Auto-create a 'main' tmux session at login so work survives disconnects.
profile_d="${user_home}/.bash_profile"
cat >> "${profile_d}" <<'EOF'

# Auto-attach to a persistent tmux session on interactive SSH login
if command -v tmux >/dev/null 2>&1 && [ -n "$PS1" ] && [ -z "$TMUX" ] && [ -n "$SSH_CONNECTION" ]; then
  tmux attach -t main 2>/dev/null || tmux new -s main
fi
EOF
chown "${USERNAME}:${USERNAME}" "${profile_d}"
ok "Login auto-attaches to tmux session 'main'"

# ═════════════════════════════════════════════════════════════════════════════
section "Unattended security upgrades"
# ═════════════════════════════════════════════════════════════════════════════
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
ok "Automatic security updates enabled"

# ═════════════════════════════════════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════════════════════════════════════
echo
echo "╭──────────────────────────────────────────────╮"
echo "│  Hardening complete                           │"
echo "╰──────────────────────────────────────────────╯"
echo
if is_true "${TS_CONNECTED}"; then ts_note="connected (${TS_IP})"; else ts_note="not confirmed"; fi
echo "  User .............. ${USERNAME} (sudo, passwordless)"
echo "  Tailscale ......... ${ts_note}"
echo "  SSH exposure ...... ${SSH_EXPOSURE}"
echo "  SSH auth .......... key-only (passwords: ${PASSWORD_AUTH}, root: ${PERMIT_ROOT_LOGIN})"
echo "  fail2ban .......... ban ${F2B_BANTIME} / ${F2B_MAXRETRY} tries / ${F2B_FINDTIME}"
echo "  Firewall .......... UFW default-deny inbound"
echo "  cloudflared ....... ${CF_STATUS}"
echo "  tmux .............. auto-attaches to 'main' on login"
echo
echo "Next steps — KEEP THIS SESSION OPEN and verify in a NEW terminal:"
if [[ -n "${TS_IP}" ]]; then
  echo "  1. New terminal:  ssh ${USERNAME}@${TS_IP}   (over Tailscale)"
else
  echo "  1. Get on Tailscale, then:  ssh ${USERNAME}@<tailscale-ip>"
fi
echo "  2. Confirm sudo works:  sudo whoami   → should print 'root'"
echo "  3. Only once that works, you may close this root session."
if ! is_true "${TS_CONNECTED}"; then
  echo
  echo "  ⚠ Public SSH is still OPEN because Tailscale wasn't confirmed."
  echo "    Fix Tailscale (tailscale up --ssh), then: ufw delete allow ${SSH_PORT}/tcp"
fi
echo
