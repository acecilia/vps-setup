#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# harden-vps.sh — first-boot hardening & setup for a vanilla Hetzner VPS
#
# Run this as root, on a fresh server, immediately after your first SSH login:
#
#     scp -r vps-setup root@<server-ip>:/root/        # from your laptop
#     ssh root@<server-ip>
#     cd vps-setup && ./harden-vps.sh
#
# It asks for what it needs (username, your SSH public key, Tailscale auth key,
# optional Cloudflare token). Everything else uses sane, secure defaults. For
# an unattended run, export the same names as environment variables instead,
# e.g.  USERNAME=andres SSH_PUBLIC_KEY="ssh-ed25519 ..." ./harden-vps.sh
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
# locked out. The script is idempotent — safe to re-run.
# ─────────────────────────────────────────────────────────────────────────────
set -Eeuo pipefail

# ── Logging ──────────────────────────────────────────────────────────────────
LOG_FILE="/var/log/harden-vps.log"

# Colours (disabled if not a tty)
if [[ -t 1 ]]; then
  C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'; C_BLUE=$'\e[34m'
  C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'; C_RED=$'\e[31m'
else
  C_RESET=""; C_BOLD=""; C_BLUE=""; C_GREEN=""; C_YELLOW=""; C_RED=""
fi

log()  { echo "${C_BLUE}${C_BOLD}::${C_RESET} ${C_BOLD}$*${C_RESET}"; }
ok()   { echo "   ${C_GREEN}✓${C_RESET} $*"; }
warn() { echo "   ${C_YELLOW}!${C_RESET} $*"; }
die()  { echo "${C_RED}${C_BOLD}✗ $*${C_RESET}" >&2; exit 1; }

step=0
section() { step=$((step+1)); echo; log "[${step}] $*"; }

trap 'die "Failed at line ${LINENO}: ${BASH_COMMAND}"' ERR

# ── Preflight ────────────────────────────────────────────────────────────────
[[ "${EUID}" -eq 0 ]] || die "Run this as root (you're on a fresh Hetzner box: just \`ssh root@<ip>\`)."

command -v apt-get >/dev/null 2>&1 || die "This script targets Debian/Ubuntu (apt). Detected something else."

# Mirror all output to a logfile for later inspection.
exec > >(tee -a "${LOG_FILE}") 2>&1

echo "${C_BOLD}╭──────────────────────────────────────────────╮${C_RESET}"
echo "${C_BOLD}│  Hetzner VPS hardening & setup                │${C_RESET}"
echo "${C_BOLD}╰──────────────────────────────────────────────╯${C_RESET}"
echo "   log: ${LOG_FILE}"

# ── Settings ─────────────────────────────────────────────────────────────────
# Secrets/identity are asked for interactively, at the moment they're needed,
# and re-asked if rejected. Anything below can still be pre-set as an environment
# variable for an unattended run (e.g. USERNAME=andres ./harden-vps.sh).
USERNAME="${USERNAME:-}"
SSH_PUBLIC_KEY="${SSH_PUBLIC_KEY:-}"
TAILSCALE_AUTHKEY="${TAILSCALE_AUTHKEY:-}"
CLOUDFLARED_TUNNEL_TOKEN="${CLOUDFLARED_TUNNEL_TOKEN:-}"

# Non-secret behaviour toggles (secure defaults; override via env if you must).
PASSWORDLESS_SUDO="${PASSWORDLESS_SUDO:-true}"
TAILSCALE_SSH="${TAILSCALE_SSH:-true}"
SSH_TAILSCALE_ONLY="${SSH_TAILSCALE_ONLY:-true}"
INSTALL_CLOUDFLARED="${INSTALL_CLOUDFLARED:-true}"
SSH_PORT="${SSH_PORT:-22}"
PERMIT_ROOT_LOGIN="${PERMIT_ROOT_LOGIN:-no}"
PASSWORD_AUTH="${PASSWORD_AUTH:-no}"
F2B_BANTIME="${F2B_BANTIME:-24h}"
F2B_FINDTIME="${F2B_FINDTIME:-10m}"
F2B_MAXRETRY="${F2B_MAXRETRY:-3}"
ENABLE_UNATTENDED_UPGRADES="${ENABLE_UNATTENDED_UPGRADES:-true}"
SET_TIMEZONE="${SET_TIMEZONE:-}"

is_true()  { [[ "${1,,}" =~ ^(true|yes|1|y)$ ]]; }
have_tty() { [[ -t 0 ]]; }

# ask VAR "prompt text" [silent] — read a fresh value into VAR (overwrites it).
# Dies if there's no terminal, naming the env var to set for unattended runs.
ask() {
  local var="$1" text="$2" silent="${3:-}" val
  have_tty || die "Need ${var} but there's no terminal to ask on. Re-run with ${var}=... set."
  if [[ "${silent}" == "silent" ]]; then read -rsp "   ${text}: " val; echo; else read -rp "   ${text}: " val; fi
  printf -v "${var}" '%s' "${val}"
}

# ask_retry "question" — yes/no prompt, defaults to No. False if no terminal.
ask_retry() {
  local ans
  have_tty || return 1
  read -rp "   $1 [y/N] " ans
  [[ "${ans,,}" =~ ^(y|yes)$ ]]
}

# Username is referenced everywhere (section titles, AllowUsers…) so resolve it
# first. Re-asks until it's a valid Linux username.
while ! [[ "${USERNAME}" =~ ^[a-z_][a-z0-9_-]*$ ]]; do
  [[ -n "${USERNAME}" ]] && warn "Invalid username '${USERNAME}' — use lowercase letters, digits, '-' and '_'."
  USERNAME=""
  ask USERNAME "Username for the non-root sudo account"
done

export DEBIAN_FRONTEND=noninteractive

# ═════════════════════════════════════════════════════════════════════════════
section "System update & base packages"
# ═════════════════════════════════════════════════════════════════════════════
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
  curl wget git vim nano ufw fail2ban tmux ca-certificates gnupg \
  unattended-upgrades htop rsync >/dev/null
ok "Base packages installed"

if [[ -n "${SET_TIMEZONE}" ]]; then
  timedatectl set-timezone "${SET_TIMEZONE}" && ok "Timezone set to ${SET_TIMEZONE}"
fi

# ═════════════════════════════════════════════════════════════════════════════
section "Non-root sudo user: ${USERNAME}"
# ═════════════════════════════════════════════════════════════════════════════
if id "${USERNAME}" >/dev/null 2>&1; then
  ok "User '${USERNAME}' already exists"
else
  adduser --disabled-password --gecos "" "${USERNAME}"
  ok "Created user '${USERNAME}'"
fi
usermod -aG sudo "${USERNAME}"
ok "Added '${USERNAME}' to sudo group"

if is_true "${PASSWORDLESS_SUDO}"; then
  echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/90-${USERNAME}"
  chmod 440 "/etc/sudoers.d/90-${USERNAME}"
  visudo -cf "/etc/sudoers.d/90-${USERNAME}" >/dev/null || die "Generated sudoers file is invalid"
  ok "Passwordless sudo enabled"
fi

# Ask for the SSH public key now (only if not pre-set), re-asking on bad format.
# Blank is allowed only when Tailscale SSH will still give you a way in.
if [[ -z "${SSH_PUBLIC_KEY}" ]]; then
  if have_tty; then
    warn "Paste your *public* key (ssh-ed25519 AAAA... you@host)."
    is_true "${TAILSCALE_SSH}" && warn "Leave blank to rely on Tailscale SSH instead."
    while :; do
      ask SSH_PUBLIC_KEY "SSH public key"
      [[ -z "${SSH_PUBLIC_KEY}" ]] && break
      [[ "${SSH_PUBLIC_KEY}" =~ ^(ssh-(ed25519|rsa)|ecdsa-) ]] && break
      warn "That doesn't look like a public key — it should start with ssh-ed25519 / ssh-rsa / ecdsa-."
      SSH_PUBLIC_KEY=""
    done
  fi
elif [[ ! "${SSH_PUBLIC_KEY}" =~ ^(ssh-(ed25519|rsa)|ecdsa-) ]]; then
  die "SSH_PUBLIC_KEY doesn't look like a public key (expected ssh-ed25519 / ssh-rsa / ecdsa-...)."
fi

# Never leave a box with no way back in.
if [[ -z "${SSH_PUBLIC_KEY}" ]] && ! is_true "${TAILSCALE_SSH}"; then
  die "No SSH key and Tailscale SSH disabled — that would lock you out. Provide a key or enable TAILSCALE_SSH."
fi

# Install the key for the user (root keeps its existing keys, so this session stays up).
if [[ -n "${SSH_PUBLIC_KEY}" ]]; then
  user_home="/home/${USERNAME}"
  install -d -m 700 -o "${USERNAME}" -g "${USERNAME}" "${user_home}/.ssh"
  auth="${user_home}/.ssh/authorized_keys"
  touch "${auth}"
  grep -qxF "${SSH_PUBLIC_KEY}" "${auth}" || echo "${SSH_PUBLIC_KEY}" >> "${auth}"
  chmod 600 "${auth}"; chown "${USERNAME}:${USERNAME}" "${auth}"
  ok "Installed SSH key for ${USERNAME}"
else
  warn "No SSH key installed — you will depend on Tailscale SSH for access."
fi

# ═════════════════════════════════════════════════════════════════════════════
section "Tailscale"
# ═════════════════════════════════════════════════════════════════════════════
if ! command -v tailscale >/dev/null 2>&1; then
  curl -fsSL https://tailscale.com/install.sh | sh
  ok "Tailscale installed"
else
  ok "Tailscale already installed"
fi
systemctl enable --now tailscaled >/dev/null 2>&1 || true

ts_up_args=()
is_true "${TAILSCALE_SSH}" && ts_up_args+=(--ssh)

# Bring Tailscale up. If an auth key is rejected, say so and re-ask (or fall
# back to browser login). Loops until the box is actually on the tailnet.
while :; do
  if [[ -z "${TAILSCALE_AUTHKEY}" ]] && have_tty; then
    warn "Get a key at https://login.tailscale.com/admin/settings/keys"
    ask TAILSCALE_AUTHKEY "Tailscale auth key (blank to log in via browser URL)"
  fi

  if [[ -n "${TAILSCALE_AUTHKEY}" ]]; then
    if tailscale up --authkey="${TAILSCALE_AUTHKEY}" "${ts_up_args[@]}"; then
      break
    fi
    warn "Tailscale rejected that auth key (expired, wrong, or already used?)."
    TAILSCALE_AUTHKEY=""
    have_tty || die "Invalid TAILSCALE_AUTHKEY and no terminal to re-ask. Re-run with a valid key."
    # loop re-asks for a fresh key
  else
    warn "Starting interactive Tailscale login — open the URL it prints and approve this machine."
    if tailscale up "${ts_up_args[@]}"; then
      break
    fi
    warn "Interactive Tailscale login didn't complete."
    have_tty || die "Couldn't bring Tailscale up unattended. Re-run with TAILSCALE_AUTHKEY=... set."
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
# Never ban our own private ranges (Tailscale 100.64/10, LAN, loopback)
ignoreip = 127.0.0.1/8 ::1 100.64.0.0/10 192.168.0.0/16 10.0.0.0/8

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

# Always allow traffic over the Tailscale interface.
ufw allow in on tailscale0 comment 'Tailscale mesh' >/dev/null

if is_true "${SSH_TAILSCALE_ONLY}" && is_true "${TS_CONNECTED}"; then
  # SSH reachable ONLY through Tailscale — port 22 invisible to the internet.
  ufw allow in on tailscale0 to any port "${SSH_PORT}" proto tcp comment 'SSH (Tailscale only)' >/dev/null
  ok "SSH locked to tailscale0 — public port ${SSH_PORT} is closed"
  SSH_EXPOSURE="Tailscale only"
else
  # Safety net: keep public SSH open (still key-only + fail2ban-protected).
  ufw allow "${SSH_PORT}/tcp" comment 'SSH (public — Tailscale not confirmed)' >/dev/null
  if is_true "${SSH_TAILSCALE_ONLY}"; then
    warn "Wanted Tailscale-only SSH but Tailscale wasn't confirmed — left public SSH OPEN."
    warn "Once Tailscale works, re-run this script (or: ufw delete allow ${SSH_PORT}/tcp)."
  fi
  SSH_EXPOSURE="Public (key-only + fail2ban)"
fi

ufw --force enable >/dev/null
ok "UFW enabled — default-deny inbound"

# ═════════════════════════════════════════════════════════════════════════════
section "cloudflared (Cloudflare Tunnel)"
# ═════════════════════════════════════════════════════════════════════════════
if is_true "${INSTALL_CLOUDFLARED}"; then
  if ! command -v cloudflared >/dev/null 2>&1; then
    install -d -m 755 /usr/share/keyrings
    curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
      | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
      > /etc/apt/sources.list.d/cloudflared.list
    apt-get update -qq
    apt-get install -y -qq cloudflared >/dev/null
    ok "cloudflared installed ($(cloudflared --version 2>/dev/null | head -n1))"
  else
    ok "cloudflared already installed"
  fi

  # Ask for a connector token only if not pre-set; blank skips tunnel setup.
  if [[ -z "${CLOUDFLARED_TUNNEL_TOKEN}" ]] && have_tty; then
    warn "Optional: a Cloudflare Tunnel exposes services with no open inbound ports."
    warn "Get a connector token from Zero Trust → Networks → Tunnels → Install connector."
    ask CLOUDFLARED_TUNNEL_TOKEN "Cloudflare Tunnel token (blank to skip)"
  fi

  CF_STATUS="Binary installed, tunnel not configured"
  while [[ -n "${CLOUDFLARED_TUNNEL_TOKEN}" ]]; do
    # `service install` decodes the token locally and registers the service.
    if cloudflared service install "${CLOUDFLARED_TUNNEL_TOKEN}" >/dev/null 2>&1; then
      systemctl enable --now cloudflared >/dev/null 2>&1 || true
      ok "cloudflared tunnel service installed and running"
      CF_STATUS="Tunnel service running (token-based)"
      break
    fi
    warn "That tunnel token was rejected (malformed or revoked?)."
    CLOUDFLARED_TUNNEL_TOKEN=""
    have_tty || { warn "No terminal to re-ask — skipping tunnel setup."; break; }
    ask CLOUDFLARED_TUNNEL_TOKEN "Cloudflare Tunnel token (blank to skip)"
  done

  if [[ "${CF_STATUS}" == "Binary installed, tunnel not configured" ]]; then
    warn "No tunnel configured — binary is ready. Finish later with a token, or:"
    warn "  cloudflared tunnel login && cloudflared tunnel create <name>"
  fi
else
  ok "Skipped (INSTALL_CLOUDFLARED=false)"
  CF_STATUS="Skipped"
fi

# ═════════════════════════════════════════════════════════════════════════════
section "tmux (persistent sessions)"
# ═════════════════════════════════════════════════════════════════════════════
user_home="/home/${USERNAME}"
tmux_conf="${user_home}/.tmux.conf"
if [[ ! -f "${tmux_conf}" ]]; then
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
else
  ok "${tmux_conf} already exists — left untouched"
fi

# Auto-create a 'main' tmux session at login so work survives disconnects.
profile_d="${user_home}/.bash_profile"
hook='# Auto-attach to a persistent tmux session on interactive SSH login'
if ! grep -qF "${hook}" "${profile_d}" 2>/dev/null; then
  cat >> "${profile_d}" <<'EOF'

# Auto-attach to a persistent tmux session on interactive SSH login
if command -v tmux >/dev/null 2>&1 && [ -n "$PS1" ] && [ -z "$TMUX" ] && [ -n "$SSH_CONNECTION" ]; then
  tmux attach -t main 2>/dev/null || tmux new -s main
fi
EOF
  chown "${USERNAME}:${USERNAME}" "${profile_d}"
  ok "Login auto-attaches to tmux session 'main'"
else
  ok "tmux login hook already present"
fi

# ═════════════════════════════════════════════════════════════════════════════
section "Unattended security upgrades"
# ═════════════════════════════════════════════════════════════════════════════
if is_true "${ENABLE_UNATTENDED_UPGRADES}"; then
  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
  ok "Automatic security updates enabled"
else
  ok "Skipped (ENABLE_UNATTENDED_UPGRADES=false)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════════════════════════════════════
echo
echo "${C_GREEN}${C_BOLD}╭──────────────────────────────────────────────╮${C_RESET}"
echo "${C_GREEN}${C_BOLD}│  Hardening complete                           │${C_RESET}"
echo "${C_GREEN}${C_BOLD}╰──────────────────────────────────────────────╯${C_RESET}"
echo
if is_true "${PASSWORDLESS_SUDO}"; then sudo_note="sudo, passwordless"; else sudo_note="sudo"; fi
if is_true "${TS_CONNECTED}"; then ts_note="connected (${TS_IP})"; else ts_note="not confirmed"; fi
echo "  User .............. ${USERNAME} (${sudo_note})"
echo "  Tailscale ......... ${ts_note}"
echo "  SSH exposure ...... ${SSH_EXPOSURE}"
echo "  SSH auth .......... key-only (passwords: ${PASSWORD_AUTH}, root: ${PERMIT_ROOT_LOGIN})"
echo "  fail2ban .......... ban ${F2B_BANTIME} / ${F2B_MAXRETRY} tries / ${F2B_FINDTIME}"
echo "  Firewall .......... UFW default-deny inbound"
echo "  cloudflared ....... ${CF_STATUS}"
echo "  tmux .............. auto-attaches to 'main' on login"
echo
echo "${C_BOLD}Next steps — KEEP THIS SESSION OPEN and verify in a NEW terminal:${C_RESET}"
if [[ -n "${TS_IP}" ]]; then
  echo "  1. New terminal:  ${C_BOLD}ssh ${USERNAME}@${TS_IP}${C_RESET}   (over Tailscale)"
else
  echo "  1. Get on Tailscale, then:  ssh ${USERNAME}@<tailscale-ip>"
fi
echo "  2. Confirm sudo works:  ${C_BOLD}sudo whoami${C_RESET}  → should print 'root'"
echo "  3. Only once that works, you may close this root session."
if is_true "${SSH_TAILSCALE_ONLY}" && ! is_true "${TS_CONNECTED}"; then
  echo
  echo "${C_YELLOW}  ⚠ Public SSH is still OPEN because Tailscale wasn't confirmed.${C_RESET}"
  echo "${C_YELLOW}    Fix Tailscale, then re-run ./harden-vps.sh to close port ${SSH_PORT}.${C_RESET}"
fi
echo
