#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# harden-vps.sh — first-boot hardening & setup for a vanilla Hetzner VPS
#
# Run as root on a fresh server, right after your first SSH login:
#
#     ssh root@<server-ip>
#     cd vps-setup && ./harden-vps.sh
#
# It prompts for the few things it needs — username, your SSH public key, and a
# Cloudflare Tunnel token — plus a one-time Tailscale browser login, and re-asks
# if you give it something invalid. Everything else is fixed policy: every run
# produces the same hardened result.
#
# HOW IT STAYS SAFE
#
#   • The non-root user is created FIRST, then the script re-launches the rest of
#     itself inside a tmux session that RUNS AS and is OWNED BY that user. So if
#     your SSH connection ever drops mid-run, the work keeps going on the box —
#     reconnect over Tailscale as that user and `tmux attach -t vps-setup` (no
#     sudo) to pick it right back up. Privileged steps use the user's passwordless
#     sudo. (Running as the user also means user-level files like ~/.tmux.conf
#     are written to the USER's home, not root's.)
#
#   • The network lockdown happens LAST and never cuts your only way in. Public
#     SSH is kept open until you've confirmed, from a second terminal, that you
#     can log in over Tailscale. Only then is port 22 closed.
#
# Order of operations:
#   Phase A (as root, before tmux):
#     1.  Create the non-root sudo user + install your SSH key
#   Phase B (re-launched as that user, inside its own tmux session):
#     2.  System update + base packages
#     3.  fail2ban
#     4.  cloudflared (Cloudflare Tunnel)
#     5.  tmux config
#     6.  Unattended security upgrades
#     7.  Tailscale (brought up and VERIFIED)
#     8.  SSH daemon hardening (key-only, no root login)
#     9.  UFW firewall — public SSH kept open as a safety net
#    10.  Lockdown — close public SSH ONLY after you confirm Tailscale works
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

# Absolute path to this script, so the re-exec into tmux can find it again.
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

# ── Stage detection (purely by who is running) ───────────────────────────────
# As root   -> Phase A (bootstrap): create the non-root user, then re-exec this
#              script as that user inside a tmux session it owns.
# As a user -> Phase B (run): do the hardening as the current user, via its
#              passwordless sudo. This covers both the bootstrap's tmux hand-off
#              and simply re-running the script yourself later.
if [[ "${EUID}" -eq 0 ]]; then
  STAGE="bootstrap"; USERNAME=""
else
  STAGE="run"; USERNAME="$(id -un)"
fi

# ── Preflight ────────────────────────────────────────────────────────────────
command -v apt-get >/dev/null 2>&1 || die "This script targets Debian/Ubuntu (apt). Detected something else."
[[ -t 0 ]] || die "Run this interactively — it asks for a few values (username, SSH key, Tailscale key)."
if [[ "${STAGE}" == "run" ]]; then
  sudo -n true 2>/dev/null || die "Passwordless sudo isn't working for '${USERNAME}' — cannot continue."
fi

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

# ── Fixed policy ─────────────────────────────────────────────────────────────
# The hardening decisions are deliberately NOT configurable, so every run
# produces the same locked-down box. Edit these constants to change the policy
# for ALL future runs.
SSH_PORT=22            # kept at 22 — the box is reached over Tailscale, not this port
PERMIT_ROOT_LOGIN=no   # no root SSH login
PASSWORD_AUTH=no       # key-only SSH (no passwords)
F2B_BANTIME=24h        # fail2ban: how long a ban lasts
F2B_FINDTIME=10m       # fail2ban: window for counting failures
F2B_MAXRETRY=3         # fail2ban: failures before a ban

# ═════════════════════════════════════════════════════════════════════════════
# PHASE A — as root: create the user, install the key, then hand off to tmux
# ═════════════════════════════════════════════════════════════════════════════
if [[ "${STAGE}" == "bootstrap" ]]; then
  echo "╭──────────────────────────────────────────────╮"
  echo "│  Hetzner VPS hardening & setup                │"
  echo "╰──────────────────────────────────────────────╯"
  echo
  echo ":: First I'll create your non-root user, then re-launch the rest inside a"
  echo "   tmux session OWNED BY that user. If your SSH connection drops, reconnect"
  echo "   over Tailscale as that user and run:  tmux attach -t vps-setup"
  echo

  export DEBIAN_FRONTEND=noninteractive
  command -v tmux >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq tmux >/dev/null; }

  # Username — re-asked until it's a valid Linux username.
  echo
  warn "── Non-root USERNAME ────────────────────────────────────────────────"
  warn "What:  the login name for the everyday sudo account this script creates."
  warn "Why:   you'll log in as this user; direct root SSH login is disabled."
  warn "Pick:  anything you like — lowercase letters, digits, '-' and '_'."
  while ! [[ "${USERNAME}" =~ ^[a-z_][a-z0-9_-]*$ ]]; do
    [[ -n "${USERNAME}" ]] && warn "Invalid username '${USERNAME}' — use lowercase letters, digits, '-' and '_'."
    ask USERNAME "Username for the non-root sudo account"
  done

  # Create the user (idempotent) + passwordless sudo.
  if id "${USERNAME}" >/dev/null 2>&1; then
    ok "User '${USERNAME}' already exists — reusing it"
  else
    adduser --disabled-password --gecos "" "${USERNAME}"
    ok "Created user '${USERNAME}'"
  fi
  usermod -aG sudo "${USERNAME}"
  echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/90-${USERNAME}"
  chmod 440 "/etc/sudoers.d/90-${USERNAME}"
  visudo -cf "/etc/sudoers.d/90-${USERNAME}" >/dev/null || die "Generated sudoers file is invalid"
  ok "Passwordless sudo enabled for '${USERNAME}'"

  # SSH public key (required) — re-asked until it looks like a public key.
  echo
  warn "── Your SSH PUBLIC key (required) ───────────────────────────────────"
  warn "What:  the *public* half of your SSH keypair — the one-line .pub file."
  warn "Why:   it's installed for '${USERNAME}' so you can authenticate over SSH,"
  warn "       both now (public IP) and later (over Tailscale)."
  warn "Where: on your laptop run  cat ~/.ssh/id_ed25519.pub  and copy the line."
  warn "       No keypair yet?  ssh-keygen -t ed25519  first, then copy the .pub."
  local_key=""
  while :; do
    ask local_key "Paste your SSH public key (ssh-ed25519 / ssh-rsa / ecdsa-...)"
    [[ "${local_key}" =~ ^(ssh-(ed25519|rsa)|ecdsa-) ]] && break
    warn "That doesn't look like a public key — it should start with ssh-ed25519 / ssh-rsa / ecdsa-. Try again."
  done
  user_home="/home/${USERNAME}"
  install -d -m 700 -o "${USERNAME}" -g "${USERNAME}" "${user_home}/.ssh"
  echo "${local_key}" > "${user_home}/.ssh/authorized_keys"
  chmod 600 "${user_home}/.ssh/authorized_keys"
  chown "${USERNAME}:${USERNAME}" "${user_home}/.ssh/authorized_keys"
  ok "Installed SSH key for ${USERNAME}"

  # Hand this terminal to the user so their tmux can attach to it (the pty is
  # currently owned by root; without this, a non-root tmux can't open it).
  tty_dev="$(tty 2>/dev/null || true)"
  [[ -n "${tty_dev}" && -e "${tty_dev}" ]] && chown "${USERNAME}" "${tty_dev}" 2>/dev/null || true

  echo
  log "Re-launching the rest as '${USERNAME}' inside tmux session 'vps-setup'…"
  # The session runs AS the user and is OWNED BY the user; the script inside uses
  # the user's passwordless sudo for privileged steps. -A attaches if it already
  # exists (resume). The trailing read keeps the pane open so you can read the
  # summary if you reattach after it finishes.
  exec sudo -u "${USERNAME}" -H tmux new-session -A -s vps-setup \
    "bash '${SELF}'; printf '\\n[setup finished — press ENTER to close this tmux session] '; read _"
  die "exec into tmux failed"
fi

# ═════════════════════════════════════════════════════════════════════════════
# PHASE B — running as ${USERNAME}, inside its own tmux session
# ═════════════════════════════════════════════════════════════════════════════
user_home="/home/${USERNAME}"
export DEBIAN_FRONTEND=noninteractive

# Mirror all output to the terminal AND append it to a root-owned logfile via
# sudo tee, so there's a full record of the run.
exec > >(sudo tee -a "${LOG_FILE}") 2>&1

echo "╭──────────────────────────────────────────────╮"
echo "│  Hetzner VPS hardening & setup                │"
echo "╰──────────────────────────────────────────────╯"
echo "   user: ${USERNAME}   session: tmux 'vps-setup'   log: ${LOG_FILE}"

# ═════════════════════════════════════════════════════════════════════════════
section "System update & base packages"
# ═════════════════════════════════════════════════════════════════════════════
sudo apt-get update -qq
sudo apt-get upgrade -y -qq
# Only the services the script configures. (tmux is already installed.)
sudo apt-get install -y -qq ufw fail2ban tmux unattended-upgrades >/dev/null
ok "Base packages installed"

# ═════════════════════════════════════════════════════════════════════════════
section "fail2ban (SSH brute-force protection)"
# ═════════════════════════════════════════════════════════════════════════════
sudo tee /etc/fail2ban/jail.local >/dev/null <<EOF
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
sudo systemctl enable fail2ban >/dev/null 2>&1
sudo systemctl restart fail2ban
ok "fail2ban active (ban ${F2B_BANTIME} after ${F2B_MAXRETRY} fails in ${F2B_FINDTIME})"

# ═════════════════════════════════════════════════════════════════════════════
section "cloudflared (Cloudflare Tunnel)"
# ═════════════════════════════════════════════════════════════════════════════
sudo install -d -m 755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
  | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
  | sudo tee /etc/apt/sources.list.d/cloudflared.list >/dev/null
sudo apt-get update -qq
sudo apt-get install -y -qq cloudflared >/dev/null
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
CLOUDFLARED_TUNNEL_TOKEN=""
while :; do
  [[ -z "${CLOUDFLARED_TUNNEL_TOKEN}" ]] && ask CLOUDFLARED_TUNNEL_TOKEN "Cloudflare Tunnel token" silent
  # `service install` decodes the token locally and registers the service.
  if [[ -n "${CLOUDFLARED_TUNNEL_TOKEN}" ]] && sudo cloudflared service install "${CLOUDFLARED_TUNNEL_TOKEN}" >/dev/null 2>&1; then
    sudo systemctl enable --now cloudflared >/dev/null 2>&1 || true
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
# Written as the user, into the user's home — no sudo/chown needed.
cat > "${user_home}/.tmux.conf" <<'EOF'
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
ok "Wrote ${user_home}/.tmux.conf"

# ═════════════════════════════════════════════════════════════════════════════
section "Unattended security upgrades"
# ═════════════════════════════════════════════════════════════════════════════
sudo tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
sudo systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
ok "Automatic security updates enabled"

# ═════════════════════════════════════════════════════════════════════════════
section "Tailscale"
# ═════════════════════════════════════════════════════════════════════════════
# NOTE: bringing Tailscale up can briefly disturb networking. That's exactly why
# we run inside tmux (a blip won't kill the run) and why the firewall below keeps
# public SSH open until you've verified Tailscale works.
curl -fsSL https://tailscale.com/install.sh | sudo sh
ok "Tailscale installed"
sudo systemctl enable --now tailscaled >/dev/null 2>&1 || true

echo
warn "── TAILSCALE login (browser) ────────────────────────────────────────"
warn "What:  joins THIS server to your private tailnet via a browser login."
warn "Why:   Tailscale becomes the private path to SSH — public port 22 is closed"
warn "       at the very end, only after you've confirmed Tailscale SSH works."
warn "How:   tailscale prints a URL below — open it, sign in, and approve this"
warn "       machine. The script waits, then continues automatically."
echo
# --operator lets '${USERNAME}' run tailscale without sudo afterwards.
while :; do
  if sudo tailscale up --ssh --operator="${USERNAME}"; then
    break
  fi
  warn "Tailscale login didn't complete."
  ask_retry "Try Tailscale login again?" || break
done

# Verify Tailscale is actually connected before we trust it for the lockdown.
TS_CONNECTED="false"
TS_IP=""
if sudo tailscale status >/dev/null 2>&1; then
  TS_IP="$(sudo tailscale ip -4 2>/dev/null | head -n1 || true)"
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
# Drop-in config so we never clobber the distro's sshd_config. A reload does NOT
# drop existing sessions, so your current shell stays alive.
sshd_drop="/etc/ssh/sshd_config.d/99-hardening.conf"
sudo install -d -m 755 /etc/ssh/sshd_config.d
sudo tee "${sshd_drop}" >/dev/null <<EOF
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

if sudo sshd -t; then
  sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd 2>/dev/null || sudo systemctl restart ssh
  ok "SSH config valid and reloaded (root login: ${PERMIT_ROOT_LOGIN}, passwords: ${PASSWORD_AUTH})"
else
  sudo rm -f "${sshd_drop}"
  die "sshd config test failed — reverted the drop-in so you keep your current session."
fi

# ═════════════════════════════════════════════════════════════════════════════
section "UFW firewall"
# ═════════════════════════════════════════════════════════════════════════════
sudo ufw --force reset >/dev/null
sudo ufw default deny incoming  >/dev/null
sudo ufw default allow outgoing >/dev/null

# Allow everything over the Tailscale interface — your trusted path in.
sudo ufw allow in on tailscale0 comment 'Tailscale mesh' >/dev/null

# IMPORTANT: keep public SSH OPEN for now. The lockdown step below closes it only
# after you've confirmed a working Tailscale login, so a dropped connection can
# never strand you. UFW permits already-established connections, so enabling it
# here does not cut your current session either.
sudo ufw allow "${SSH_PORT}/tcp" comment 'SSH (public — closed after Tailscale verified)' >/dev/null
sudo ufw --force enable >/dev/null
ok "UFW enabled — default-deny inbound; SSH reachable via Tailscale AND public ${SSH_PORT} for now"

# ═════════════════════════════════════════════════════════════════════════════
section "Lockdown — close public SSH (only after you verify Tailscale)"
# ═════════════════════════════════════════════════════════════════════════════
if is_true "${TS_CONNECTED}"; then
  echo
  warn "Everything is configured and SSH is hardened, but public port ${SSH_PORT} is"
  warn "still OPEN on purpose. Prove you can get in over Tailscale BEFORE closing it:"
  echo
  echo "     1. Leave this tmux session running (don't close this terminal)."
  echo "     2. On a device joined to your tailnet, open a NEW terminal and run:"
  echo
  echo "            ssh ${USERNAME}@${TS_IP}"
  echo
  echo "        Use the new user '${USERNAME}' (root login is disabled) with your SSH key."
  echo "     3. Confirm you get a shell and that 'sudo whoami' prints 'root'."
  echo
  warn "If your laptop isn't on Tailscale yet: install it and 'tailscale up' first."
  echo
  while :; do
    ask GATE "Type 'lock' once Tailscale SSH works — or 'skip' to leave public SSH open"
    case "${GATE,,}" in
      lock|locked|y|yes)
        echo
        warn "About to CLOSE public port ${SSH_PORT}. What happens next:"
        echo "     • If THIS terminal is connected over the public IP, it may freeze"
        echo "       or disconnect the moment the port closes."
        echo "     • That's fine — this session runs in tmux ON THE SERVER as you, so"
        echo "       it does NOT die. It finishes, and the result is in ${LOG_FILE}."
        echo "     • To get back to it, reconnect over Tailscale and reattach — no sudo,"
        echo "       it's your own session:"
        echo
        echo "            ssh ${USERNAME}@${TS_IP}"
        echo "            tmux attach -t vps-setup"
        echo
        echo "       (Already on Tailscale? Nothing drops — you'll just see the summary.)"
        echo
        read -rp "   Press ENTER to close public SSH now (or Ctrl-C to abort and keep it open)... " _
        sudo ufw delete allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || true
        sudo ufw reload >/dev/null 2>&1 || true
        ok "Public port ${SSH_PORT} closed — SSH is now reachable ONLY over Tailscale."
        SSH_EXPOSURE="Tailscale only"
        break ;;
      skip|s|n|no)
        warn "Leaving public SSH OPEN (still key-only + fail2ban)."
        warn "Close it later, once Tailscale works, with:  sudo ufw delete allow ${SSH_PORT}/tcp"
        SSH_EXPOSURE="Public (key-only + fail2ban)"
        break ;;
      *)
        warn "Please type 'lock' (close public SSH) or 'skip' (keep it open)." ;;
    esac
  done
else
  warn "Tailscale was not confirmed — leaving public SSH OPEN so you aren't locked out."
  warn "Once Tailscale works (sudo tailscale up --ssh) and you've verified  ssh ${USERNAME}@<tailscale-ip> ,"
  warn "close public SSH with:  sudo ufw delete allow ${SSH_PORT}/tcp"
  SSH_EXPOSURE="Public (key-only + fail2ban)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# Persistent-session login hook (written LAST, so reconnects during setup land in
# a plain shell where `tmux attach -t vps-setup` works without interference).
# ═════════════════════════════════════════════════════════════════════════════
profile="${user_home}/.bash_profile"
if ! grep -q "tmux attach -t main" "${profile}" 2>/dev/null; then
  cat >> "${profile}" <<'EOF'

# Load .bashrc (PATH like ~/.local/bin, aliases) for login shells too
if [ -f "$HOME/.bashrc" ]; then . "$HOME/.bashrc"; fi

# Auto-attach to a persistent tmux session on interactive SSH login
if command -v tmux >/dev/null 2>&1 && [ -n "$PS1" ] && [ -z "$TMUX" ] && [ -n "$SSH_CONNECTION" ]; then
  tmux attach -t main 2>/dev/null || tmux new -s main
fi
EOF
fi
ok "Future logins auto-attach to tmux session 'main'"

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
if [[ "${SSH_EXPOSURE}" == "Tailscale only" ]]; then
  echo "  Done. From now on, reach this box over Tailscale:  ssh ${USERNAME}@${TS_IP}"
else
  echo "  Public SSH is still open. Verify  ssh ${USERNAME}@${TS_IP:-<tailscale-ip>}  works,"
  echo "  then close it with:  sudo ufw delete allow ${SSH_PORT}/tcp"
fi
echo
