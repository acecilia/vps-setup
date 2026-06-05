# vps-setup

First-boot hardening & setup for a **vanilla Hetzner VPS** (Debian/Ubuntu).
One script takes a fresh box you've just `ssh root@`'d into and turns it into a
private, locked-down server you reach over Tailscale.

## What it sets up

| Layer            | What you get                                                              |
|------------------|---------------------------------------------------------------------------|
| **Tailscale**    | SSH over your private mesh; the box becomes a `100.x.x.x` node            |
| **SSH hardening**| key-only auth, no root password login, drop-in config, `AllowUsers`      |
| **fail2ban**     | bans brute-forcers (ignores Tailscale/LAN ranges)                        |
| **UFW**          | default-deny inbound; **SSH locked to the `tailscale0` interface**        |
| **cloudflared**  | Cloudflare Tunnel — expose services with **zero open inbound ports**     |
| **tmux**         | persistent sessions; login auto-attaches to a `main` session             |
| **Extras**       | non-root sudo user, unattended security upgrades, base tooling           |

The guiding idea (from the reference guides): **SSH is never exposed to the
public internet** — it lives behind Tailscale, and anything you want to serve
goes out through a Cloudflare Tunnel, so the firewall stays default-deny.

## Usage

From your laptop, copy this folder up and connect:

```bash
scp -r vps-setup root@<server-ip>:/root/
ssh root@<server-ip>
```

On the server:

```bash
cd vps-setup
cp config.env.example config.env
nano config.env          # set USERNAME, SSH_PUBLIC_KEY, Tailscale auth key, etc.
./harden-vps.sh
```

You can also run it with no `config.env` — it'll prompt for the essentials and
use safe defaults for the rest.

### Get the values you'll need

- **`SSH_PUBLIC_KEY`** — on your laptop: `cat ~/.ssh/id_ed25519.pub` (the whole line).
- **`TAILSCALE_AUTHKEY`** — https://login.tailscale.com/admin/settings/keys
  (a reusable/ephemeral key lets the script run unattended; otherwise it does an
  interactive `tailscale up` and prints a login URL).
- **`CLOUDFLARED_TUNNEL_TOKEN`** *(optional)* — Cloudflare Zero Trust dashboard →
  **Networks → Tunnels → Create/Install connector**. With it, the script installs
  the tunnel as a service automatically. Without it, the binary is installed and
  you finish the tunnel later.

## Safety: you can't lock yourself out

- The firewall is only restricted to Tailscale **after** Tailscale is confirmed
  connected. If it isn't, **public SSH is left open** (still key-only +
  fail2ban) and the script tells you to re-run once Tailscale works.
- SSH config is written as a **drop-in** and validated with `sshd -t` before
  reload; if it's invalid the drop-in is removed so your current session stays up.
- **Always verify access in a second terminal before closing your root session.**
  The script reminds you at the end.
- The script is **idempotent** — safe to re-run after fixing config.

## After it finishes

```bash
# In a NEW terminal, over Tailscale:
ssh <username>@<tailscale-ip>
sudo whoami        # -> root
```

Only then close the original root session.

## Files

| File                   | Purpose                                          |
|------------------------|--------------------------------------------------|
| `harden-vps.sh`        | the setup script (run as root)                   |
| `config.env.example`   | template config — copy to `config.env`           |
| `config.env`           | **your** settings (gitignored — holds secrets)   |
| `.gitignore`           | keeps `config.env` and logs out of git           |

A full log of each run is written to `/var/log/harden-vps.log`.

## Customising

Everything is driven by `config.env`. Re-running the script after changing it
applies the new settings. A few common tweaks:

- Keep public SSH open: `SSH_TAILSCALE_ONLY="false"`.
- Skip cloudflared: `INSTALL_CLOUDFLARED="false"`.
- Tighter bans: lower `F2B_MAXRETRY`, raise `F2B_BANTIME`.

## References / inspiration

- https://github.com/deniurchak/claude-vps-setup-prompt/blob/main/hetzner-public.md
- https://andrey-markin.com/blog/claude-code-vps-setup
- https://www.thetalhatahir.com/blog/personal-ai-assistant-with-claude-code
