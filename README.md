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

As root on the fresh server, from inside this repo:

```bash
./harden-vps.sh
```

There are no flags, config files, or environment variables — every run produces
the same hardened box. The script **asks for what it needs, when it needs it**,
and re-asks if you give it something it can't use:

- **Username** for the non-root sudo account (re-asks if invalid).
- **Your SSH public key** — `cat ~/.ssh/id_ed25519.pub` on your laptop
  (re-asks on bad format; blank is allowed since Tailscale SSH still gets you in).
- **Tailscale auth key** from
  https://login.tailscale.com/admin/settings/keys — **re-asks if the key is
  rejected**. Leave it blank to log in via the browser URL it prints instead.
- **Cloudflare Tunnel token** from Zero Trust →
  **Networks → Tunnels → Install connector** — required, and **re-asks until a
  token successfully registers the tunnel**.

Everything else is fixed policy. To change a hardening decision for all future
runs, edit the *Fixed policy* constants near the top of `harden-vps.sh`.

## Safety: you can't lock yourself out

- The firewall is only restricted to Tailscale **after** Tailscale is confirmed
  connected. If it isn't, **public SSH is left open** (still key-only +
  fail2ban) and the script tells you how to close port 22 once Tailscale works.
- SSH config is written as a **drop-in** and validated with `sshd -t` before
  reload; if it's invalid the drop-in is removed so your current session stays up.
- Tailscale SSH is always enabled, so even a blank SSH key still leaves you a
  way in over the tailnet (the script warns you when no key is installed).
- **Always verify access in a second terminal before closing your root session.**
  The script reminds you at the end.
- It's meant to run **once on a freshly provisioned box** (it assumes the user
  and config don't already exist).

## After it finishes

```bash
# In a NEW terminal, over Tailscale:
ssh <username>@<tailscale-ip>
sudo whoami        # -> root
```

Only then close the original root session.

## Files

| File              | Purpose                              |
|-------------------|--------------------------------------|
| `harden-vps.sh`   | the setup script (run as root)       |
| `.gitignore`      | keeps run logs out of git            |

A full log of each run is written to `/var/log/harden-vps.log`.

## References / inspiration

- https://github.com/deniurchak/claude-vps-setup-prompt/blob/main/hetzner-public.md
- https://andrey-markin.com/blog/claude-code-vps-setup
- https://www.thetalhatahir.com/blog/personal-ai-assistant-with-claude-code
