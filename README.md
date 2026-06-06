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
- **Your SSH public key** — `cat ~/.ssh/id_ed25519.pub` on your laptop.
  **Required** (re-asks on bad format). Tailscale restricts *where* SSH is
  reachable from; this key proves *who* you are.
- **Tailscale login** — the script runs `tailscale up` and prints a URL; open
  it, sign in, and approve the machine. No auth key needed. (Re-asks to retry if
  the login doesn't complete.)
- **Cloudflare Tunnel token** from Zero Trust →
  **Networks → Tunnels → Install connector** — required, and **re-asks until a
  token successfully registers the tunnel**.

Everything else is fixed policy. To change a hardening decision for all future
runs, edit the *Fixed policy* constants near the top of `harden-vps.sh`.

## Safety: you can't lock yourself out

- **It survives an SSH drop.** The script re-launches itself inside a `tmux`
  session on the server, so if your connection ever dies mid-run the work keeps
  going on the box. The session runs as **root**, so once the non-root user
  exists (and root SSH is disabled) you reconnect as that user and reattach with
  `sudo tmux attach -t vps-setup`. (Without the tmux wrapper, a dropped
  connection sends `SIGHUP` and the run dies half-done — leaving the box
  partially configured.)
- **Public SSH stays open until you've proven Tailscale works.** All the safe
  configuration runs first; the network lockdown is last. After Tailscale is up
  and SSH is hardened, the script *stops* and asks you to open a **second
  terminal**, `ssh <user>@<tailscale-ip>`, and confirm you get in. Only when you
  type `lock` does it close public port 22. Type `skip` (or if Tailscale can't be
  confirmed) and public SSH is left open — still key-only + fail2ban — rather
  than stranding you.
- **It warns before it cuts you off.** Right before closing port 22 it explains
  what's about to happen and prints the exact commands to reconnect over
  Tailscale and reattach to the running `tmux` session.
- SSH config is written as a **drop-in** and validated with `sshd -t` before
  reload; if it's invalid the drop-in is removed so your current session stays up.
  A reload never drops existing sessions, so your root shell stays alive.
- It's meant to run **once on a freshly provisioned box**.

## Security notes

A few deliberate trade-offs, called out so there are no surprises:

- **Official remote installers.** Tailscale and the Cloudflare apt repo are set up
  via their vendor scripts (`curl … | sudo sh`, signed GPG keyring). Convenient
  and standard, but it does run vendor code as root — pin/vendor it yourself if
  your threat model requires.
- **Passwordless sudo** for the created user (`NOPASSWD:ALL`). The auth factor is
  your SSH key; the account has no password. Drop `NOPASSWD` if you'd rather be
  prompted.
- **Cloudflare token.** Passed to `cloudflared service install` as an argument, so
  it's briefly visible in `ps` to local users (cloudflared's own interface). It's
  prompted with no echo and never written to the repo or logged.
- No secrets or keys are stored in this repo — everything sensitive is prompted at
  runtime. `*.log` is gitignored.

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
