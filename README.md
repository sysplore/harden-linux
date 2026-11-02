# Harden Linux

Ansible roles for hardening Debian and Ubuntu servers, designed to be run
directly from the CLI or from [Semaphore UI](docs/semaphore.md).

The hardening logic lives in this repository. Semaphore is the inventory,
credential, execution and scheduling plane. There is no second web app and no
second credential store.

## How it works

Three pieces:

1. **This repository** — hardening roles, playbooks and profiles. It contains no
   real hosts and no credentials.
2. **Semaphore** — stores servers, SSH credentials and sudo secrets; clones this
   repo, runs a playbook with the profile you choose, keeps logs and schedules.
3. **The target server** — Debian or Ubuntu.

For Semaphore, do not edit `hosts.yml`. Add servers to the Semaphore inventory.
`hosts.yml` is only for the optional CLI path.

## Harden one server (no inventory editing)

This is the simple path. In Semaphore:

1. **Task Templates** → `harden-one` → **Run**.
2. Fill the form:
   - **Server IP or hostname**
   - **Distribution**: Debian or Ubuntu
   - **SSH user**: leave blank for `root`
   - **SSH password**
   - **Sudo password**: leave blank to reuse the SSH password
3. Run it.

The template adds the host dynamically, runs the bootstrap playbook (creates the
`ansible` user, groups, sudoers and SSH key), then runs the full hardening
playbook. When it finishes, root SSH is disabled; use the `ansible` user and key
for later runs. You do not need to edit the inventory YAML for this path.

Use the inventory YAML editor only for the fleet path: add hosts to
`linux-ansible`, then run `harden-check` / `harden-apply` against them.

## First server in Semaphore (fleet inventory)

1. **Repositories** → New Repository: `https://github.com/sysplore/harden-linux.git`,
   branch `main`. It is public, so no Git key is required.
2. **Key Store** → New Key: `ansible-ssh`, type SSH, login `ansible`, private
   key. The matching public key must be in `/home/ansible/.ssh/authorized_keys`
   on the server.
3. If the server has no `ansible` key yet, create `bootstrap-root` (root
   password or root SSH key) and a `linux-bootstrap` inventory with the same
   hosts. Run the `bootstrap` template first.
4. **Inventory** → New Inventory: `linux-ansible`, type Static YAML, SSH key
   `ansible-ssh`. This is where hosts live:

   ```yaml
   all:
     children:
       linux:
         children:
           debian:
             hosts:
               web01:
                 ansible_host: 203.0.113.10
           ubuntu:
             hosts:
               app01:
                 ansible_host: 203.0.113.11
   ```

5. **Environment** → New Environment: add `ansible_become_password` as a secret
   variable, `ssh_public_key` as a normal variable (the public half of
   `ansible-ssh`), and any `notify_*` variables you want.
6. **Task Templates** → New Template: `harden-check`, playbook
   `main-playbook.yml`, inventory `linux-ansible`, repository and environment as
   above, arguments `--check --diff --extra-vars @profiles/baseline.yml`.
7. Run `harden-check` with `--limit web01`. Review the diff in the task log. Then
   run `harden-apply` with the same limit.
8. For a fresh server, run the `bootstrap` template first
   (`requirements-playbook.yml`, `linux-bootstrap`, `--extra-vars
   bootstrap_user=root`), then switch to `linux-ansible`.

Profiles: `baseline.yml`, `nist-800-53.yml`, `bsi-grundschutz.yml`, `strict.yml`.
`scripts/semaphore_bootstrap.py` creates the repository entry, key, inventory,
environment and templates for you; it deliberately does not add hosts.

## Supported platforms

- Debian 12 (Bookworm) and Debian 13 (Trixie)
- Ubuntu 22.04 LTS and later (including 24.04 and 26.04 LTS)

## What it does

| Area | Role | Highlights |
|---|---|---|
| Packages | `packages` | Debian/Ubuntu aware, optional upgrade, minimal package set |
| Kernel / system | `system_hardening` | sysctl, ASLR, kptr/dmesg restrictions, login.defs, umask, mount hardening, module blacklist |
| Time | `ntp` | systemd-timesyncd, verified synchronization |
| Logging | `logging` | persistent journald, rsyslog, iptables log separation, logrotate, logwatch |
| SSH | `ssh` | drop-in config, key-only auth, MFA-ready, modern KEX/ciphers/MACs, `sshd -t` validation |
| Passwords / lockout | `password_quality` | pwquality (NIST 800-63B-4 aligned), faillock |
| Updates | `unattended_upgrades` | distro-specific security origins, conffile-safe upgrades, reboot window |
| Firewall / IDS | `firewall` | UFW default-deny, psad, fail2ban, notifications |
| Mail | `mail` | msmtp, aliases, non-fatal test message |
| Notifications | `notify` | SMTP, webhook, ntfy, Gotify, local-only |
| Malware | `clamav`, `rkhunter` | scheduled scans, logs, notifications |
| Integrity | `integrity` | AIDE database and daily check |
| Audit | `auditd` | pinned Neo23x0 rules, local watches, immutable rules |
| Audit report | `lynis` | HTML report, local retention or notifications |
| Bootstrap | `requirements` | sudo user, groups, sudoers drop-ins, su restriction, authorized key |

See [AUDIT.md](AUDIT.md) for the security review, NIST/BSI mapping and remaining
gaps.

## Quick start (CLI)

1. Install the tooling:

   ```bash
   pip install ansible-core passlib
   ansible-galaxy collection install -r requirements.yml
   ```

2. Create the inventory:

   ```bash
   cp host_vars/example.yml host_vars/server1.yml
   ```

   Edit `hosts.yml` and add the host under the correct distro group:

   ```yaml
   all:
     children:
       linux:
         children:
           debian:
             hosts:
               server1:
                 ansible_host: 203.0.113.10
           ubuntu:
             hosts: {}
   ```

3. Put connection credentials in `host_vars/server1.yml` and encrypt them:

   ```bash
   ansible-vault encrypt_string --name 'ansible_password' 'secret'
   ```

4. Bootstrap the host:

   ```bash
   ansible-playbook -i hosts.yml requirements-playbook.yml --ask-vault-pass
   ```

5. Preview and apply hardening:

   ```bash
   ansible-playbook -i hosts.yml main-playbook.yml --ask-vault-pass --check --diff
   ansible-playbook -i hosts.yml main-playbook.yml --ask-vault-pass
   ```

6. For later runs, use the `ansible` user and its SSH key instead of a password.

## Reusable inventory and credentials

- `hosts.yml` holds hosts and groups only.
- `host_vars/<host>.yml` holds per-host connection details and overrides.
- `group_vars/all.yml` holds shared defaults.
- `group_vars/debian.yml` and `group_vars/ubuntu.yml` hold distro-specific
  defaults.
- Secrets are vaulted or supplied by Semaphore. They are never committed.

If you previously used `group_vars/variables.yml`, migrate its values into
`group_vars/all.yml` and vaulted `host_vars/<host>.yml`. That file was tracked
in git before this refactor: **rotate any credential that was ever committed**.
Deleting the file does not remove it from git history.

## Feature selection

Choose roles per host with `harden_features`:

```yaml
harden_features:
  packages: true
  system: true
  ntp: true
  logging: true
  mail: false
  notify: true
  ssh: true
  password_policy: true
  unattended_upgrades: true
  firewall: true
  clamav: false
  rkhunter: true
  integrity: true
  auditd: true
  lynis: true
  mfa: false
```

Every role also has a tag:

```bash
ansible-playbook ... --tags ssh,firewall
ansible-playbook ... --skip-tags clamav,lynis
```

## Notifications (SMTP optional)

SMTP is not required. The `notify` role installs
`/usr/local/sbin/harden-notify` and routes alerts from ClamAV, AIDE, rkhunter,
Lynis, logwatch, fail2ban and the reboot-required check.

| `notify_backend` | Requires | Behaviour |
|---|---|---|
| `auto` | — | SMTP if `mail_to` is set, else webhook, ntfy, gotify, else `none` |
| `smtp` | `mail_to` + SMTP settings | msmtp/mail |
| `webhook` | `notify_webhook_url` | JSON POST to a generic endpoint |
| `ntfy` | `notify_ntfy_topic` | ntfy.sh or self-hosted |
| `gotify` | URL + token | self-hosted Gotify |
| `none` | — | local-only log at `/var/log/harden/notify.log` |

Examples:

```yaml
# Slack
notify_backend: webhook
notify_webhook_url: "https://hooks.slack.com/services/..."
notify_webhook_field: text

# Discord uses "content" instead of "text"
# notify_webhook_field: content

# ntfy
notify_backend: ntfy
notify_ntfy_url: "https://ntfy.sh"
notify_ntfy_topic: "my-secret-topic"
# notify_ntfy_token: "..."   # protected topics

# Gotify
notify_backend: gotify
notify_gotify_url: "https://gotify.example.com"
notify_gotify_token: "..."

# No network notifications at all
notify_backend: none
```

Test it with:

```bash
ansible-playbook -i hosts.yml main-playbook.yml --tags notify -e notify_test=true
# or on the host
sudo /usr/local/sbin/harden-notify --test
```

Webhook URLs and tokens are secrets. Vault them or provide them through
Semaphore; `/etc/harden-notify.conf` is mode `0600`.

If `mail_to` is empty and no webhook/ntfy/gotify target is configured, the
notifier is installed in local-only mode. Everything still logs locally, and
the reboot-required check is sent through the configured backend.

`psad` and `unattended-upgrades` keep their native mail hooks. With no SMTP
they log locally; the notifier covers the reboot-required signal and all other
alert sources.

If `mail_to` is set, `mail_smtp_server` and `mail_pw` are required and validated
before the play changes anything.

## Safety

- `sshd`, `sudoers` and `fail2ban` configs are validated before restart.
- Config edits use `backup: true` where practical.
- Optional roles can be set to continue on error, but production defaults to
  failing fast.
- `auditd` rules are immutable (`-e 2`) until reboot.
- `proc_hidepid` and mount hardening are opt-in/opt-out and can break agents or
  applications that execute from `/tmp`; test on a canary host.
- `password_quality` edits PAM. Test on a canary host; set
  `faillock_enabled: false` if your release lacks `pam_faillock`.
- The default sysctl profile disables IPv6 router advertisements. Override
  `sysctl_settings` if the host uses SLAAC/DHCPv6.
- Keep a second SSH session open during the first SSH run.

## Semaphore

See [docs/semaphore.md](docs/semaphore.md) for inventory, credentials, task
templates, schedules and guardrails. To create the project and templates
automatically, use `scripts/semaphore_bootstrap.py` with `semaphore.env`.

## Verification

```bash
yamllint .
ansible-lint
ansible-playbook --syntax-check -i hosts.yml main-playbook.yml
ansible-playbook --syntax-check -i hosts.yml requirements-playbook.yml
```

On a host after a run:

```bash
sshd -T | grep -E 'permitrootlogin|passwordauthentication|kbdinteractiveauthentication|authenticationmethods'
ufw status verbose
systemctl is-active auditd fail2ban psad clamav-freshclam
/usr/local/sbin/harden-notify --test
unattended-upgrade --dry-run
lynis audit system
```

## Credits

This project started from
[How To Secure A Linux Server](https://github.com/imthenachoman/How-To-Secure-A-Linux-Server)
and its Ansible companion by [moltenbit](https://github.com/moltenbit). The
audit rules are from [Neo23x0](https://github.com/Neo23x0/auditd).

## License

Documentation is licensed CC BY-SA 4.0. See [LICENSE](LICENSE).
