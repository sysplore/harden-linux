# Running this repo with Semaphore UI

Semaphore is the control plane for inventory, credentials, execution, schedules,
RBAC and job history. This repository is the hardening product: the playbooks,
roles and profiles that Semaphore runs.

Do not build a second executor or a second credential store. Semaphore must be
the only component that can log in to a host.

## Architecture

```text
Semaphore
  inventories / credentials / environments
  task templates / schedules / users / task history
        |
        |  runs ansible-playbook from this repo
        v
  Debian / Ubuntu hosts
        ^
        |  artifacts: job logs, Lynis/AIDE/rkhunter output, diffs
        |
  Your SIEM / ticketing / reporting (optional)
```

## Automated bootstrap

`scripts/semaphore_bootstrap.py` creates the project, SSH key, repository,
inventory, environment and task templates through the Semaphore API. It is
idempotent: existing names are reused. It targets the Semaphore 2.16 API
(the instance at `sp.sysplore.com` reports 2.16.14).

1. Push this repository to the Git remote Semaphore will clone.
2. Create an API token in Semaphore: account menu -> **API Tokens**.
3. Copy the example environment file and fill it in:

   ```bash
   cp semaphore.env.example semaphore.env
   chmod 600 semaphore.env
   $EDITOR semaphore.env
   ```

4. Preview, then run:

   ```bash
   set -a; . ./semaphore.env; set +a
   python3 scripts/semaphore_bootstrap.py --dry-run
   python3 scripts/semaphore_bootstrap.py
   ```

`semaphore.env` is gitignored. The script reads the private key from
`SEMAPHORE_SSH_KEY_FILE` and sends it to Semaphore; it does not write any secret
to the repository.

The script creates these templates:

- `harden-check`
- `harden-apply`
- `harden-bsi`
- `harden-strict`
- `maintenance-report`
- `notify-test`
- `drift-check`
- `bootstrap` (only when `SEMAPHORE_BOOTSTRAP_PASSWORD` is set)

It does not create schedules or approvals; add those in the Semaphore UI. Use
`--limit` for the first run, for example `--limit server1`.

Hosts are added in Semaphore. The script creates the empty `linux` / `debian` /
`ubuntu` group structure; leave `SEMAPHORE_INVENTORY_FILE` empty unless you
explicitly want to seed hosts from a file.

## 1. Install Semaphore

Run Semaphore on a hardened management host, behind a VPN or at least TLS, and
restrict who can reach it. Do not expose it to the public internet.

Set a persistent encryption key before adding credentials:

```bash
export SEMAPHORE_ACCESS_KEY_ENCRYPTION="$(head -c 32 /dev/urandom | base64)"
```

Back this value up. Without it, Semaphore cannot decrypt the credentials in its
database. Back up the Semaphore database with the key.

## 2. Create the project

1. Create a project.
2. Add a **Key Store** credential:
   - `ansible` user, SSH private key (steady state).
   - A root or sudo-capable credential for the one-time bootstrap.
3. Add an **Inventory** using the same group structure as `hosts.yml`:

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

The groups `linux`, `debian` and `ubuntu` are required: `group_vars/debian.yml`
and `group_vars/ubuntu.yml` are loaded by group name.

4. Add an **Environment** with any non-secret defaults, for example:

```json
{
  "ansible_user": "ansible",
  "harden_serial": "1"
}
```

For the sudo password, use a vaulted `host_vars/<host>.yml` with
`ansible_become_password`, or a secret environment variable if your Semaphore
version supports secret variables. The repository defaults to
`sudo_nopasswd: false`; granting `NOPASSWD: ALL` to the automation account is a
deliberate risk decision, not a default.

## 3. Bootstrap

Create a task template:

| Field | Value |
|---|---|
| Playbook | `requirements-playbook.yml` |
| Inventory | your project inventory |
| Credential | root or sudo-capable bootstrap credential |
| Limit | one host, then a small batch |
| Extra variables | `{"bootstrap_user": "root"}` |

This creates the `ansible` user, the `sshusers`/`sudousers`/`suusers` groups,
sudoers drop-ins and the authorized key. Run it per host or in small batches.

## 4. Hardening task templates

| Template | Playbook | Extra CLI arguments |
|---|---|---|
| `harden-check` | `main-playbook.yml` | `--check --diff --extra-vars @profiles/baseline.yml` |
| `harden-apply` | `main-playbook.yml` | `--extra-vars @profiles/nist-800-53.yml` |
| `harden-bsi` | `main-playbook.yml` | `--extra-vars @profiles/bsi-grundschutz.yml` |
| `harden-strict` | `main-playbook.yml` | `--extra-vars @profiles/strict.yml` |
| `maintenance-report` | `main-playbook.yml` | `--tags lynis,integrity --extra-vars @profiles/baseline.yml` |
| `notify-test` | `main-playbook.yml` | `--tags notify -e notify_test=true` |
| `drift-check` | `main-playbook.yml` | `--check --diff --tags system,ssh,password,firewall,updates,audit,integrity --extra-vars @profiles/baseline.yml` |

Use `--limit` per host or group. For production, run `harden-check` first and
review the diff in the Semaphore task log before running `harden-apply`.

Notifications are configured per host or per Semaphore environment with the
`notify_*` variables. Backends are `smtp`, `webhook`, `ntfy`, `gotify` and
`none`; `auto` selects the first configured one. Run the `notify-test` template
once after changing a backend.

A canary flow:

1. `harden-check` with `--limit web01`.
2. Review the diff and the Lynis/AIDE artifacts.
3. `harden-apply` with `--limit web01`.
4. Verify SSH, UFW and the application.
5. Apply to the rest in batches (`harden_serial: "25%"`).

## 5. Schedules

Typical schedule:

| Job | Cadence |
|---|---|
| `drift-check` | weekly |
| `maintenance-report` | daily or weekly |
| `harden-check` | weekly |
| `harden-apply` | monthly, after review |

Semaphore stores task history. If you need long-term evidence, export the task
artifact/log to your SIEM or ticketing system. Do not build a second scheduler.

## 6. Guardrails

- Always run `--check --diff` before applying.
- Keep a second SSH session open during the first SSH run. The SSH role writes a
  drop-in, validates with `sshd -t`, and refuses to restart on an invalid config.
- `auditd` rules become immutable (`-e 2`) until reboot. Plan rule changes.
- `proc_hidepid` and `mount_*_hardening` can break monitoring agents and
  applications that execute from `/tmp`. Test on a canary host.
- Keep `harden_continue_on_error: false` in production. Optional roles are still
  individually guarded so missing mail does not abort the run.
- Do not give Semaphore users more project access than they need. Use its RBAC.
- Rotate the `ansible` SSH key and the Semaphore credentials on a schedule.

## 7. What the profiles do

Profiles are extra-vars files:

| Profile | Intent |
|---|---|
| `profiles/baseline.yml` | Sensible defaults for a general server |
| `profiles/nist-800-53.yml` | NIST SP 800-53 Rev. 5 / 800-63B-4 orientation |
| `profiles/bsi-grundschutz.yml` | BSI IT-Grundschutz SYS.1.1 / SYS.1.3 orientation |
| `profiles/strict.yml` | High-value hosts, MFA and stricter lockout |

Profiles set `harden_features` and policy variables. They do not bypass the
roles' safety checks.

## 8. What not to do

- Do not store SSH keys or passwords in this repository.
- Do not run `ansible-playbook` from a second web app. Use Semaphore.
- Do not use `--check` as a substitute for a backup or a canary.
- Do not disable `sshd -t`, `visudo -cf` or `fail2ban-client -t` validation to
  make a bad config "work".
