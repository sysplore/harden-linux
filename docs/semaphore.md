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
`SEMAPHORE_SSH_KEY_FILE`, the matching public key from
`SEMAPHORE_SSH_PUBLIC_KEY_FILE`, and sends them to Semaphore. The public key is
stored in the environment as `ssh_public_key` so the bootstrap playbook can
install it for the `ansible` user. It does not write any secret to the repo.

The script creates these templates:

- `harden-one` — single server, end-to-end form; registers the host on success
- `add-host` — add a server to the inventory from a form
- `sync-hosts` — refresh the fleet host dropdown after manual inventory edits
- `fleet` — hosts from `linux-ansible`; choose a host or group, Dry run = check
- `maintenance-report` — Lynis and AIDE only
- `bootstrap` — optional fleet bootstrap when the `ansible` user/key is missing

The bootstrap creates one environment (`harden`) shared by both templates. The
form's current SSH user/password and sudo password are used for the initial
connection; the hardening user's managed password is stored as
`ansible_become_password` and `user_pw` for fleet. The one-host environment split
was removed.

It does not create schedules or approvals; add those in the Semaphore UI. Use
the **Target host** dropdown (or the **Limit** field) for the first run.

Rerun the bootstrap after upgrading an existing project. That creates the
`add-host` and `sync-hosts` templates, adds the `fleet_host` dropdown to
`fleet`, and stores the inventory API settings and token in the environment.

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

| Template | Playbook | Use |
|---|---|---|
| `harden-one` | `harden-one.yml` | One server; fill the form; registers the host on success |
| `add-host` | `add-host.yml` | Add or update one inventory host from a form |
| `sync-hosts` | `sync-hosts.yml` | Refresh the fleet host dropdown after manual YAML edits |
| `fleet` | `main-playbook.yml` | Inventory hosts; host dropdown and profile selector; Dry run for check |
| `maintenance-report` | `main-playbook.yml` | `--tags lynis,integrity` |
| `bootstrap` | `requirements-playbook.yml` | Fleet bootstrap only |

### Adding hosts from the UI

Semaphore 2.16 has no structured host editor, so this repository supplies one
through the `add-host` template. The `fleet` **Target host** dropdown is a
`fleet_host` survey variable kept in sync by the inventory helper; it is not a
native Semaphore host picker.

1. Run `add-host`. Enter the server IP or hostname, pick Debian or Ubuntu, and
   optionally set the current SSH user, address override and SSH port.
2. The playbook writes the host into the `linux-ansible` static YAML inventory
   through the Semaphore API and refreshes the `fleet` **Target host** dropdown.
3. Run `fleet`. Select one host in **Target host**, or leave it at
   **All linux hosts** and use **Extra hosts or groups** with comma-separated
   patterns for several hosts. The current SSH port comes from the inventory;
   set the new SSH port, new hardening user, profile and mail settings, then
   check **Dry run** and review.

`fleet` runs the bootstrap requirements step before the hardening roles, so the
new hardening username, the SSH port and the inventory key are applied on the
selected hosts. The **Current SSH user** field overrides the inventory
credential user for that run. After a successful hardening run, every selected
host is registered in the inventory with its hardening user and SSH port; this
happens after the SSH handlers have run, and a failed run does not update the
inventory.

The SMTP fields behave as in `harden-one`: leave **Notification email** blank to
skip mail entirely, or set it and choose **Verify SMTP now = No** to configure
mail without sending a test message. `open_inbound_tcp` is passed to the
firewall role.

`harden-one` remains the single-server path: IP, current user, password and all
common settings in one form. It takes an optional **Current SSH port** for the
first connection and an optional **New SSH port** for the final sshd port; the
new port is opened in UFW before the change, and sshd restarts only once, after
the hardening tasks finish. The initial bootstrap can use `root` as the current
user; the new hardening user receives the SSH key and the managed password.
After a successful run the inventory stores the hardening user and the effective
port, so `fleet` can run as that user and use the managed password for sudo.
Set **Current SSH user** only when you deliberately want a different connection
account for that run. It registers the target under the IP or hostname you
entered; use `add-host` if you want a separate inventory name. The initial
password is used for the first bootstrap and is not stored. `add-host` assumes
the host already accepts the key, so use `harden-one` or `bootstrap` for a fresh
server. Semaphore 2.16 supports one SSH credential per inventory, so per-host
passwords would require separate inventories.

The bootstrap generates or reuses a managed password for the hardening user and
stores it in Semaphore as `ansible_become_password` and `user_pw`. The
requirements role sets that password on the hardening user, so fleet can sudo as
the hardening user without NOPASSWD. Set `SEMAPHORE_BECOME_PASSWORD` to pin a
specific password; otherwise it is generated once in
`SEMAPHORE_BECOME_PASSWORD_FILE` (default
`~/.config/harden-linux/semaphore_become_password`, mode 0600). Keep that file
or set the variable if you rerun the bootstrap from another machine.

This needs an API token with project write access. The bootstrap stores
`SEMAPHORE_RUNNER_API_TOKEN` (or `SEMAPHORE_API_TOKEN` when the former is
empty) as the `semaphore_api_token` environment secret, and also sets
`semaphore_url`, `semaphore_project_id` and `semaphore_inventory_id` in the
environment. Every task using that environment can read the token; use a
dedicated token and rotate it if that is too broad for your deployment. The
runner must also be able to reach `SEMAPHORE_URL`; use an internal URL if the
public one is not reachable from the runner.

If you edit the inventory YAML by hand, run `sync-hosts` to refresh the
dropdown. The helper rewrites the YAML, so comments and formatting are not
preserved. Removing a host from the inventory does not remove it from existing
task history or from a running task. The dropdown lists up to every host in the
inventory; for large fleets use the optional **Limit** field with a host
pattern instead.

Use the **Target host** dropdown for one host, **Extra hosts or groups** or the
optional **Limit** field for several. For production, run `fleet` with
**Dry run** checked and review the diff in the task log. Run it again with Dry
run unchecked to apply.

Notifications are configured per host or per Semaphore environment with the
`notify_*` variables. Backends are `smtp`, `webhook`, `ntfy`, `gotify` and
`none`; `auto` selects the first configured one. Test with:

```bash
sudo /usr/local/sbin/harden-notify --test
```

A canary flow:

1. `fleet`, select `web01`, Dry run checked.
2. Review the diff and the Lynis/AIDE artifacts.
3. `fleet`, select `web01`, Dry run unchecked.
4. Verify SSH, UFW and the application.
5. Apply to the rest in batches (`harden_serial: "25%"`).

## 5. Schedules

Typical schedule:

| Job | Cadence |
|---|---|
| `fleet` (Dry run) | weekly |
| `maintenance-report` | daily or weekly |
| `fleet` (apply) | monthly, after review |

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
