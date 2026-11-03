#!/usr/bin/env python3
"""Bootstrap a Semaphore UI project for this hardening repository.

This script creates, idempotently:
  - a project
  - an SSH key (and optionally a bootstrap login/password key)
  - a repository
  - a hardening inventory (and optionally a bootstrap inventory)
  - an environment with inventory API settings and optional secrets
  - task templates for single-host, inventory, maintenance and bootstrap runs

It uses only the Python standard library. Secrets are read from the environment
or files and are never written to the repository.

Usage:
  export SEMAPHORE_URL=https://sp.sysplore.com
  export SEMAPHORE_API_TOKEN=...        # do not commit this
  export SEMAPHORE_REPO_URL=https://github.com/sysplore/harden-linux.git
  export SEMAPHORE_SSH_KEY_FILE=~/.ssh/id_ed25519
  # optional: export SEMAPHORE_INVENTORY_FILE=hosts.yml
  python3 scripts/semaphore_bootstrap.py --dry-run
  python3 scripts/semaphore_bootstrap.py
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional


class APIError(RuntimeError):
    pass


DEFAULT_INVENTORY = """all:
  children:
    linux:
      children:
        debian:
          hosts: {}
        ubuntu:
          hosts: {}
"""


class Semaphore:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Any:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "harden-linux-semaphore-bootstrap/1.0")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                raw = response.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            raise APIError(f"{method} {path} -> HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise APIError(f"{method} {path} -> {exc.reason}") from exc

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(self, path: str, body: Dict[str, Any]) -> Any:
        return self.request("POST", path, body)


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def find_by_name(items: List[Dict[str, Any]], name: str) -> Optional[Dict[str, Any]]:
    return next((item for item in items if item.get("name") == name), None)


def ensure_project(api: Semaphore, name: str, dry_run: bool) -> Dict[str, Any]:
    print(f"project: {name}")
    if dry_run:
        return {"id": 0, "name": name}
    for project in api.get("/api/projects"):
        if project.get("name") == name:
            print(f"  exists (id={project['id']})")
            return project
    project = api.post("/api/projects", {"name": name, "alert": False, "max_parallel_tasks": 0})
    print(f"  created (id={project['id']})")
    return project


def ensure_key(
    api: Semaphore,
    project_id: int,
    name: str,
    key_type: str,
    payload: Dict[str, Any],
    dry_run: bool,
) -> Dict[str, Any]:
    print(f"key: {name} ({key_type})")
    if dry_run:
        return {"id": 0, "name": name}
    path = f"/api/project/{project_id}/keys"
    for key in api.get(f"{path}?sort=name&order=asc"):
        if key.get("name") == name:
            print(f"  exists (id={key['id']})")
            return key
    body = {"name": name, "type": key_type, "project_id": project_id}
    body.update(payload)
    key = api.post(path, body)
    print(f"  created (id={key['id']})")
    return key


def ensure_repository(
    api: Semaphore,
    project_id: int,
    name: str,
    git_url: str,
    branch: str,
    ssh_key_id: Optional[int],
    dry_run: bool,
) -> Dict[str, Any]:
    print(f"repository: {name} -> {git_url}")
    if dry_run:
        return {"id": 0, "name": name}
    path = f"/api/project/{project_id}/repositories"
    for repo in api.get(f"{path}?sort=name&order=asc"):
        if repo.get("name") == name:
            print(f"  exists (id={repo['id']})")
            if repo.get("git_url") != git_url:
                print(f"  WARNING: existing git_url is {repo.get('git_url')}", file=sys.stderr)
            return repo
    body: Dict[str, Any] = {
        "name": name,
        "project_id": project_id,
        "git_url": git_url,
        "git_branch": branch,
    }
    if ssh_key_id:
        body["ssh_key_id"] = ssh_key_id
    repo = api.post(path, body)
    print(f"  created (id={repo['id']})")
    return repo


def ensure_inventory(
    api: Semaphore,
    project_id: int,
    name: str,
    inventory: str,
    ssh_key_id: int,
    dry_run: bool,
) -> Dict[str, Any]:
    print(f"inventory: {name}")
    if dry_run:
        return {"id": 0, "name": name}
    path = f"/api/project/{project_id}/inventory"
    for item in api.get(f"{path}?sort=name&order=asc"):
        if item.get("name") == name:
            print(f"  exists (id={item['id']})")
            return item
    body = {
        "name": name,
        "project_id": project_id,
        "type": "static-yaml",
        "inventory": inventory,
        "ssh_key_id": ssh_key_id,
    }
    item = api.post(path, body)
    print(f"  created (id={item['id']})")
    return item


def ensure_environment(
    api: Semaphore,
    project_id: int,
    name: str,
    secrets: List[Dict[str, Any]],
    extra_vars: Dict[str, str],
    dry_run: bool,
) -> Dict[str, Any]:
    print(f"environment: {name}")
    if dry_run:
        return {"id": 0, "name": name}
    path = f"/api/project/{project_id}/environment"
    environment_vars = {"harden_serial": "1"}
    environment_vars.update(extra_vars)

    def resolve_secrets(existing: Dict[str, Any]) -> List[Dict[str, Any]]:
        resolved = []
        for secret in secrets:
            item = dict(secret)
            if item["name"] in existing:
                item["id"] = existing[item["name"]]
                item["operation"] = "update"
            else:
                item["operation"] = "create"
            resolved.append(item)
        return resolved

    for item in api.get(f"{path}?sort=name&order=asc"):
        if item.get("name") == name:
            print(f"  exists (id={item['id']})")
            if secrets or extra_vars:
                detail = api.get(f"{path}/{item['id']}")
                existing_secrets = {
                    secret.get("name"): secret.get("id")
                    for secret in (detail.get("secrets") or [])
                }
                body: Dict[str, Any] = {
                    "id": item["id"],
                    "name": name,
                    "project_id": project_id,
                    "json": json.dumps(environment_vars),
                    "env": detail.get("env") or "{}",
                }
                if secrets:
                    body["secrets"] = resolve_secrets(existing_secrets)
                api.request("PUT", f"{path}/{item['id']}", body)
                print("  variables updated")
            return item
    body = {
        "name": name,
        "project_id": project_id,
        "json": json.dumps(environment_vars),
        "env": "{}",
    }
    if secrets:
        body["secrets"] = secrets
    item = api.post(path, body)
    print(f"  created (id={item['id']})")
    return item


def ensure_template(
    api: Semaphore,
    project_id: int,
    name: str,
    inventory_id: int,
    repository_id: int,
    environment_id: int,
    playbook: str,
    arguments: List[str],
    branch: str,
    description: str,
    dry_run: bool,
    survey_vars: Optional[List[Dict[str, Any]]] = None,
    task_params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    print(f"template: {name}")
    if dry_run:
        return {"id": 0, "name": name}
    path = f"/api/project/{project_id}/templates"
    for item in api.get(f"{path}?sort=name&order=asc"):
        if item.get("name") == name:
            print(f"  exists (id={item['id']})")
            if survey_vars is not None or task_params is not None:
                update_body = dict(api.get(f"{path}/{item['id']}"))
                update_body.update(
                    {
                        "name": name,
                        "project_id": project_id,
                        "inventory_id": inventory_id,
                        "repository_id": repository_id,
                        "environment_id": environment_id,
                        "playbook": playbook,
                        "arguments": json.dumps(arguments),
                        "description": description,
                        "app": "ansible",
                        "git_branch": branch,
                        "allow_override_args_in_task": True,
                    }
                )
                if survey_vars is not None:
                    existing_vars = update_body.get("survey_vars") or []
                    desired_names = {var["name"] for var in survey_vars}
                    preserved_names = {"fleet_host"} if name == "fleet" else set()
                    update_body["survey_vars"] = list(survey_vars) + [
                        var
                        for var in existing_vars
                        if var.get("name") not in desired_names
                        and var.get("name") in preserved_names
                    ]
                if task_params is not None:
                    merged_task_params = dict(update_body.get("task_params") or {})
                    merged_task_params.update(task_params)
                    update_body["task_params"] = merged_task_params
                api.request("PUT", f"{path}/{item['id']}", update_body)
                print("  updated template settings")
            return item
    body = {
        "name": name,
        "project_id": project_id,
        "inventory_id": inventory_id,
        "repository_id": repository_id,
        "environment_id": environment_id,
        "playbook": playbook,
        "arguments": json.dumps(arguments),
        "description": description,
        "app": "ansible",
        "git_branch": branch,
        "allow_override_args_in_task": True,
    }
    if survey_vars is not None:
        body["survey_vars"] = survey_vars
    if task_params is not None:
        body["task_params"] = task_params
    item = api.post(path, body)
    print(f"  created (id={item['id']})")
    return item


def ensure_fleet_host_survey(api: Semaphore, project_id: int) -> None:
    print("fleet host dropdown: fleet_host")
    templates = api.get(f"/api/project/{project_id}/templates?sort=name&order=asc")
    fleet = find_by_name(templates, "fleet")
    if not fleet:
        print("  fleet template not found; skipping")
        return

    path = f"/api/project/{project_id}/templates/{fleet['id']}"
    template = api.get(path)
    survey_vars = template.get("survey_vars") or []
    fleet_var = next((var for var in survey_vars if var.get("name") == "fleet_host"), None)
    if fleet_var:
        if survey_vars[0] is fleet_var:
            print("  exists")
            return
        survey_vars.remove(fleet_var)
        survey_vars.insert(0, fleet_var)
        template["survey_vars"] = survey_vars
        api.request("PUT", path, template)
        print("  moved to the top")
        return

    survey_vars.insert(
        0,
        {
            "name": "fleet_host",
            "title": "Target host",
            "description": "Pick one host from the inventory, or All linux hosts.",
            "type": "enum",
            "required": False,
            "values": [{"name": "All linux hosts", "value": ""}],
        },
    )
    template["survey_vars"] = survey_vars
    api.request("PUT", path, template)
    print("  created")


def read_private_key(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"SSH private key not found: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        print(f"WARNING: {path} is accessible by group/other ({oct(mode)})", file=sys.stderr)
    return path.read_text(encoding="utf-8")


def load_or_create_become_password(value: str) -> str:
    if value:
        return value

    path = Path(
        env("SEMAPHORE_BECOME_PASSWORD_FILE", "~/.config/harden-linux/semaphore_become_password")
    ).expanduser()
    if path.is_file():
        password = path.read_text(encoding="utf-8").strip()
        if password:
            return password

    password = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(password + "\n", encoding="utf-8")
    path.chmod(0o600)
    print(f"Generated a managed become password and stored it in {path}", file=sys.stderr)
    return password


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap a Semaphore project for harden-linux.")
    parser.add_argument("--dry-run", action="store_true", help="print the plan without calling the API")
    parser.add_argument("--prune", action="store_true", help="delete templates not in the managed set")
    args = parser.parse_args()

    base_url = env("SEMAPHORE_URL")
    token = env("SEMAPHORE_API_TOKEN")
    project_name = env("SEMAPHORE_PROJECT", "harden-linux")
    repo_url = env("SEMAPHORE_REPO_URL", "https://github.com/sysplore/harden-linux.git")
    branch = env("SEMAPHORE_REPO_BRANCH", "main")
    repo_name = env("SEMAPHORE_REPO_NAME", "harden-linux")
    key_name = env("SEMAPHORE_KEY_NAME", "Semaphore")
    ssh_login = env("SEMAPHORE_SSH_LOGIN", "ansible")
    ssh_key_file = Path(env("SEMAPHORE_SSH_KEY_FILE", "~/.ssh/id_ed25519")).expanduser()
    ssh_key_passphrase = env("SEMAPHORE_SSH_KEY_PASSPHRASE")
    ssh_public_key = env("SEMAPHORE_SSH_PUBLIC_KEY")
    if not ssh_public_key:
        pub_path = Path(env("SEMAPHORE_SSH_PUBLIC_KEY_FILE", f"{ssh_key_file}.pub")).expanduser()
        if pub_path.is_file():
            ssh_public_key = pub_path.read_text(encoding="utf-8").strip()
    if not ssh_public_key:
        print("WARNING: no SSH public key found; set SEMAPHORE_SSH_PUBLIC_KEY_FILE or SEMAPHORE_SSH_PUBLIC_KEY.", file=sys.stderr)
    inventory_file_value = env("SEMAPHORE_INVENTORY_FILE")
    inventory_name = env("SEMAPHORE_INVENTORY_NAME", "linux-ansible")
    env_name = env("SEMAPHORE_ENV_NAME", "harden")
    bootstrap_login = env("SEMAPHORE_BOOTSTRAP_LOGIN", "root")
    bootstrap_password = env("SEMAPHORE_BOOTSTRAP_PASSWORD")
    become_password = env("SEMAPHORE_BECOME_PASSWORD")
    if not args.dry_run:
        become_password = load_or_create_become_password(become_password)

    if not args.dry_run and (not base_url or not token):
        raise SystemExit("SEMAPHORE_URL and SEMAPHORE_API_TOKEN are required unless --dry-run is used.")

    if inventory_file_value:
        inventory_file = Path(inventory_file_value).expanduser()
        if not inventory_file.is_file():
            raise SystemExit(f"inventory file not found: {inventory_file}")
        inventory_text = inventory_file.read_text(encoding="utf-8")
    else:
        inventory_text = DEFAULT_INVENTORY

    if args.dry_run:
        print(f"project: {project_name} (would ensure)")
        print(f"key: {key_name} (ssh, login={ssh_login}) (would ensure)")
        if not repo_url.startswith(("git@", "ssh://")):
            print("key: none (none) (would ensure)")
        if bootstrap_password:
            print(f"key: bootstrap-login (login_password, login={bootstrap_login}) (would ensure)")
        print(f"repository: {repo_name} -> {repo_url} (would ensure)")
        print(f"inventory: {inventory_name} (would ensure)")
        if bootstrap_password:
            print("inventory: linux-bootstrap (would ensure)")
        print(f"environment: {env_name} (would ensure)")
        print("environment vars: semaphore_url, semaphore_project_id, semaphore_inventory_id, semaphore_ssh_login")
        if become_password:
            print("environment secrets: semaphore_api_token, ansible_become_password, user_pw")
        else:
            print("become password: would generate and store a managed password")
            print("environment secrets: semaphore_api_token, ansible_become_password, user_pw")
        print(f"environment: {env_name}-one (would ensure)")
        print("environment secrets: semaphore_api_token, user_pw")

    api = Semaphore(base_url, token) if not args.dry_run else None
    assert api is not None or args.dry_run

    project = ensure_project(api, project_name, args.dry_run) if api else {"id": 0, "name": project_name}
    project_id = int(project["id"])

    key = ensure_key(
        api,
        project_id,
        key_name,
        "ssh",
        {"ssh": {"login": ssh_login, "private_key": read_private_key(ssh_key_file), "passphrase": ssh_key_passphrase}},
        args.dry_run,
    ) if api else {"id": 0, "name": key_name}

    repo_key = key
    if not repo_url.startswith(("git@", "ssh://")):
        repo_key = ensure_key(api, project_id, "none", "none", {}, args.dry_run) if api else {"id": 0, "name": "none"}

    bootstrap_key = None
    if bootstrap_password:
        bootstrap_key = ensure_key(
            api,
            project_id,
            "bootstrap-login",
            "login_password",
            {"login_password": {"login": bootstrap_login, "password": bootstrap_password}},
            args.dry_run,
        ) if api else {"id": 0, "name": "bootstrap-login"}

    repo = ensure_repository(
        api,
        project_id,
        repo_name,
        repo_url,
        branch,
        int(repo_key.get("id") or 0),
        args.dry_run,
    ) if api else {"id": 0, "name": repo_name}

    inventory = ensure_inventory(
        api,
        project_id,
        inventory_name,
        inventory_text,
        int(key.get("id") or 1),
        args.dry_run,
    ) if api else {"id": 0, "name": inventory_name}

    bootstrap_inventory = None
    if bootstrap_key:
        bootstrap_inventory = ensure_inventory(
            api,
            project_id,
            "linux-bootstrap",
            inventory_text,
            int(bootstrap_key.get("id") or 1),
            args.dry_run,
        ) if api else {"id": 0, "name": "linux-bootstrap"}

    secrets = []
    if become_password:
        secrets.extend(
            [
                {
                    "name": "ansible_become_password",
                    "secret": become_password,
                    "type": "var",
                    "operation": "create",
                },
                {
                    "name": "user_pw",
                    "secret": become_password,
                    "type": "var",
                    "operation": "create",
                },
            ]
        )

    runner_api_token = env("SEMAPHORE_RUNNER_API_TOKEN") or token
    if runner_api_token:
        secrets.append(
            {
                "name": "semaphore_api_token",
                "secret": runner_api_token,
                "type": "env",
                "operation": "create",
            }
        )
    elif not args.dry_run:
        print(
            "WARNING: no Semaphore API token available; add-host, sync-hosts and "
            "harden-one registration will not update the inventory.",
            file=sys.stderr,
        )

    environment_extra = {
        "semaphore_url": base_url.rstrip("/"),
        "semaphore_project_id": str(project_id),
        "semaphore_inventory_id": str(int(inventory.get("id") or 1)),
        "semaphore_ssh_login": ssh_login,
    }
    if ssh_public_key:
        environment_extra["ssh_public_key"] = ssh_public_key
    environment = ensure_environment(api, project_id, env_name, secrets, environment_extra, args.dry_run) if api else {"id": 0, "name": env_name}
    one_host_env_name = f"{env_name}-one"
    one_host_secrets = [secret for secret in secrets if secret["name"] != "ansible_become_password"]
    one_host_environment = (
        ensure_environment(api, project_id, one_host_env_name, one_host_secrets, environment_extra, args.dry_run)
        if api
        else {"id": 0, "name": one_host_env_name}
    )

    env_id = int(environment.get("id") or 1)
    one_host_env_id = int(one_host_environment.get("id") or 1)
    inv_id = int(inventory.get("id") or 1)
    repo_id = int(repo.get("id") or 1)

    common_survey = [
        {
            "name": "harden_profile",
            "title": "Hardening profile",
            "description": "Leave blank for baseline.",
            "type": "enum",
            "required": False,
            "values": [
                {"name": "Baseline", "value": "baseline"},
                {"name": "NIST 800-53", "value": "nist-800-53"},
                {"name": "BSI Grundschutz", "value": "bsi-grundschutz"},
                {"name": "Strict", "value": "strict"},
            ],
        },
        {
            "name": "harden_user",
            "title": "New hardening username",
            "description": "Account to create; blank = ansible.",
            "type": "",
            "required": False,
        },
        {
            "name": "ssh_port",
            "title": "SSH port",
            "description": "Blank = 22. A single selected fleet host is updated in the inventory.",
            "type": "int",
            "required": False,
        },
        {
            "name": "open_inbound_tcp",
            "title": "Inbound TCP ports",
            "description": "Comma-separated, e.g. 25,465,587,993,995. Blank = none.",
            "type": "",
            "required": False,
        },
        {
            "name": "mail_to",
            "title": "Notification email",
            "description": "Blank = email disabled (skip SMTP).",
            "type": "",
            "required": False,
        },
        {
            "name": "mail_smtp_server",
            "title": "SMTP server",
            "type": "",
            "required": False,
        },
        {
            "name": "mail_port",
            "title": "SMTP port",
            "description": "Blank = 587.",
            "type": "int",
            "required": False,
        },
        {
            "name": "mail_user",
            "title": "SMTP username",
            "description": "Blank = use the From address.",
            "type": "",
            "required": False,
        },
        {
            "name": "mail_from",
            "title": "From address",
            "description": "Blank = root@hostname.",
            "type": "",
            "required": False,
        },
        {
            "name": "mail_pw",
            "title": "SMTP password",
            "type": "secret",
            "required": False,
        },
        {
            "name": "mail_tls_starttls",
            "title": "STARTTLS",
            "description": "Yes for 587, No for 465. Blank = Yes.",
            "type": "enum",
            "required": False,
            "values": [
                {"name": "Yes", "value": "true"},
                {"name": "No", "value": "false"},
            ],
        },
        {
            "name": "mail_verify",
            "title": "Verify SMTP now",
            "description": "No = save SMTP settings without sending a test (skip the SMTP check).",
            "type": "enum",
            "required": False,
            "values": [
                {"name": "No", "value": "false"},
                {"name": "Yes", "value": "true"},
            ],
        },
    ]

    one_host_survey = [
        {
            "name": "target_host",
            "title": "Server IP or hostname",
            "description": "The server to harden.",
            "type": "",
            "required": True,
        },
        {
            "name": "target_group",
            "title": "Distribution",
            "type": "enum",
            "required": True,
            "values": [
                {"name": "Debian", "value": "debian"},
                {"name": "Ubuntu", "value": "ubuntu"},
            ],
        },
        {
            "name": "target_user",
            "title": "Current SSH user",
            "description": "Leave blank for ubuntu on Ubuntu, root on Debian.",
            "type": "",
            "required": False,
        },
        {
            "name": "target_password",
            "title": "SSH password",
            "type": "secret",
            "required": True,
        },
        {
            "name": "target_become_password",
            "title": "Sudo password",
            "description": "Defaults to the SSH password.",
            "type": "secret",
            "required": False,
        },
    ] + common_survey

    add_host_survey = [
        {
            "name": "inventory_host",
            "title": "Server IP or hostname",
            "description": "Name used in the inventory and the default address.",
            "type": "",
            "required": True,
        },
        {
            "name": "inventory_address",
            "title": "Address override",
            "description": "Blank = use the server IP or hostname above.",
            "type": "",
            "required": False,
        },
        {
            "name": "inventory_group",
            "title": "Distribution",
            "type": "enum",
            "required": True,
            "default_value": "ubuntu",
            "values": [
                {"name": "Debian", "value": "debian"},
                {"name": "Ubuntu", "value": "ubuntu"},
            ],
        },
        {
            "name": "inventory_user",
            "title": "Current SSH user",
            "description": "Blank = the Semaphore SSH key user.",
            "type": "",
            "required": False,
        },
        {
            "name": "inventory_port",
            "title": "SSH port",
            "description": "Blank = 22.",
            "type": "int",
            "required": False,
        },
    ]

    fleet_survey = [
        {
            "name": "ansible_user",
            "title": "Current SSH user",
            "description": "User used to connect now; blank = the inventory credential user.",
            "type": "",
            "required": False,
        },
        {
            "name": "fleet_hosts",
            "title": "Extra hosts or groups",
            "description": "Comma-separated host patterns; overrides the Target host dropdown. Use for multiple hosts.",
            "type": "",
            "required": False,
        },
    ] + common_survey

    templates = [
        (
            "harden-one",
            "harden-one.yml",
            ["--extra-vars", "inventory_registration_enabled=true"],
            "Add one server by IP and password, bootstrap it, and harden it.",
            one_host_survey,
            None,
        ),
        (
            "fleet",
            "fleet-playbook.yml",
            ["--extra-vars", "inventory_registration_enabled=true"],
            "Fleet: select one or more inventory hosts; bootstrap and harden. Use Dry run for check.",
            fleet_survey,
            {"allow_override_limit": True},
        ),
        (
            "maintenance-report",
            "main-playbook.yml",
            ["--tags", "lynis,integrity", "--extra-vars", "@profiles/baseline.yml"],
            "Run the Lynis and AIDE maintenance report.",
            None,
            None,
        ),
        (
            "bootstrap",
            "requirements-playbook.yml",
            ["--extra-vars", f"bootstrap_user={bootstrap_login}"],
            "Bootstrap the hardening user and SSH access.",
            None,
            None,
        ),
        (
            "add-host",
            "add-host.yml",
            [],
            "Add a server to the Semaphore inventory from a form.",
            add_host_survey,
            None,
        ),
        (
            "sync-hosts",
            "sync-hosts.yml",
            [],
            "Refresh the fleet host dropdown from the inventory.",
            None,
            None,
        ),
    ]

    for name, playbook, arguments, description, survey_vars, task_params in templates:
        if name == "bootstrap" and not bootstrap_inventory:
            print("template: bootstrap (skipped: set SEMAPHORE_BOOTSTRAP_PASSWORD to create it)")
            continue
        template_inventory = int(bootstrap_inventory["id"] or 1) if name == "bootstrap" else inv_id
        template_environment = one_host_env_id if name == "harden-one" else env_id
        if api:
            ensure_template(
                api,
                project_id,
                name,
                template_inventory,
                repo_id,
                template_environment,
                playbook,
                arguments,
                branch,
                description,
                args.dry_run,
                survey_vars=survey_vars,
                task_params=task_params,
            )
        else:
            print(f"template: {name} ({playbook}) -> {' '.join(arguments)} (would create)")

    if api:
        ensure_fleet_host_survey(api, project_id)
    else:
        print("fleet host dropdown: fleet_host (would ensure)")

    managed_templates = {entry[0] for entry in templates}
    if args.prune and api:
        for item in api.get(f"/api/project/{project_id}/templates?sort=name&order=asc"):
            if item.get("name") not in managed_templates:
                api.request("DELETE", f"/api/project/{project_id}/templates/{item['id']}")
                print(f"template: {item['name']} (removed)")

    print("\nDone.")
    if not args.dry_run:
        print(f"Open {base_url.rstrip('/')}/project/{project_id}/templates")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except APIError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
