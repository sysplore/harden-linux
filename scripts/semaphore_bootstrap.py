#!/usr/bin/env python3
"""Bootstrap a Semaphore UI project for this hardening repository.

This script creates, idempotently:
  - a project
  - an SSH key (and optionally a bootstrap login/password key)
  - a repository
  - a hardening inventory (and optionally a bootstrap inventory)
  - an environment with an optional become-password secret
  - task templates for bootstrap, check, apply, drift and maintenance runs

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
    dry_run: bool,
) -> Dict[str, Any]:
    print(f"environment: {name}")
    if dry_run:
        return {"id": 0, "name": name}
    path = f"/api/project/{project_id}/environment"
    for item in api.get(f"{path}?sort=name&order=asc"):
        if item.get("name") == name:
            print(f"  exists (id={item['id']})")
            if secrets:
                body: Dict[str, Any] = {
                    "name": name,
                    "project_id": project_id,
                    "json": json.dumps({"harden_serial": "1"}),
                    "env": "{}",
                    "secrets": secrets,
                }
                api.request("PUT", f"{path}/{item['id']}", body)
                print("  secrets updated")
            return item
    body: Dict[str, Any] = {
        "name": name,
        "project_id": project_id,
        "json": json.dumps({"harden_serial": "1"}),
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
    arguments: str,
    branch: str,
    description: str,
    dry_run: bool,
) -> Dict[str, Any]:
    print(f"template: {name}")
    if dry_run:
        return {"id": 0, "name": name}
    path = f"/api/project/{project_id}/templates"
    for item in api.get(f"{path}?sort=name&order=asc"):
        if item.get("name") == name:
            print(f"  exists (id={item['id']})")
            return item
    body = {
        "name": name,
        "project_id": project_id,
        "inventory_id": inventory_id,
        "repository_id": repository_id,
        "environment_id": environment_id,
        "playbook": playbook,
        "arguments": arguments,
        "description": description,
        "app": "ansible",
        "git_branch": branch,
        "allow_override_args_in_task": True,
    }
    item = api.post(path, body)
    print(f"  created (id={item['id']})")
    return item


def read_private_key(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"SSH private key not found: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        print(f"WARNING: {path} is accessible by group/other ({oct(mode)})", file=sys.stderr)
    return path.read_text(encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap a Semaphore project for harden-linux.")
    parser.add_argument("--dry-run", action="store_true", help="print the plan without calling the API")
    args = parser.parse_args()

    base_url = env("SEMAPHORE_URL")
    token = env("SEMAPHORE_API_TOKEN")
    project_name = env("SEMAPHORE_PROJECT", "harden-linux")
    repo_url = env("SEMAPHORE_REPO_URL", "https://github.com/sysplore/harden-linux.git")
    branch = env("SEMAPHORE_REPO_BRANCH", "main")
    repo_name = env("SEMAPHORE_REPO_NAME", "harden-linux")
    key_name = env("SEMAPHORE_KEY_NAME", "ansible-ssh")
    ssh_login = env("SEMAPHORE_SSH_LOGIN", "ansible")
    ssh_key_file = Path(env("SEMAPHORE_SSH_KEY_FILE", "~/.ssh/id_ed25519")).expanduser()
    inventory_file_value = env("SEMAPHORE_INVENTORY_FILE")
    inventory_name = env("SEMAPHORE_INVENTORY_NAME", "linux-ansible")
    env_name = env("SEMAPHORE_ENV_NAME", "harden")
    bootstrap_login = env("SEMAPHORE_BOOTSTRAP_LOGIN", "root")
    bootstrap_password = env("SEMAPHORE_BOOTSTRAP_PASSWORD")
    become_password = env("SEMAPHORE_BECOME_PASSWORD")

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
        if bootstrap_password:
            print(f"key: bootstrap-login (login_password, login={bootstrap_login}) (would ensure)")
        print(f"repository: {repo_name} -> {repo_url} (would ensure)")
        print(f"inventory: {inventory_name} (would ensure)")
        if bootstrap_password:
            print("inventory: linux-bootstrap (would ensure)")
        print(f"environment: {env_name} (would ensure)")

    api = Semaphore(base_url, token) if not args.dry_run else None
    assert api is not None or args.dry_run

    project = ensure_project(api, project_name, args.dry_run) if api else {"id": 0, "name": project_name}
    project_id = int(project["id"])

    key = ensure_key(
        api,
        project_id,
        key_name,
        "ssh",
        {"ssh": {"login": ssh_login, "private_key": read_private_key(ssh_key_file), "passphrase": ""}},
        args.dry_run,
    ) if api else {"id": 0, "name": key_name}

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
        int(key.get("id") or 0) if repo_url.startswith(("git@", "ssh://")) else None,
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
        secrets.append(
            {
                "name": "ansible_become_password",
                "secret": become_password,
                "type": "var",
                "operation": "create",
            }
        )
    else:
        print("WARNING: SEMAPHORE_BECOME_PASSWORD is not set; tasks need passwordless sudo or a become secret.", file=sys.stderr)

    environment = ensure_environment(api, project_id, env_name, secrets, args.dry_run) if api else {"id": 0, "name": env_name}

    env_id = int(environment.get("id") or 1)
    inv_id = int(inventory.get("id") or 1)
    repo_id = int(repo.get("id") or 1)

    templates = [
        (
            "bootstrap",
            "requirements-playbook.yml",
            f"--extra-vars bootstrap_user={bootstrap_login}",
            "Bootstrap the hardening user and SSH access.",
        ),
        (
            "harden-check",
            "main-playbook.yml",
            "--check --diff --extra-vars @profiles/baseline.yml",
            "Preview the baseline hardening changes.",
        ),
        (
            "harden-apply",
            "main-playbook.yml",
            "--extra-vars @profiles/nist-800-53.yml",
            "Apply the NIST-oriented hardening profile.",
        ),
        (
            "harden-bsi",
            "main-playbook.yml",
            "--extra-vars @profiles/bsi-grundschutz.yml",
            "Apply the BSI-oriented hardening profile.",
        ),
        (
            "harden-strict",
            "main-playbook.yml",
            "--extra-vars @profiles/strict.yml",
            "Apply the strict high-value-host profile.",
        ),
        (
            "maintenance-report",
            "main-playbook.yml",
            "--tags lynis,integrity --extra-vars @profiles/baseline.yml",
            "Run the Lynis and AIDE maintenance report.",
        ),
        (
            "notify-test",
            "main-playbook.yml",
            "--tags notify -e notify_test=true",
            "Send a notification test through the configured backend.",
        ),
        (
            "drift-check",
            "main-playbook.yml",
            "--check --diff --tags system,ssh,password,firewall,updates,audit,integrity --extra-vars @profiles/baseline.yml",
            "Check for drift without applying changes.",
        ),
    ]

    for name, playbook, arguments, description in templates:
        if name == "bootstrap" and not bootstrap_inventory:
            print("template: bootstrap (skipped: set SEMAPHORE_BOOTSTRAP_PASSWORD to create it)")
            continue
        template_inventory = int(bootstrap_inventory["id"] or 1) if name == "bootstrap" else inv_id
        if api:
            ensure_template(
                api,
                project_id,
                name,
                template_inventory,
                repo_id,
                env_id,
                playbook,
                arguments,
                branch,
                description,
                args.dry_run,
            )
        else:
            print(f"template: {name} ({playbook}) -> {arguments} (would create)")

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
