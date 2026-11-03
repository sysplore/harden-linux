#!/usr/bin/env python3
"""Maintain the Semaphore hardening inventory through the Semaphore API.

Semaphore 2.16 stores static inventories as one YAML/INI document. This helper
adds a host to a static-yaml inventory and keeps the `fleet_host` survey
dropdown on the `fleet` template in sync, so hosts can be selected in the task
form instead of hand-editing YAML.

The API token is read from the environment (`SEMAPHORE_API_TOKEN` or
`semaphore_api_token`) so it never appears in process arguments.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover - ansible-core always ships PyYAML
    print("error: PyYAML is required (it ships with ansible-core)", file=sys.stderr)
    raise SystemExit(1)


DISTRIBUTIONS = ("debian", "ubuntu")
FLEET_TEMPLATE_NAME = "fleet"
FLEET_SURVEY_VAR = "fleet_host"
ALL_HOSTS_LABEL = "All linux hosts"
USER_PW_SECRET = "user_pw"


def env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return default


class InventoryError(RuntimeError):
    pass


class SemaphoreAPI:
    def __init__(self, base_url: str, token: str, timeout: int = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        if not re.match(r"^https?://", self.base_url):
            raise InventoryError("SEMAPHORE_URL must start with http:// or https://")

    def request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
    ) -> Tuple[int, Any]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(self.base_url + path, data=data, method=method)
        request.add_header("Authorization", f"Bearer {self.token}")
        request.add_header("Accept", "application/json")
        request.add_header("User-Agent", "harden-linux-semaphore-inventory/1.0")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
                return response.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace").strip()
            if exc.code in (401, 403):
                raise InventoryError(
                    f"Semaphore rejected the API token (HTTP {exc.code}); "
                    "the token needs project write access"
                ) from exc
            raise InventoryError(f"{method} {path} returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise InventoryError(f"cannot reach Semaphore at {self.base_url}: {exc.reason}") from exc

    def get(self, path: str) -> Any:
        return self.request("GET", path)[1]

    def put(self, path: str, body: Dict[str, Any]) -> None:
        self.request("PUT", path, body)


def validate_args(args: argparse.Namespace) -> None:
    if not args.host or not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", args.host):
        raise InventoryError(
            "host must start with a letter or digit and contain only letters, "
            "digits, '.', '_' or '-' (use a name for IPv6 targets and put the "
            "address in --address)"
        )
    if args.host in ("all", "linux", "debian", "ubuntu"):
        raise InventoryError("host must not shadow an inventory group name")
    if not args.address or not re.match(r"^[A-Za-z0-9][A-Za-z0-9._:%-]*$", args.address):
        raise InventoryError(
            "address must start with a letter or digit and contain only letters, "
            "digits, '.', '_', ':', '%' or '-'"
        )
    if args.group not in DISTRIBUTIONS:
        raise InventoryError("group must be debian or ubuntu")
    if args.user and re.search(r"[\s,]", args.user):
        raise InventoryError("user must not contain spaces or ','")
    if args.port is not None and not (1 <= args.port <= 65535):
        raise InventoryError("port must be between 1 and 65535")


def ensure_dict(parent: Dict[str, Any], key: str) -> Dict[str, Any]:
    value = parent.get(key)
    if value is None:
        value = {}
        parent[key] = value
    if not isinstance(value, dict):
        raise InventoryError(f"inventory key '{key}' is not a mapping")
    return value


def load_tree(inventory: Dict[str, Any]) -> Dict[str, Any]:
    if inventory.get("type") not in ("static", "static-yaml"):
        raise InventoryError(
            "only static-yaml inventories can be edited; "
            "change the inventory type in Semaphore"
        )
    raw = inventory.get("inventory") or ""
    if not isinstance(raw, str):
        raise InventoryError("inventory content is not a string")
    tree = yaml.safe_load(raw) or {}
    if not isinstance(tree, dict):
        raise InventoryError("inventory must be a YAML mapping")
    return tree


def host_groups(tree: Dict[str, Any]) -> Dict[str, Any]:
    all_group = ensure_dict(tree, "all")
    children = ensure_dict(all_group, "children")
    linux = ensure_dict(children, "linux")
    return ensure_dict(linux, "children")


def hosts_in_tree(tree: Dict[str, Any]) -> List[str]:
    hosts = set()
    for group in host_groups(tree).values():
        if not isinstance(group, dict):
            continue
        group_hosts = group.get("hosts")
        if isinstance(group_hosts, dict):
            hosts.update(str(host) for host in group_hosts)
    return sorted(hosts)


def update_tree(tree: Dict[str, Any], args: argparse.Namespace) -> Tuple[Dict[str, Any], List[str]]:
    groups = host_groups(tree)
    notes: List[str] = []

    for group_name in DISTRIBUTIONS:
        group = ensure_dict(groups, group_name)
        ensure_dict(group, "hosts")

    for group_name in DISTRIBUTIONS:
        if group_name == args.group:
            continue
        other_hosts = groups[group_name]["hosts"]
        if args.host in other_hosts:
            del other_hosts[args.host]
            notes.append(f"removed {args.host} from group {group_name}")

    target_hosts = groups[args.group]["hosts"]
    existing = target_hosts.get(args.host)
    host_vars = dict(existing) if isinstance(existing, dict) else {}

    host_vars["ansible_host"] = args.address
    if args.port is None or args.port == 22:
        host_vars.pop("ansible_port", None)
    else:
        host_vars["ansible_port"] = args.port
    if args.user:
        host_vars["ansible_user"] = args.user

    target_hosts[args.host] = host_vars
    return tree, notes


def dump_tree(tree: Dict[str, Any]) -> str:
    return yaml.safe_dump(
        tree,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=1000,
    )


def sync_fleet_dropdown(
    api: SemaphoreAPI,
    project_id: int,
    tree: Dict[str, Any],
    check: bool = False,
    strict: bool = False,
) -> bool:
    try:
        templates = api.get(f"/api/project/{project_id}/templates?sort=name&order=asc") or []
        fleet = next((item for item in templates if item.get("name") == FLEET_TEMPLATE_NAME), None)
        if not fleet:
            print(
                f"warning: template '{FLEET_TEMPLATE_NAME}' not found; host dropdown not updated",
                file=sys.stderr,
            )
            return False

        template = api.get(f"/api/project/{project_id}/templates/{fleet['id']}")
        survey_vars = template.get("survey_vars") or []
        fleet_var = next((item for item in survey_vars if item.get("name") == FLEET_SURVEY_VAR), None)
        if not fleet_var:
            print(
                f"warning: {FLEET_TEMPLATE_NAME}.{FLEET_SURVEY_VAR} survey variable not found; "
                "rerun scripts/semaphore_bootstrap.py",
                file=sys.stderr,
            )
            return False

        values = [{"name": ALL_HOSTS_LABEL, "value": ""}]
        values.extend({"name": host, "value": host} for host in hosts_in_tree(tree))

        if fleet_var.get("values") == values:
            return False
        if check:
            return True

        fleet_var["values"] = values
        api.put(f"/api/project/{project_id}/templates/{template['id']}", template)
        return True
    except InventoryError as exc:
        if strict:
            raise
        print(f"warning: host dropdown not updated: {exc}", file=sys.stderr)
        return False


def read_settings() -> Tuple[SemaphoreAPI, int, int]:
    base_url = env("SEMAPHORE_URL", "semaphore_url")
    token = env("SEMAPHORE_API_TOKEN", "semaphore_api_token")
    project_id = env("SEMAPHORE_PROJECT_ID", "semaphore_project_id")
    inventory_id = env("SEMAPHORE_INVENTORY_ID", "semaphore_inventory_id")

    if not base_url:
        raise InventoryError("SEMAPHORE_URL is not set")
    if not token:
        raise InventoryError("SEMAPHORE_API_TOKEN is not set")
    if not project_id.isdigit():
        raise InventoryError("SEMAPHORE_PROJECT_ID is not set")
    if not inventory_id.isdigit():
        raise InventoryError("SEMAPHORE_INVENTORY_ID is not set")

    return SemaphoreAPI(base_url, token), int(project_id), int(inventory_id)


def add_host(args: argparse.Namespace) -> int:
    validate_args(args)
    api, project_id, inventory_id = read_settings()
    inventory_path = f"/api/project/{project_id}/inventory/{inventory_id}"

    for attempt in range(1, 4):
        inventory = api.get(inventory_path)
        original = inventory.get("inventory") or ""
        tree = load_tree(inventory)
        original_tree = yaml.safe_load(original) or {}
        updated_tree, notes = update_tree(tree, args)

        if updated_tree == original_tree:
            if not args.check and sync_fleet_dropdown(api, project_id, updated_tree):
                print("changed")
                for note in notes:
                    print(note)
                print(f"host {args.host} was already present; refreshed the host dropdown")
                return 0
            print("unchanged")
            for note in notes:
                print(note)
            print(f"host {args.host} is already present in {args.group}")
            return 0

        if args.check:
            print("would-change")
            for note in notes:
                print(note)
            print(f"would add host {args.host} ({args.address}) to {args.group}")
            return 0

        latest = api.get(inventory_path)
        if (latest.get("inventory") or "") != original:
            if attempt < 3:
                print("inventory changed while updating; retrying", file=sys.stderr)
                continue
            raise InventoryError("inventory changed while updating; rerun the task")

        inventory["inventory"] = dump_tree(updated_tree)
        api.put(inventory_path, inventory)

        sync_fleet_dropdown(api, project_id, updated_tree)
        print("changed")
        for note in notes:
            print(note)
        print(f"added host {args.host} ({args.address}) to {args.group}")
        return 0

    raise InventoryError("could not update the inventory after 3 attempts")


def sync_hosts(args: argparse.Namespace) -> int:
    api, project_id, inventory_id = read_settings()
    inventory = api.get(f"/api/project/{project_id}/inventory/{inventory_id}")
    tree = load_tree(inventory)
    changed = sync_fleet_dropdown(api, project_id, tree, check=args.check, strict=True)
    if args.check and changed:
        print("would-change")
        print("would update the fleet host dropdown")
    elif changed:
        print("changed")
        print("updated the fleet host dropdown")
    else:
        print("unchanged")
        print("fleet host dropdown is current")
    return 0


def find_environment(api: SemaphoreAPI, project_id: int, inventory_id: int) -> str:
    for item in api.get(f"/api/project/{project_id}/environment?sort=name&order=asc") or []:
        detail = api.get(f"/api/project/{project_id}/environment/{item['id']}")
        payload = detail.get("json")
        payload = json.loads(payload) if isinstance(payload, str) else (payload or {})
        if str(payload.get("semaphore_inventory_id") or "") == str(inventory_id):
            return str(item["id"])
    raise InventoryError(
        "could not identify the harden environment; "
        "set semaphore_environment_id in the environment JSON"
    )


def store_password(args: argparse.Namespace) -> int:
    api, project_id, inventory_id = read_settings()
    password = env("SEMAPHORE_USER_PW")
    if not password:
        raise InventoryError("SEMAPHORE_USER_PW is not set; nothing to store")
    env_id = (args.environment or "").strip()
    if env_id and not env_id.isdigit():
        raise InventoryError("--environment must be the numeric Semaphore environment id")
    if not env_id:
        env_id = find_environment(api, project_id, inventory_id)
    path = f"/api/project/{project_id}/environment/{env_id}"
    detail = api.get(path)
    secrets = [dict(secret) for secret in (detail.get("secrets") or [])]
    for secret in secrets:
        if secret.get("name") == USER_PW_SECRET:
            secret["secret"] = password
            secret["type"] = "var"
            secret["operation"] = "update"
            break
    else:
        secrets.append(
            {"name": USER_PW_SECRET, "type": "var", "secret": password, "operation": "create"}
        )
    if args.check:
        print("would-change")
        print(f"would store the hardening user password in environment {args.environment}")
        return 0
    body = {
        "id": detail["id"],
        "name": detail["name"],
        "project_id": detail["project_id"],
        "json": detail.get("json") or "{}",
        "secrets": secrets,
    }
    api.put(path, body)
    print("changed")
    print(f"stored the hardening user password in environment {args.environment}")
    return 0


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage the Semaphore hardening inventory.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    add = subparsers.add_parser("add-host", help="add or update one host in the Semaphore inventory")
    add.add_argument("--host", required=True, help="inventory host name")
    add.add_argument("--address", help="ansible_host address (default: the host name)")
    add.add_argument("--group", required=True, choices=DISTRIBUTIONS, help="distribution group")
    add.add_argument("--user", default="", help="ansible_user (default: the inventory credential user)")
    add.add_argument("--port", type=int, default=None, help="SSH port (omit or 22 for the default)")
    add.add_argument("--check", action="store_true", help="report the change without writing it")

    sync = subparsers.add_parser("sync", help="refresh the fleet host dropdown from the inventory")
    sync.add_argument("--check", action="store_true", help="report the change without writing it")

    store = subparsers.add_parser(
        "store-password", help="store the hardening user password as an environment secret"
    )
    store.add_argument(
        "--environment", default="", help="Semaphore environment id (default: auto-detect)"
    )
    store.add_argument("--check", action="store_true", help="report the change without writing it")

    args = parser.parse_args(argv)
    if args.command == "add-host":
        args.address = args.address or args.host
    return args


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    if not args.check and env("SEMAPHORE_INVENTORY_CHECK").lower() in ("1", "true", "yes"):
        args.check = True
    try:
        if args.command == "add-host":
            return add_host(args)
        if args.command == "sync":
            return sync_hosts(args)
        if args.command == "store-password":
            return store_password(args)
    except InventoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
