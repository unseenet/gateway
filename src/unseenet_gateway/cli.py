"""unseenet-gateway: command line.

  unseenet-gateway -c gateway.toml keys          create the group key and the gateway key
  unseenet-gateway -c gateway.toml create-groups publish manifests (needs the group key)
  unseenet-gateway -c gateway.toml import-once   one import pass
  unseenet-gateway -c gateway.toml run           import every `interval` seconds
  unseenet-gateway -c gateway.toml stats         what has been imported and skipped

Passphrases come from UNSEENET_GATEWAY_PASSPHRASE (gateway key) and
UNSEENET_GATEWAY_GROUP_PASSPHRASE (group key), or are asked for.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import os
import sys
import tomllib
from pathlib import Path

from unseenet.core.groups import make_group_id
from unseenet.core import crypto

from . import __version__
from .core import keys
from .core.state import State
from .core.unseenet_side import Node, gateway_manifest
from .usenet.convert import unseenet_name
from .usenet.importer import Importer
from .usenet.source import NewsServer

log = logging.getLogger("unseenet_gateway")


def passphrase(env: str, prompt: str) -> str:
    return os.environ.get(env) or getpass.getpass(prompt)


def load_config(path: str) -> dict:
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    base = Path(path).resolve().parent
    gw = cfg["gateway"]
    for k in ("state", "gateway_key", "group_key"):
        if k in gw:
            gw[k] = str((base / gw[k]).resolve())
    return cfg


def carried_groups(cfg: dict) -> dict[str, str]:
    """Usenet group name -> Unseenet Group ID, from the group owner's public key."""
    owner = crypto.key_from_text(cfg["gateway"]["group_owner"])
    prefix = cfg["usenet"].get("prefix", "usenet")
    out = {}
    for g in cfg["usenet"]["groups"]:
        name = unseenet_name(g, prefix)
        if name is None:
            log.warning("%s cannot be gatewayed (name)", g)
            continue
        out[g] = make_group_id(name, owner)
    return out


def cmd_keys(cfg: dict) -> None:
    gw = cfg["gateway"]
    g = keys.create(Path(gw["group_key"]), passphrase(
        "UNSEENET_GATEWAY_GROUP_PASSPHRASE", "New passphrase for the GROUP key: "), "group")
    k = keys.create(Path(gw["gateway_key"]), passphrase(
        "UNSEENET_GATEWAY_PASSPHRASE", "New passphrase for the GATEWAY key: "), "gateway")
    print(f"group key   {g.key_text}  ({gw['group_key']})")
    print(f"gateway key {k.key_text}  ({gw['gateway_key']})")
    print("\nPut the group key's public key in the config as gateway.group_owner,")
    print("and move the group key file off this host once the groups exist.")


async def cmd_create_groups(cfg: dict) -> None:
    gw, us = cfg["gateway"], cfg["usenet"]
    owner = keys.load(Path(gw["group_key"]), passphrase(
        "UNSEENET_GATEWAY_GROUP_PASSPHRASE", "Passphrase for the GROUP key: "))
    gateway = keys.load(Path(gw["gateway_key"]), passphrase(
        "UNSEENET_GATEWAY_PASSPHRASE", "Passphrase for the GATEWAY key: "))
    if owner.key_text != gw["group_owner"]:
        sys.exit("group_owner in the config does not match the group key")
    node = Node(cfg["unseenet"]["node"], cfg["unseenet"].get("socks_port"))
    for usenet_group, group_id in carried_groups(cfg).items():
        name = group_id.rpartition("@")[0]
        art = gateway_manifest(
            owner, gateway, name, network="usenet", foreign_group=usenet_group,
            direction=us.get("direction", "import"), host=gw["host"],
            operator=gw["operator"], contact=gw["contact"], abuse=gw.get("abuse", ""),
            policy=gw.get("policy", ""), title=f"Usenet: {usenet_group}",
            description=f"Gatewayed from the Usenet group {usenet_group} by {gw['host']}. "
                        "Posts are signed by the gateway, not by their authors.",
            serial=int(us.get("manifest_serial", 1)),
            retention_days=int(us.get("retention_days", 90)),
            pow_bits=int(gw.get("pow_bits", 18)))
        result = await node.post(art)
        print(f"{result:9} {group_id}")
    await node.close()


async def cmd_import(cfg: dict, loop: bool) -> None:
    gw, us = cfg["gateway"], cfg["usenet"]
    gateway = keys.load(Path(gw["gateway_key"]), passphrase(
        "UNSEENET_GATEWAY_PASSPHRASE", "Passphrase for the GATEWAY key: "))
    imp = Importer(
        state=State(Path(gw["state"])), news=NewsServer(us.get("server", "127.0.0.1:119")),
        node=Node(cfg["unseenet"]["node"], cfg["unseenet"].get("socks_port")),
        gateway=gateway, carried=carried_groups(cfg), pow_bits=int(gw.get("pow_bits", 18)),
        start=us.get("start", "new"), max_per_run=int(us.get("max_per_run", 200)))
    while True:
        try:
            st = await imp.run()
            log.info("pass done: %s", st)
        except (ConnectionError, OSError) as exc:
            log.warning("pass failed: %s", exc)
            await imp.news.close()
            await imp.node.close()
        if not loop:
            break
        await asyncio.sleep(int(gw.get("interval", 60)))
    await imp.news.close()
    await imp.node.close()


def main() -> None:
    p = argparse.ArgumentParser(prog="unseenet-gateway", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-c", "--config", default="gateway.toml")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"unseenet-gateway {__version__}")
    p.add_argument("command", choices=["keys", "create-groups", "import-once", "run", "stats"])
    a = p.parse_args()
    logging.basicConfig(level=logging.INFO if a.verbose or a.command == "run" else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(a.config)
    if a.command == "keys":
        cmd_keys(cfg)
    elif a.command == "create-groups":
        asyncio.run(cmd_create_groups(cfg))
    elif a.command in ("import-once", "run"):
        asyncio.run(cmd_import(cfg, a.command == "run"))
    elif a.command == "stats":
        print(json.dumps(State(Path(cfg["gateway"]["state"])).stats(), indent=2))


if __name__ == "__main__":
    main()
