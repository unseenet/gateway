"""unseenet-gateway: command line.

  unseenet-gateway -c gateway.toml keys          create the group key and the gateway key
  unseenet-gateway -c gateway.toml create-groups publish manifests (needs the group key)
  unseenet-gateway -c gateway.toml import-once   one import pass
  unseenet-gateway -c gateway.toml run           import every `interval` seconds
  unseenet-gateway -c gateway.toml stats         what has been imported and skipped

Networks are configured as sections ([usenet], [nostr]); -n limits a command to one.

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
from .nostr.convert import unseenet_name as nostr_name
from .nostr.importer import Importer as NostrImporter, source_name
from .nostr.relay import Relay
from .usenet.convert import unseenet_name as usenet_name
from .usenet.importer import Importer as UsenetImporter
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


def carried_groups(cfg: dict, network: str) -> dict[str, str]:
    """Source (group, room, …) -> Unseenet Group ID, from the group owner's public key."""
    owner = crypto.key_from_text(cfg["gateway"]["group_owner"])
    sec = cfg[network]
    to_name = usenet_name if network == "usenet" else nostr_name
    out = {}
    for g in sec["groups"]:
        name = to_name(g, sec.get("prefix", network))
        if name is None:
            log.warning("%s cannot be gatewayed (name)", g)
            continue
        out[g] = make_group_id(name, owner)
    return out


ONLY: str | None = None   # --network


def networks(cfg: dict) -> list[str]:
    return [n for n in ("usenet", "nostr") if n in cfg and ONLY in (None, n)]


def describe(network: str, source: str, sec: dict, host: str) -> tuple[str, str, str]:
    """(manifest source, title, description) for a gatewayed group."""
    if network == "nostr":
        full = source_name(sec["relay"], source)
        return (full, f"Nostr: {source}",
                f"Gatewayed from the NIP-29 group {source} on {sec['relay']} by {host}. "
                "Posts are signed by the gateway; the original signed Nostr event is kept "
                "in Origin-Proof.")
    return (source, f"Usenet: {source}",
            f"Gatewayed from the Usenet group {source} by {host}. "
            "Posts are signed by the gateway, not by their authors.")


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
    gw = cfg["gateway"]
    owner = keys.load(Path(gw["group_key"]), passphrase(
        "UNSEENET_GATEWAY_GROUP_PASSPHRASE", "Passphrase for the GROUP key: "))
    gateway = keys.load(Path(gw["gateway_key"]), passphrase(
        "UNSEENET_GATEWAY_PASSPHRASE", "Passphrase for the GATEWAY key: "))
    if owner.key_text != gw["group_owner"]:
        sys.exit("group_owner in the config does not match the group key")
    node = Node(cfg["unseenet"]["node"], cfg["unseenet"].get("socks_port"))
    for net in networks(cfg):
        sec = cfg[net]
        host = sec.get("host", gw.get("host", ""))
        for source, group_id in carried_groups(cfg, net).items():
            name = group_id.rpartition("@")[0]
            src, title, desc = describe(net, source, sec, host)
            art = gateway_manifest(
                owner, gateway, name, network=net, source=src,
                direction=sec.get("direction", "import"), host=host,
                operator=gw["operator"], contact=gw["contact"], abuse=gw.get("abuse", ""),
                policy=gw.get("policy", ""), title=title, description=desc,
                serial=int(sec.get("manifest_serial", 1)),
                retention_days=int(sec.get("retention_days", 90)),
                pow_bits=int(gw.get("pow_bits", 18)))
            result = await node.post(art)
            print(f"{result:9} {group_id}")
    await node.close()


def make_importers(cfg: dict, gateway, state: State, node: Node) -> list:
    gw, out = cfg["gateway"], []
    pow_bits = int(gw.get("pow_bits", 18))
    nets = networks(cfg)
    if "usenet" in nets:
        us = cfg["usenet"]
        out.append(UsenetImporter(
            state=state, news=NewsServer(us.get("server", "127.0.0.1:119")), node=node,
            gateway=gateway, carried=carried_groups(cfg, "usenet"), pow_bits=pow_bits,
            start=us.get("start", "new"), max_per_run=int(us.get("max_per_run", 200))))
    if "nostr" in nets:
        ns = cfg["nostr"]
        out.append(NostrImporter(
            state=state, relay=Relay(ns["relay"], proxy=ns.get("proxy")), node=node,
            gateway=gateway, carried=carried_groups(cfg, "nostr"), pow_bits=pow_bits,
            start=ns.get("start", "new")))
    return out


async def _close(imp) -> None:
    for attr in ("news", "relay"):
        if hasattr(imp, attr):
            await getattr(imp, attr).close()


async def cmd_import(cfg: dict, loop: bool) -> None:
    gw = cfg["gateway"]
    gateway = keys.load(Path(gw["gateway_key"]), passphrase(
        "UNSEENET_GATEWAY_PASSPHRASE", "Passphrase for the GATEWAY key: "))
    node = Node(cfg["unseenet"]["node"], cfg["unseenet"].get("socks_port"))
    importers = make_importers(cfg, gateway, State(Path(gw["state"])), node)
    while True:
        for imp in importers:
            name = type(imp).__module__.split(".")[-2]
            try:
                st = await imp.run()
                log.info("%s pass done: %s", name, st)
            except Exception as exc:  # noqa: BLE001  (one network failing must not stop the others)
                log.warning("%s pass failed: %s", name, exc)
                await _close(imp)
                await node.close()
        if not loop:
            break
        await asyncio.sleep(int(gw.get("interval", 60)))
    for imp in importers:
        await _close(imp)
    await node.close()


def main() -> None:
    p = argparse.ArgumentParser(prog="unseenet-gateway", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-c", "--config", default="gateway.toml")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-n", "--network", choices=["usenet", "nostr"],
                   help="only this network (create-groups, import-once, run)")
    p.add_argument("--version", action="version", version=f"unseenet-gateway {__version__}")
    p.add_argument("command", choices=["keys", "create-groups", "import-once", "run", "stats"])
    a = p.parse_args()
    logging.basicConfig(level=logging.INFO if a.verbose or a.command == "run" else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(a.config)
    global ONLY
    ONLY = a.network
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
