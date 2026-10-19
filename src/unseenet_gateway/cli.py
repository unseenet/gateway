"""unseenet-gateway: command line.

  unseenet-gateway -c gateway.toml keys          create the group key and the gateway key
  unseenet-gateway -c gateway.toml create-groups publish manifests (needs the group key)
  unseenet-gateway -c gateway.toml import-once   one pass: import, then export submissions
  unseenet-gateway -c gateway.toml run           a pass every `interval` seconds
  unseenet-gateway -c gateway.toml stats         what has been imported and skipped

Networks are configured as sections ([usenet], [nostr], [matrix], …); -n limits
a command to one. Network adapters may add commands of their own (nostr-key:
create the gateway's Nostr key, for export; matrix-login: save the token of
the gateway's Matrix account).

Passphrases come from UNSEENET_GATEWAY_PASSPHRASE (gateway key) and
UNSEENET_GATEWAY_GROUP_PASSPHRASE (group key), or are asked for.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import tomllib
from pathlib import Path

from unseenet.core.groups import personal_inbox_id

from . import __version__
from .core import keys
from .core.adapter import Adapter
from .core.desk import Desk
from .core.importer import Importer
from .core.portal import Portal
from .core.registry import adapters
from .core.state import State
from .core.submissions import Exporter, inbox_manifest
from .core.unseenet_side import Node, gateway_manifest

log = logging.getLogger("unseenet_gateway")
ONLY: str | None = None          # -n
GATEWAY_PASS = ("UNSEENET_GATEWAY_PASSPHRASE", "Passphrase for the GATEWAY key: ")
GROUP_PASS = ("UNSEENET_GATEWAY_GROUP_PASSPHRASE", "Passphrase for the GROUP key: ")


def load_config(path: str) -> dict:
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    base = Path(path).resolve().parent
    gw = cfg["gateway"]
    for k in ("state", "gateway_key", "group_key"):
        if k in gw:
            gw[k] = str((base / gw[k]).resolve())
    return cfg


def configured(cfg: dict, desk: Desk | None = None) -> list[Adapter]:
    """An adapter for each configured network ([usenet], [nostr], …), honouring -n."""
    out = []
    for name, cls in adapters().items():
        if name not in cfg or ONLY not in (None, name):
            continue
        try:
            ad = cls(cfg, desk)
        except TypeError:                 # an adapter from before the desk: cls(cfg)
            ad = cls(cfg)
            ad.desk = desk
        out.append(ad)
    return out


def make_desk(cfg: dict, state: State, node: Node, gateway) -> Desk | None:
    """The operator's desk (core/desk.py), when gateway.operator is a key and
    gateway.contact its inbox; `requests = false` turns it off."""
    gw = cfg["gateway"]
    if not gw.get("requests", True):
        return None
    if not str(gw.get("operator", "")).startswith("ed25519:") \
            or not str(gw.get("contact", "")).startswith("inbox@"):
        return None
    return Desk(state=state, node=node, gateway=gateway, operator=gw["operator"],
                contact=gw["contact"], pow_bits=int(gw.get("pow_bits", 18)))


async def publish_manifest(cfg: dict, ad: Adapter, c, owner, gateway, node: Node) -> str:
    """Publish one gatewayed group's manifest (and the submissions inbox if it exports)."""
    gw = cfg["gateway"]
    inbox = personal_inbox_id(gateway.public_key)
    if c.direction == "both":
        await node.post(inbox_manifest(gateway))
    art = gateway_manifest(
        owner, gateway, c.name, network=ad.network, source=c.source,
        direction=c.direction, host=ad.host(),
        submissions=inbox if c.direction == "both" else None,
        operator=gw["operator"], contact=gw["contact"], abuse=gw.get("abuse", ""),
        policy=gw.get("policy", ""), title=c.title, description=c.description,
        view=c.view, kinds=c.kinds,
        # clients pay what the manifest says; for export that is the gateway's own
        # minimum (0023 5.2), so say it here or every submission would be refused
        min_pow=int(gw.get("export_min_pow", 20)) if c.direction == "both" else 0,
        serial=int(ad.section.get("manifest_serial", 1)),
        retention_days=int(ad.section.get("retention_days", 90)),
        pow_bits=int(gw.get("pow_bits", 18)))
    return await node.post(art)


def cmd_keys(cfg: dict) -> None:
    gw = cfg["gateway"]
    g = keys.create(Path(gw["group_key"]), keys.passphrase(
        "UNSEENET_GATEWAY_GROUP_PASSPHRASE", "New passphrase for the GROUP key: "), "group")
    k = keys.create(Path(gw["gateway_key"]), keys.passphrase(
        "UNSEENET_GATEWAY_PASSPHRASE", "New passphrase for the GATEWAY key: "), "gateway")
    print(f"group key   {g.key_text}  ({gw['group_key']})")
    print(f"gateway key {k.key_text}  ({gw['gateway_key']})")
    print("\nPut the group key's public key in the config as gateway.group_owner,")
    print("and move the group key file off this host once the groups exist.")


async def cmd_create_groups(cfg: dict) -> None:
    gw = cfg["gateway"]
    owner = keys.load(Path(gw["group_key"]), keys.passphrase(*GROUP_PASS))
    gateway = keys.load(Path(gw["gateway_key"]), keys.passphrase(*GATEWAY_PASS))
    if owner.key_text != gw["group_owner"]:
        sys.exit("group_owner in the config does not match the group key")
    node = Node(cfg["unseenet"]["node"], cfg["unseenet"].get("socks_port"))
    state = State(Path(gw["state"]))
    ads = configured(cfg, make_desk(cfg, state, node, gateway))   # approved sources too
    if int(gw.get("pow_bits", 18)) < int(gw.get("export_min_pow", 20)) and any(
            c.direction == "both" for ad in ads for c in ad.carried()):
        sys.exit("pow_bits is below export_min_pow: the manifest would ask more postage "
                 "than the gateway pays for its own imports, and nodes would refuse them")
    for ad in ads:
        for c in ad.carried():
            print(f"{await publish_manifest(cfg, ad, c, owner, gateway, node):9} {c.group_id}")
    await node.close()


def make_portals(cfg: dict, gateway, state: State, node: Node, feeds: list) -> list[Portal]:
    """Portals ([[portals]]): Unseenet groups with a counterpart on another network.

    [[portals]]
    group = "test.portal@<fingerprint>"   # the Unseenet group ID
    network = "nostr"
    relay = "wss://nostr.unseenet.org"    # as in the manifest's portal source
    connect = "ws://10.0.0.5:2929"        # optional: how the gateway reaches it
    id = "test-portal"                    # the NIP-29 group id
    """
    gw, out, known = cfg["gateway"], [], adapters()
    pow_bits = int(gw.get("pow_bits", 18))
    by_net: dict[str, Adapter] = {}
    for p in cfg.get("portals", []):
        net = p.get("network", "nostr")
        if ONLY not in (None, net):
            continue
        cls = known.get(net)
        if cls is None or not cls.capabilities.portals:
            log.warning("portal %s: no adapter for %s with portals", p.get("group"), net)
            continue
        ad = by_net.setdefault(net, cls(cfg))
        out.append(Portal(
            state=state, node=node, gateway=gateway,
            counterpart=ad.counterpart(p, state=state, feeds=feeds),
            group_id=p["group"], pow_bits=pow_bits,
            delay_max=float(p.get("delay_max", gw.get("export_delay_max", 600)))))
    return out


def make_exporter(cfg: dict, ads: list[Adapter], gateway, state: State, node: Node,
                  feeds: list):
    """An Exporter for every gatewayed group with direction "both", or None."""
    gw, targets = cfg["gateway"], {}
    for ad in ads:
        if ad.capabilities.export:
            for gid, send in ad.export_targets(state=state, feeds=feeds).items():
                targets[gid] = (ad.network, send)
    if not targets:
        return None
    return Exporter(state=state, node=node, gateway=gateway, targets=targets,
                    min_pow=int(gw.get("export_min_pow", 20)),
                    per_key_per_hour=int(gw.get("export_per_hour", 10)),
                    delay_max=float(gw.get("export_delay_max", 600)))


async def _close(task) -> None:
    try:
        await (task.feed.close() if isinstance(task, Importer) else task.close())
    except Exception:  # noqa: BLE001
        pass


async def cmd_import(cfg: dict, loop: bool) -> None:
    gw = cfg["gateway"]
    gateway = keys.load(Path(gw["gateway_key"]), keys.passphrase(*GATEWAY_PASS))
    node = Node(cfg["unseenet"]["node"], cfg["unseenet"].get("socks_port"))
    state = State(Path(gw["state"]))
    pow_bits = int(gw.get("pow_bits", 18))
    desk = make_desk(cfg, state, node, gateway)
    owner = None
    if desk is not None and gw.get("auto_create"):
        # approved sources get their group at once: the group key must be on this host
        owner = keys.load(Path(gw["group_key"]), keys.passphrase(*GROUP_PASS))
        if owner.key_text != gw["group_owner"]:
            sys.exit("group_owner in the config does not match the group key")

    def build():
        ads = configured(cfg, desk)
        feeds = [f for ad in ads
                 for f in ad.feeds(state=state, node=node, gateway=gateway, pow_bits=pow_bits)]
        tasks: list = [Importer(feed=f, state=state, node=node, gateway=gateway,
                                pow_bits=pow_bits) for f in feeds]
        tasks += make_portals(cfg, gateway, state, node, feeds)
        return ads, feeds, tasks, make_exporter(cfg, ads, gateway, state, node, feeds)

    ads, feeds, tasks, exporter = build()
    while True:
        for task in tasks:
            try:
                st = await task.run()
                log.info("%s pass done: %s", task.label, st)
            except Exception as exc:  # noqa: BLE001  (one network failing must not stop the others)
                log.warning("%s pass failed: %s", task.label, exc)
                await _close(task)
                await node.close()
        if exporter is not None:
            try:
                log.info("export pass done: %s", await exporter.run())
            except Exception as exc:  # noqa: BLE001
                log.warning("export pass failed: %s", exc)
                await node.close()
        if desk is not None:
            try:
                if await desk_pass(cfg, desk, ads, feeds, owner, gateway, node):
                    for task in tasks:
                        await _close(task)
                    ads, feeds, tasks, exporter = build()     # carry what was approved
            except Exception as exc:  # noqa: BLE001
                log.warning("request pass failed: %s", exc)
                await node.close()
        if not loop:
            break
        await asyncio.sleep(int(gw.get("interval", 60)))
    for task in tasks:
        await _close(task)
    await node.close()


async def desk_pass(cfg: dict, desk: Desk, ads: list[Adapter], feeds: list, owner, gateway,
                    node: Node) -> bool:
    """New requests to the operator, and their answers. True if something new is to be
    carried now (approved, and its group published here)."""
    for ad in ads:
        await ad.handle_requests(desk, feeds)
    rebuild = False
    for req in await desk.poll():
        if req.status != "approved":
            continue                       # the adapter declines on the other side next pass
        ad = next((a for a in ads if a.network == req.network), None)
        c = next((c for c in ad.carried() if c.source == req.source), None) if ad else None
        if c is None:
            continue
        if owner is None:
            log.warning("%s %s approved: run create-groups to publish %s (or set "
                        "gateway.auto_create)", req.network, req.source, c.name)
            continue
        log.info("approved %s %s: %s %s", req.network, req.source, c.name,
                 await publish_manifest(cfg, ad, c, owner, gateway, node))
        rebuild = True
    return rebuild


def main() -> None:
    known = adapters()
    extra = {name: cls for cls in known.values() for name in cls.commands}
    p = argparse.ArgumentParser(prog="unseenet-gateway", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-c", "--config", default="gateway.toml")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-n", "--network", choices=list(known),
                   help="only this network (create-groups, import-once, run)")
    p.add_argument("--version", action="version", version=f"unseenet-gateway {__version__}")
    p.add_argument("command", choices=["keys", "create-groups", "import-once", "run",
                                       "stats", *extra])
    a = p.parse_args()
    logging.basicConfig(level=logging.INFO if a.verbose or a.command == "run" else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(a.config)
    global ONLY
    ONLY = a.network
    if a.command == "keys":
        cmd_keys(cfg)
    elif a.command in extra:
        extra[a.command](cfg).run_command(a.command)
    elif a.command == "create-groups":
        asyncio.run(cmd_create_groups(cfg))
    elif a.command in ("import-once", "run"):
        asyncio.run(cmd_import(cfg, a.command == "run"))
    elif a.command == "stats":
        print(json.dumps(State(Path(cfg["gateway"]["state"])).stats(), indent=2))


if __name__ == "__main__":
    main()
