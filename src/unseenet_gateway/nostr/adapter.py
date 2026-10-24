"""The Nostr adapter: NIP-29 groups (UN-RFC 0026).

Configuration, section [nostr], with one relay::

    relay     = "wss://groups.example.org"
    prefix    = "nostr"           # `test.nostr` on test nodes
    host      = "gateway.example.org"
    direction = "import"          # or "both"
    start     = "new"             # or "all"
    groups    = ["group-id", {id = "other", name = "chosen.name"}]

or several, one [[nostr.relays]] table each (url, groups, and optionally
direction and start). Optional: `proxy`, `profile_relays`, and the gateway's
Nostr key at `gateway.nostr_key` (default: `nostr.key` beside the gateway key).
"""

from __future__ import annotations

import logging
from pathlib import Path

from unseenet.core import crypto

from ..core import keys
from ..core.adapter import Adapter, Capabilities, Carried, Feed, Send
from .convert import NETWORK, npub, unseenet_name
from .event import N as SECP_N, pubkey_of
from .exporter import NostrSender
from .feed import NostrFeed, source_name
from .portal import NostrCounterpart
from .relay import Relay

log = logging.getLogger(__name__)
PASSPHRASE = ("UNSEENET_GATEWAY_PASSPHRASE", "Passphrase for the GATEWAY key: ")


class NostrAdapter(Adapter):
    network = NETWORK
    capabilities = Capabilities(export=True, retractions=True, portals=True)
    commands = {"nostr-key": "create the gateway's Nostr key (for export)"}

    def __init__(self, cfg: dict, desk=None):
        super().__init__(cfg, desk)
        self._secret: bytes | None = None

    # --- configuration ---
    def relays(self) -> list[dict]:
        """[nostr] relay/groups, or one [[nostr.relays]] table per relay."""
        sec = self.section
        if "relays" in sec:
            return sec["relays"]
        return [{"url": sec["relay"], "groups": sec.get("groups", [])}]

    def direction(self, relay: dict) -> str:
        return relay.get("direction", self.section.get("direction", "import"))

    def key_path(self) -> Path:
        return Path(self.gw.get("nostr_key", str(Path(self.gw["gateway_key"]).with_name(
            "nostr.key"))))

    def secret(self) -> bytes:
        if self._secret is None:
            self._secret = keys.load_secret(self.key_path(), keys.passphrase(*PASSPHRASE))
        return self._secret

    def host(self) -> str:
        """The gateway's npub once it has a Nostr key (UN-RFC 0026 section 2)."""
        if self.key_path().exists():
            return npub(pubkey_of(self.secret()).hex())
        return super().host()

    def _relay_groups(self, relay: dict, host: str | None = None) -> list[tuple[str, Carried]]:
        """(NIP-29 group id, Carried) for the groups on one relay."""
        out = []
        for g in relay.get("groups", []):
            foreign, wanted = (g["id"], g.get("name")) if isinstance(g, dict) else (g, None)
            name = f"{self.prefix}.{wanted}" if wanted else unseenet_name(foreign, self.prefix)
            if name is None:
                log.warning("%s cannot be gatewayed (name)", foreign)
                continue
            out.append((foreign, Carried(
                source=source_name(relay["url"], foreign), name=name,
                group_id=self.group_id(name), direction=self.direction(relay),
                title=f"Nostr: {foreign}",
                view="chat",          # NIP-29 groups are chat rooms in Nostr clients (gateway#26)
                description=(f"Gatewayed from the NIP-29 group {foreign} on {relay['url']} "
                             f"by {host}. Posts are signed by the gateway; the original "
                             "signed Nostr event is kept in Origin-Proof."))))
        return out

    # --- the adapter ---
    def carried(self) -> list[Carried]:
        host = self.host()
        return [c for relay in self.relays() for _, c in self._relay_groups(relay, host)]

    def feeds(self, *, state, node, gateway: crypto.Identity, pow_bits: int) -> list[Feed]:
        sec = self.section
        return [NostrFeed(
            state=state, relay=Relay(relay["url"], proxy=sec.get("proxy")),
            carried={f: c.group_id for f, c in self._relay_groups(relay)},
            start=relay.get("start", sec.get("start", "new")),
            profile_relays=sec.get("profile_relays"), proxy=sec.get("proxy"))
            for relay in self.relays()]

    def export_targets(self, *, state, feeds: list[Feed]) -> dict[str, Send]:
        relays = [r for r in self.relays() if self.direction(r) == "both"]
        targets: dict[str, Send] = {}
        for relay in relays:
            groups = {c.group_id: f for f, c in self._relay_groups(relay)}
            # share the feed's connection to the same relay
            conn = next((f.relay for f in feeds if getattr(f, "relay", None)
                         and f.relay.url == relay["url"]),
                        Relay(relay["url"], proxy=self.section.get("proxy")))
            sender = NostrSender(relay=conn, secret=self.secret(), state=state, groups=groups)
            for gid in groups:
                targets[gid] = sender.send
        return targets

    def counterpart(self, entry: dict, *, state, feeds: list[Feed]) -> NostrCounterpart:
        """[[portals]] entry: group, relay, optional connect (how the gateway reaches it), id."""
        sec = self.section
        return NostrCounterpart(
            state=state, relay=Relay(entry.get("connect", entry["relay"]), proxy=sec.get("proxy")),
            public_url=entry["relay"], secret=self.secret(), group_id=entry["group"],
            nostr_group=entry.get("id") or entry["group"].rpartition("@")[0].replace(".", "-"),
            profile_relays=sec.get("profile_relays"), proxy=sec.get("proxy"))

    def run_command(self, name: str) -> None:
        if name != "nostr-key":
            raise NotImplementedError(name)
        path = self.key_path()
        secret = keys.create_secret(path, keys.passphrase(*PASSPHRASE), "nostr",
                                    valid=lambda b: 0 < int.from_bytes(b, "big") < SECP_N)
        pk = pubkey_of(secret).hex()
        print(f"nostr key {npub(pk)}\n          {pk}  ({path})")
