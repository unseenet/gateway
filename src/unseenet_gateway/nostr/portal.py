"""Portals to Nostr: an Unseenet group with a NIP-29 counterpart (UN-RFC 0023 3.5).

The Unseenet group is the source. Its owner opens a portal by listing it in
the group's manifest (`portals`); the gateway then

1. creates the NIP-29 group on a relay where its Nostr key may create groups,
2. exports articles posted in the Unseenet group *after* the portal was
   opened (the authors of older ones were never warned), after a random
   delay, as in UN-RFC 0026 section 5,
3. imports what Nostr users write in the counterpart into the Unseenet group,
   signed by the gateway key and carrying Origin-* headers (UN-RFC 0026
   section 4).

When the owner removes the portal from the manifest, the gateway stops both
ways at its next pass. Closed, inbox and local groups never get a portal,
and a moderated group only when the gateway key is one of its moderators.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field

from unseenet.core import crypto
from unseenet.core.article import Article, ArticleError
from unseenet.core.groups import Manifest
from unseenet.nntp import NNTPError, strip_reader_headers

from ..core.state import State
from ..core.unseenet_side import Node
from .convert import NETWORK
from .event import sign_event
from .exporter import ExportError, NostrSender
from .importer import METADATA, Importer, RunStats
from .relay import Relay

log = logging.getLogger(__name__)
CREATE_GROUP, EDIT_METADATA = 9007, 9002


@dataclass
class PortalStats:
    active: bool = False
    exported: int = 0
    waiting: int = 0
    imported: int = 0
    duplicate: int = 0
    skipped: int = 0
    refused: int = 0
    cancelled: int = 0


@dataclass
class _Pending:
    number: int
    due: float
    art: Article = field(repr=False)


def portal_entry(manifest: dict, network: str, source: str, gateway_key: str) -> dict | None:
    """The manifest's portal entry for this counterpart and gateway, if any."""
    for p in manifest.get("portals") or []:
        if not isinstance(p, dict):
            continue
        gws = p.get("gateway")
        gws = [gws] if isinstance(gws, str) else (gws or [])
        if p.get("network") == network and p.get("source") == source and gateway_key in gws:
            return p
    return None


def may_have_portal(m: Manifest, gateway_pk: bytes) -> str | None:
    """None if this group may have a portal run by this gateway, else why not."""
    if m.local:
        return "local group"
    if m.type == "open":
        return None
    if m.type == "moderated":
        return None if gateway_pk in m.moderators else "moderated, gateway is no moderator"
    return f"{m.type} group"


def exportable(art: Article, gateway_pk: bytes) -> str | None:
    """None if the article may go out through the portal, else why not (0023 5.4)."""
    if art.control:
        return "control"
    if "Encrypted" in art:
        return "encrypted"
    if art.author_key == gateway_pk or "Origin-Network" in art:
        return "came from another network"
    if not art.get("Content-Type", "text/plain").startswith("text/plain"):
        return "not plain text"
    if not art.body.strip():
        return "empty"
    return None


class NostrPortal:
    def __init__(self, *, state: State, node: Node, gateway: crypto.Identity,
                 relay: Relay, public_url: str, secret: bytes, group_id: str,
                 nostr_group: str, pow_bits: int, delay_max: float = 600,
                 profile_relays: list[str] | None = None, proxy: str | None = None):
        self.state, self.node, self.gateway = state, node, gateway
        self.relay, self.public_url = relay, public_url.rstrip("/")
        self.group_id, self.nostr_group = group_id, nostr_group
        self.source = f"{self.public_url}'{nostr_group}"
        self.delay_max = delay_max
        self.sender = NostrSender(relay=relay, secret=secret, state=state,
                                  groups={group_id: nostr_group}, public_url=self.public_url)
        self.importer = Importer(state=state, relay=relay, node=node, gateway=gateway,
                                 carried={nostr_group: group_id}, pow_bits=pow_bits,
                                 start="new", profile_relays=profile_relays, proxy=proxy)
        self.manifest: Manifest | None = None
        self.pending: dict[str, _Pending] = {}
        self._warned = ""
        self.cursor_key = f"portal:{group_id}"
        self.opened_key = f"portal-opened:{group_id}"

    # --- the Unseenet side ---
    async def _read_group(self) -> list[tuple[int, Article]]:
        """New articles in the Unseenet group; the first pass reads it all, for the manifest."""
        c = await self.node._conn()
        try:
            _, low, high = await c.group(self.group_id)
        except NNTPError as exc:
            log.warning("portal %s: node has no such group: %s", self.group_id, exc)
            return []
        after = self.state.get_cursor("unseenet", self.cursor_key)
        start = low if self.manifest is None or after is None else max(after + 1, low)
        out = []
        for n in range(start, high + 1):
            raw = await c.article(str(n))
            if raw is None:
                continue
            try:
                art = Article.from_bytes(strip_reader_headers(raw))
                art.verify_signature()
            except (ArticleError, ValueError) as exc:
                log.debug("portal %s: #%d unreadable: %s", self.group_id, n, exc)
                continue
            out.append((n, art))
        return out

    def _see_manifest(self, n: int, art: Article) -> None:
        try:
            m = Manifest.from_article(art)
        except ArticleError as exc:
            log.info("portal %s: bad manifest #%d: %s", self.group_id, n, exc)
            return
        if not m.supersedes(self.manifest):
            return
        was = self.active
        self.manifest = m
        now = self.active
        if now and not was and self.state.get_cursor("unseenet", self.opened_key) is None:
            self.state.set_cursor("unseenet", self.opened_key, n)
            log.info("portal %s opened by manifest #%d (serial %d)", self.group_id, n, m.serial)
        elif was and not now:
            self.state.db.execute("DELETE FROM cursor WHERE network=? AND source=?",
                                  ("unseenet", self.opened_key))
            self.state.db.commit()
            self.pending.clear()
            log.info("portal %s closed by manifest #%d", self.group_id, n)

    @property
    def active(self) -> bool:
        m = self.manifest
        if m is None or m.group_id != self.group_id:
            return False
        if portal_entry(m.raw, NETWORK, self.source, self.gateway.key_text) is None:
            return False
        why = may_have_portal(m, self.gateway.public_key)
        if why and self._warned != m.message_id:
            self._warned = m.message_id
            log.warning("portal %s listed but refused: %s", self.group_id, why)
        return why is None

    # --- the Nostr side ---
    async def ensure_counterpart(self) -> None:
        flag = f"portal-created:{self.source}"
        if self.state.get_cursor(NETWORK, flag):
            return
        meta = await self.relay.query({"kinds": [METADATA], "#d": [self.nostr_group]})
        if not meta:
            ev = sign_event(self.sender.secret, CREATE_GROUP, "", [["h", self.nostr_group]])
            ok, msg = await self.relay.publish(ev)
            if not ok and not msg.startswith("duplicate"):
                raise ExportError(f"cannot create {self.source}: {msg}")
        m = self.manifest
        title = (m.title or m.name) if m else self.group_id
        about = (f"Portal to the Unseenet group {m.name if m else self.group_id} "
                 f"({self.group_id}). Posts are copied both ways by an Unseenet gateway: "
                 "what you write here appears in Unseenet, and Unseenet posts appear here "
                 "with their author's name. https://unseenet.org")
        ev = sign_event(self.sender.secret, EDIT_METADATA, "",
                        [["h", self.nostr_group], ["name", f"{title} (Unseenet)"],
                         ["about", about]])
        ok, msg = await self.relay.publish(ev)
        if not ok:
            raise ExportError(f"cannot set metadata on {self.source}: {msg}")
        self.state.set_cursor(NETWORK, flag, 1)
        self.state.set_cursor(NETWORK, f"joined:{self.relay.url}'{self.nostr_group}", 1)
        log.info("portal counterpart %s ready", self.source)

    # --- one pass ---
    async def run(self) -> PortalStats:
        st = PortalStats()
        arts = await self._read_group()
        high = self.state.get_cursor("unseenet", self.cursor_key) or 0
        for n, art in arts:
            high = max(high, n)
            if art.control == ["manifest"]:
                self._see_manifest(n, art)
        if not self.active:
            self.state.set_cursor("unseenet", self.cursor_key, high)
            return st
        st.active = True
        await self.ensure_counterpart()
        opened = self.state.get_cursor("unseenet", self.opened_key) or 0
        now = time.time()
        for n, art in arts:
            if n <= opened or art.message_id in self.pending:
                continue
            if self.state.foreign_for(art.message_id):
                continue
            if exportable(art, self.gateway.public_key) is None:
                self.pending[art.message_id] = _Pending(
                    n, now + random.uniform(0, self.delay_max), art)
        for mid, p in sorted(self.pending.items(), key=lambda kv: kv[1].number):
            if p.due > now:
                continue
            try:
                eid = await self.sender.send(p.art)
            except ExportError as exc:
                st.refused += 1
                log.warning("portal %s: relay refused %s: %s", self.group_id, mid, exc)
                del self.pending[mid]
                continue
            self.state.remember(NETWORK, eid, mid, self.group_id, "out")
            del self.pending[mid]
            st.exported += 1
            log.info("portal exported %s -> %s", mid, eid[:16])
        st.waiting = len(self.pending)
        # never move the cursor past an article still waiting for its delay
        low_wait = min((p.number for p in self.pending.values()), default=None)
        self.state.set_cursor("unseenet", self.cursor_key,
                              high if low_wait is None else max(low_wait - 1, 0))
        rs: RunStats = await self.importer.run()
        for f in ("imported", "duplicate", "skipped", "refused", "cancelled"):
            setattr(st, f, getattr(st, f) + getattr(rs, f))
        return st
