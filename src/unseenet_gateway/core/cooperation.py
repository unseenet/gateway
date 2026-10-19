"""Several gateways for one gatewayed group (UN-RFC 0038).

Every gateway reads the groups it serves. From that it knows

- who the group's gateways are: the moderators in the newest manifest, and its
  own rank among them (their keys sorted by fingerprint);
- which foreign messages other gateways have imported (their origin pairs), so
  it never imports them again and can thread replies to them;
- which submissions another gateway has already approved.

The importer and the exporter then act by turns: rank k waits k x stagger
before doing what a lower rank has not done. No heartbeats, no election.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from unseenet.core import crypto
from unseenet.core.article import Article, ArticleError
from unseenet.core.groups import Manifest
from unseenet.nntp import NNTPError, strip_reader_headers

from .state import State
from .unseenet_side import Node

log = logging.getLogger(__name__)
DEFAULT_STAGGER = 300
MIN_STAGGER, MAX_STAGGER = 60, 3600


@dataclass
class GroupView:
    manifest: Manifest | None = None
    gateways: list[bytes] = field(default_factory=list)   # sorted by fingerprint
    peer_imports: int = 0


def stagger_of(m: Manifest | None) -> int:
    try:
        value = int(((m.raw if m else {}).get("gateway") or {}).get("stagger", DEFAULT_STAGGER))
    except (TypeError, ValueError):
        return DEFAULT_STAGGER
    return min(max(value, MIN_STAGGER), MAX_STAGGER)


class Watcher:
    """Reads the gatewayed groups this gateway serves (UN-RFC 0038 sections 4, 5)."""

    def __init__(self, *, state: State, node: Node, gateway: crypto.Identity,
                 groups: list[str], joined: list[str] = ()):
        self.state, self.node, self.gateway = state, node, gateway
        self.joined = set(joined)          # groups another gateway owns: wait for admission
        self.groups = list(dict.fromkeys(groups))
        self.views: dict[str, GroupView] = {g: GroupView() for g in self.groups}
        self.label = "watch"

    # --- what the importer and exporter ask ---
    def gateways(self, group_id: str) -> list[bytes]:
        return self.views.get(group_id, GroupView()).gateways

    def admitted(self, group_id: str) -> bool:
        """This gateway may write in the group (or its manifest has not been seen yet)."""
        view = self.views.get(group_id)
        if view is None or view.manifest is None:
            return group_id not in self.joined
        return self.gateway.public_key in view.gateways

    def rank(self, group_id: str) -> int:
        gws = self.gateways(group_id)
        return gws.index(self.gateway.public_key) if self.gateway.public_key in gws else 0

    def delay(self, group_id: str) -> float | None:
        """Seconds this gateway waits before acting in the group; None: it may not act."""
        if not self.admitted(group_id):
            return None
        return float(self.rank(group_id) * stagger_of(self.views[group_id].manifest)
                     if group_id in self.views else 0)

    def approved_elsewhere(self, message_id: str) -> bool:
        return self.state.get_cursor("unseenet", f"approved:{message_id}") is not None

    # --- reading ---
    async def run(self):
        total = 0
        for gid in self.groups:
            try:
                total += await self._read(gid)
            except NNTPError as exc:
                log.debug("watch %s: %s", gid, exc)
        return f"{total} articles from other gateways"

    async def _read(self, gid: str) -> int:
        c = await self.node._conn()
        _, low, high = await c.group(gid)
        key = f"watch:{gid}"
        after = self.state.get_cursor("unseenet", key)
        view = self.views.setdefault(gid, GroupView())
        start = low if (after is None or view.manifest is None) else max(after + 1, low)
        seen = 0
        for n in range(start, high + 1):
            raw = await c.article(str(n))
            if raw is None:
                continue
            try:
                art = Article.from_bytes(strip_reader_headers(raw))
                art.verify_signature()
            except (ArticleError, ValueError):
                continue
            if art.control == ["manifest"]:
                self._see_manifest(view, art)
                continue
            if art.control:
                continue
            seen += self._see_article(gid, view, art)
        self.state.set_cursor("unseenet", key, high)
        return seen

    def _see_manifest(self, view: GroupView, art: Article) -> None:
        try:
            m = Manifest.from_article(art, stored=True)
        except ArticleError:
            return
        if not m.supersedes(view.manifest):
            return
        view.manifest = m
        view.gateways = sorted(set(m.moderators), key=crypto.fingerprint)
        log.info("watch %s: %d gateway(s), this one has rank %s", m.group_id,
                 len(view.gateways), (view.gateways.index(self.gateway.public_key)
                                      if self.gateway.public_key in view.gateways else "-"))

    def _see_article(self, gid: str, view: GroupView, art: Article) -> int:
        try:
            author = art.author_key
        except (KeyError, crypto.CryptoError):
            return 0
        if author == self.gateway.public_key or author not in view.gateways:
            if "Approved-By" in art and art.get("Approved-By") != self.gateway.key_text:
                self.state.set_cursor("unseenet", f"approved:{art.message_id}", 1)
            return 0
        network, origin = art.get("Origin-Network"), art.get("Origin-ID")
        if network and origin and self.state.lookup(network, origin) is None:
            self.state.remember(network, origin, art.message_id, gid, "peer")
            view.peer_imports += 1
            return 1
        return 0
