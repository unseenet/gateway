"""Import into Unseenet, the same for every network (UN-RFC 0023 section 4).

A feed reads the other network and converts its messages; this loop does the
rest: skips what was imported before, signs with the gateway key, pays the
postage, posts to the node, remembers the mapping for threads, and cancels
imported messages the other network has since removed (section 4.5).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, fields
from datetime import datetime

from unseenet.core import crypto
from unseenet.core.article import Article, new_article
from unseenet.nntp import NNTPError

from .adapter import Feed, Skip, Source
from .state import State
from .unseenet_side import Node

log = logging.getLogger(__name__)


@dataclass
class RunStats:
    imported: int = 0
    duplicate: int = 0
    skipped: int = 0
    refused: int = 0
    cancelled: int = 0

    def add(self, other: "RunStats") -> None:
        for f in fields(self):
            setattr(self, f.name, getattr(self, f.name) + getattr(other, f.name, 0))


def cancel_article(group_id: str, target_mid: str, reason: str, *,
                   now: datetime | None = None) -> Article:
    """An Unseenet cancel (UN-RFC 0004 section 7) for an imported article."""
    return new_article(group_id, None, reason + "\n",
                       extra=[("Control", f"cancel {target_mid}")], now=now)


class Importer:
    def __init__(self, *, feed: Feed, state: State, node: Node, gateway: crypto.Identity,
                 pow_bits: int):
        self.feed, self.state, self.node = feed, state, node
        self.gateway, self.pow_bits = gateway, pow_bits

    @property
    def label(self) -> str:
        return self.feed.label or self.feed.network

    async def run(self) -> RunStats:
        total = RunStats()
        for source in self.feed.sources():
            total.add(await self.run_source(source))
        return total

    async def run_source(self, source: Source) -> RunStats:
        st, net = RunStats(), self.feed.network
        async for item in self.feed.fetch(source):
            if item.foreign_id and self.state.lookup(net, item.foreign_id):
                st.duplicate += 1                    # before paying postage
                continue
            try:
                art = self.feed.convert(source, item)
            except Skip as s:
                st.skipped += 1
                self.state.count_skip(net, s.reason)
                log.info("%s %s skipped: %s", source.foreign, item.label, s)
                continue
            art.finalize(self.gateway, self.pow_bits)
            try:
                result = await self.node.post(art)
            except NNTPError as exc:
                st.refused += 1
                self.state.count_skip(net, f"node-{exc.text.split(':')[0]}")
                log.warning("node refused %s: %s", item.foreign_id, exc)
                continue
            self.state.remember(net, item.foreign_id, art.message_id, art.group)
            self.feed.imported(item, art)
            if result == "duplicate":
                st.duplicate += 1
            else:
                st.imported += 1
                log.info("imported %s -> %s %s", item.foreign_id, art.message_id, art.group)
        for r in await self.feed.retractions(source):
            key = f"cancel:{r.foreign_id}"
            if self.state.lookup(net, key):
                continue
            art = cancel_article(source.group_id, r.unseenet_id, r.reason)
            art.finalize(self.gateway, self.pow_bits)
            await self.node.post(art)
            self.state.remember(net, key, art.message_id, source.group_id, "cancel")
            st.cancelled += 1
            log.info("cancelled %s (%s)", r.unseenet_id, r.reason)
        return st
