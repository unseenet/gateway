"""Import from Usenet into Unseenet (UN-RFC 0023, section 4)."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from unseenet.core import crypto
from unseenet.nntp import NNTPError

from ..core.state import State
from ..core.unseenet_side import Node
from .convert import Skip, clean, convert, parse
from .source import NewsServer

log = logging.getLogger(__name__)
NETWORK = "usenet"


@dataclass
class RunStats:
    imported: int = 0
    duplicate: int = 0
    skipped: int = 0
    refused: int = 0


class Importer:
    def __init__(self, *, state: State, news: NewsServer, node: Node,
                 gateway: crypto.Identity, carried: dict[str, str], pow_bits: int,
                 start: str = "new", max_per_run: int = 200):
        self.state, self.news, self.node = state, news, node
        self.gateway, self.carried, self.pow_bits = gateway, carried, pow_bits
        self.start, self.max_per_run = start, max_per_run

    async def _first_cursor(self, group: str) -> int:
        low, high = await self.news.range(group)
        if self.start == "all":
            return low - 1
        if self.start.startswith("last:"):
            return max(low - 1, high - int(self.start[5:]))
        return high                                     # "new"

    async def run_group(self, group: str) -> RunStats:
        st = RunStats()
        cursor = self.state.get_cursor(NETWORK, group)
        if cursor is None:
            cursor = await self._first_cursor(group)
            self.state.set_cursor(NETWORK, group, cursor)
        done = 0
        async for n, raw in self.news.articles(group, cursor):
            if done >= self.max_per_run:
                break
            done += 1
            try:
                if raw is None:
                    raise Skip("size", "unreadable or too large")
                if self._is_new(raw, st):
                    await self._post(raw, st)
            except Skip as s:
                st.skipped += 1
                self.state.count_skip(NETWORK, s.reason)
                log.info("%s #%d skipped: %s", group, n, s)
            self.state.set_cursor(NETWORK, group, n)
        return st

    def _is_new(self, raw: bytes, st: RunStats) -> bool:
        """Quick duplicate check before paying postage."""
        mid = clean(parse(raw).get("Message-ID", ""))
        if mid and self.state.lookup(NETWORK, mid):
            st.duplicate += 1
            return False
        return True

    async def _post(self, raw: bytes, st: RunStats) -> None:
        conv = convert(raw, carried=self.carried,
                       id_map=lambda m: self.state.lookup(NETWORK, m))
        art = conv.article.finalize(self.gateway, self.pow_bits)
        try:
            result = await self.node.post(art)
        except NNTPError as exc:
            st.refused += 1
            self.state.count_skip(NETWORK, f"node-{exc.text.split(':')[0]}")
            log.warning("node refused %s: %s", conv.usenet_id, exc)
            return
        self.state.remember(NETWORK, conv.usenet_id, art.message_id, art.group)
        if result == "duplicate":
            st.duplicate += 1
        else:
            st.imported += 1
            log.info("imported %s -> %s %s", conv.usenet_id, art.message_id, art.group)

    async def run(self) -> RunStats:
        total = RunStats()
        for group in self.carried:
            st = await self.run_group(group)
            for f in ("imported", "duplicate", "skipped", "refused"):
                setattr(total, f, getattr(total, f) + getattr(st, f))
        return total
