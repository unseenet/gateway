"""Export, the Unseenet side (UN-RFC 0023 section 5), shared by all networks.

Submissions arrive in the gateway's inbox (UN-RFC 0009 section 3), sealed to
the gateway key. For each one the gateway checks it, hands it to the network
adapter after a random delay, and approves the original in Unseenet only
once the other network has accepted it.

The gateway learns nothing about authors beyond their key: submissions come
through Tor and a one-time key, and nothing here records how they arrived.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass

from unseenet.core import crypto
from unseenet.core.article import Article, ArticleError, validate_structure
from unseenet.core.groups import approve, make_manifest, open_inbox_article, personal_inbox_id
from unseenet.nntp import NNTPError, strip_reader_headers

from .state import State
from .unseenet_side import Node

log = logging.getLogger(__name__)
SUBMISSION_TYPE = "message/unseenet"


class Refused(Exception):
    """A submission the gateway will not export; the reason is for the log."""


@dataclass
class ExportStats:
    exported: int = 0
    refused: int = 0
    failed: int = 0


def inbox_manifest(gateway: crypto.Identity, pow_bits: int = 18) -> Article:
    """The gateway's personal inbox, where submissions arrive."""
    return make_manifest(gateway, "inbox", "inbox", retention_days=30, pow_bits=pow_bits)


class Exporter:
    """``targets`` maps each Unseenet Group ID with export to (network, send),
    where ``send(art)`` is the adapter's coroutine returning the foreign id."""

    def __init__(self, *, state: State, node: Node, gateway: crypto.Identity,
                 targets: dict, min_pow: int = 20, per_key_per_hour: int = 10,
                 delay_max: float = 600.0):
        self.state, self.node, self.gateway = state, node, gateway
        self.targets = targets
        self.min_pow, self.per_key_per_hour = min_pow, per_key_per_hour
        self.delay_max = delay_max
        self.inbox = personal_inbox_id(gateway.public_key)
        self.state.db.execute("CREATE TABLE IF NOT EXISTS exports ("
                              "author TEXT NOT NULL, at INTEGER NOT NULL)")

    async def _submissions(self) -> list[tuple[int, Article]]:
        c = await self.node._conn()
        try:
            _, low, high = await c.group(self.inbox)
        except NNTPError:
            return []
        after = self.state.get_cursor("unseenet", self.inbox) or (low - 1)
        out = []
        for n in range(max(after + 1, low), high + 1):
            raw = await c.article(str(n))
            if raw is None:
                continue
            try:
                outer = Article.from_bytes(strip_reader_headers(raw))
                inner, _sender = open_inbox_article(outer, self.gateway)
            except (ArticleError, ValueError):
                continue                # not for us, or not readable: nothing to do
            if not inner.get("Content-Type", "").startswith(SUBMISSION_TYPE):
                continue
            body = inner.body.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")
            try:
                sub = Article.from_bytes(body)
                validate_structure(sub, raw_size=len(body))
            except ArticleError as exc:
                log.info("submission #%d unusable: %s", n, exc)
                continue
            out.append((n, sub))
        return out

    def _check(self, art: Article) -> str:
        if art.group not in self.targets:
            raise Refused("not a group this gateway exports")
        net = self.targets[art.group][0]
        if self.state.foreign_for(art.message_id):
            raise Refused("already exported")
        if art.control:
            raise Refused("control article")
        if "Encrypted" in art:
            raise Refused("encrypted")
        if not art.get("Content-Type", "text/plain").startswith("text/plain"):
            raise Refused("not plain text")
        if art.proven_pow() < self.min_pow:
            raise Refused(f"postage below {self.min_pow} bits")
        hour_ago = int(time.time()) - 3600
        n = self.state.db.execute("SELECT COUNT(*) FROM exports WHERE author=? AND at>?",
                                  (art["Author-Key"], hour_ago)).fetchone()[0]
        if n >= self.per_key_per_hour:
            raise Refused("rate limit for this key")
        return net

    async def run(self) -> ExportStats:
        st = ExportStats()
        for n, art in await self._submissions():
            try:
                net = self._check(art)
            except Refused as r:
                st.refused += 1
                log.info("submission %s refused: %s", art.message_id, r)
                self.state.set_cursor("unseenet", self.inbox, n)
                continue
            await asyncio.sleep(random.uniform(0, self.delay_max))      # 0023 section 5.2
            try:
                foreign_id = await self.targets[art.group][1](art)
            except Exception as exc:  # noqa: BLE001  (refused by the other network)
                st.failed += 1
                log.warning("%s refused %s: %s", net, art.message_id, exc)
                self.state.set_cursor("unseenet", self.inbox, n)
                continue
            approve(art, self.gateway)                   # only after the other side accepted
            try:
                await self.node.post(art)
            except NNTPError as exc:
                log.warning("node refused approved %s: %s", art.message_id, exc)
            self.state.remember(net, foreign_id, art.message_id, art.group, "out")
            self.state.db.execute("INSERT INTO exports VALUES (?,?)",
                                  (art["Author-Key"], int(time.time())))
            self.state.set_cursor("unseenet", self.inbox, n)
            st.exported += 1
            log.info("exported %s to %s as %s", art.message_id, net, foreign_id)
        return st
