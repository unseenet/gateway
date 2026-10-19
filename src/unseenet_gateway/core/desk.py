"""The operator's desk: requests to gateway a source, decided from the operator's inbox.

A source on another network can ask to be gatewayed (on Matrix: by inviting the
gateway's account to a room it does not carry yet). The gateway then

1. sends the operator a private post (UN-RFC 0009) in their own inbox, signed by
   the gateway key, saying what the source is and what the group would be called;
2. reads the gateway's own inbox for answers. An answer counts only if its sender
   is verified as the configured operator key and it refers to the request;
3. records the decision: `approve` (optionally with a different name) or
   `decline <reason>`. Each source is asked about once.

With `auto_create`, an approved group's manifest is published by the gateway
itself, which needs the group key on the gateway host; without it, approval
only marks the source, and the operator runs `create-groups` as before.

Network-neutral: an adapter decides what counts as a request and how to answer
it on its own network; this module only talks to Unseenet and the operator.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass

from unseenet.core import crypto
from unseenet.core.article import Article, ArticleError
from unseenet.core.groups import inbox_article, open_inbox_article, personal_inbox_id
from unseenet.nntp import NNTPError, strip_reader_headers

from .state import State
from .unseenet_side import Node

log = logging.getLogger(__name__)
SCHEMA = """
CREATE TABLE IF NOT EXISTS desk (
    network  TEXT NOT NULL,
    source   TEXT NOT NULL,
    status   TEXT NOT NULL,          -- 'pending', 'approved', 'declined'
    name     TEXT,                   -- the Unseenet group name (proposed, then decided)
    request  TEXT,                   -- Message-ID of the request in the operator's inbox
    reason   TEXT,
    detail   TEXT,                   -- what the request said, for the log and the answer
    at       INTEGER NOT NULL,
    PRIMARY KEY (network, source)
);
"""
_NAME = re.compile(r"^[a-z0-9][a-z0-9+_-]*(\.[a-z0-9][a-z0-9+_-]*)*$")


@dataclass
class Request:
    network: str
    source: str
    status: str
    name: str | None
    request: str | None
    reason: str | None


def parse_answer(body: str) -> tuple[str, str] | None:
    """('approve', name or '') or ('decline', reason) from the first line that is not a
    quote; None if the answer says neither."""
    for line in body.replace("\r\n", "\n").split("\n"):
        line = line.strip()
        if not line or line.startswith(">"):
            continue
        word, _, rest = line.partition(" ")
        word = word.lower().rstrip(":.,!")
        if word in ("approve", "approved", "yes", "ja"):
            return "approve", rest.strip()
        if word in ("decline", "declined", "no", "nej"):
            return "decline", rest.strip()
        return None
    return None


class Desk:
    def __init__(self, *, state: State, node: Node, gateway: crypto.Identity, operator: str,
                 contact: str, pow_bits: int = 18):
        self.state, self.node, self.gateway = state, node, gateway
        self.operator_text = operator
        self.operator = crypto.key_from_text(operator) if operator.startswith("ed25519:") else None
        self.contact, self.pow_bits = contact, pow_bits
        self.inbox = personal_inbox_id(gateway.public_key)
        self.cursor_key = f"desk:{self.inbox}"
        self.state.db.executescript(SCHEMA)

    # --- what is known ---
    def get(self, network: str, source: str) -> Request | None:
        row = self.state.db.execute(
            "SELECT network, source, status, name, request, reason FROM desk "
            "WHERE network=? AND source=?", (network, source)).fetchone()
        return Request(*row) if row else None

    def approved(self, network: str) -> list[Request]:
        rows = self.state.db.execute(
            "SELECT network, source, status, name, request, reason FROM desk "
            "WHERE network=? AND status='approved'", (network,)).fetchall()
        return [Request(*r) for r in rows]

    def _set(self, network: str, source: str, **fields) -> None:
        cols = ", ".join(f"{k}=?" for k in fields)
        self.state.db.execute(f"UPDATE desk SET {cols} WHERE network=? AND source=?",
                              (*fields.values(), network, source))
        self.state.db.commit()

    # --- asking ---
    async def ask(self, network: str, source: str, *, title: str, detail: str,
                  name: str | None) -> bool:
        """Send the operator one request for ``source``; False if asked before."""
        if self.get(network, source) is not None:
            return False
        if self.operator is None or not self.contact.startswith("inbox@"):
            log.warning("request for %s %s not sent: gateway.operator and gateway.contact "
                        "must be a key and its personal inbox", network, source)
            return False
        proposed = name or "(none: give one, e.g. 'approve matrix.example.room')"
        body = (f"{detail}\n\n"
                f"Proposed Unseenet group: {proposed}\n\n"
                "Answer this post with one line:\n"
                "  approve              - gateway it under the proposed name\n"
                "  approve <name>       - gateway it under another name\n"
                "  decline <reason>     - do not gateway it; the reason is shown to them\n\n"
                "Only answers signed by the operator key in gateway.toml count.")
        art = inbox_article(self.contact, self.operator, from_name="Unseenet gateway",
                            subject=f"Gateway request: {title}", body=body,
                            sender=self.gateway, reply_inbox=self.inbox,
                            pow_bits=self.pow_bits)
        await self.node.post(art)
        self.state.db.execute("INSERT INTO desk VALUES (?,?,?,?,?,?,?,?)",
                              (network, source, "pending", name, art.message_id, None, detail,
                               int(time.time())))
        self.state.db.commit()
        log.info("asked the operator about %s %s (%s)", network, source, art.message_id)
        return True

    # --- answers ---
    async def poll(self) -> list[Request]:
        """Read the gateway's inbox for the operator's answers; return the decided requests."""
        c = await self.node._conn()
        try:
            _, low, high = await c.group(self.inbox)
        except NNTPError:
            return []
        after = self.state.get_cursor("unseenet", self.cursor_key) or (low - 1)
        pending = {r[0]: (r[1], r[2]) for r in self.state.db.execute(
            "SELECT request, network, source FROM desk WHERE status='pending'")}
        decided = []
        for n in range(max(after + 1, low), high + 1):
            raw = await c.article(str(n))
            self.state.set_cursor("unseenet", self.cursor_key, n)
            if raw is None or not pending:
                continue
            try:
                outer = Article.from_bytes(strip_reader_headers(raw))
                inner, sender = open_inbox_article(outer, self.gateway)
            except (ArticleError, ValueError):
                continue
            if sender is None or sender != self.operator:
                continue                           # only the operator decides
            refs = outer.get("References", "").split() + inner.get("References", "").split()
            hit = next((pending[m] for m in refs if m in pending), None)
            if hit is None:
                continue
            answer = parse_answer(inner.body)
            if answer is None:
                log.info("operator answered %s %s but said neither approve nor decline", *hit)
                continue
            network, source = hit
            verdict, arg = answer
            req = self.get(network, source)
            if verdict == "approve":
                name = arg.lower() if arg else req.name
                if not name or not _NAME.match(name) or len(name.encode()) > 128:
                    log.warning("approval of %s %s has no valid group name (%r)", network,
                                source, arg)
                    continue
                self._set(network, source, status="approved", name=name, reason=None)
            else:
                self._set(network, source, status="declined",
                          reason=arg or "Declined by the gateway's operator.")
            pending = {k: v for k, v in pending.items() if v != hit}
            decided.append(self.get(network, source))
            log.info("operator %sd %s %s", verdict, network, source)
        return decided
