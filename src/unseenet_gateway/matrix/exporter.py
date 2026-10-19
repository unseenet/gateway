"""Export to Matrix rooms: Unseenet article -> `m.room.message` (UN-RFC 0037 section 5).

The gateway writes with its own bot account, in rooms it was invited to.
Every exported event names its Unseenet author in the text (key fingerprint
included, so two authors with the same name can be told apart) and carries
the Unseenet Message-ID in `org.unseenet.message_id`, so no gateway ever
imports it back and readers can find the original.

The transaction id is derived from the Message-ID, so a retry after a lost
answer never sends the same article twice.

Virtual users per Unseenet key (`@unseenet_<fingerprint>:<server>`) need an
Application Service on the gateway's own homeserver; that is a later step.
"""

from __future__ import annotations

import hashlib
import logging

from unseenet.core import crypto
from unseenet.core.article import Article

from ..core.adapter import ExportError
from ..core.state import State
from .client import Matrix, MatrixError
from .convert import FROM_UNSEENET_KEY, NETWORK, thread_root

log = logging.getLogger(__name__)


def author_line(art: Article) -> str:
    fp = crypto.fingerprint(art.author_key)[:4]
    return f"{art.get('From', 'anonymous')} ({fp}) on Unseenet"


def txn_id(message_id: str) -> str:
    return "unseenet-" + hashlib.sha256(message_id.encode()).hexdigest()[:32]


class MatrixSender:
    def __init__(self, *, matrix: Matrix, state: State, rooms: dict[str, str],
                 room_id_of):
        self.matrix, self.state = matrix, state
        self.rooms = rooms               # Unseenet Group ID -> room alias or id
        self.room_id_of = room_id_of     # async: alias -> room id (the feed's cache)

    async def _parent(self, rid: str, art: Article) -> dict | None:
        """The Matrix event this article answers, if it answers one we know."""
        for mid in reversed(art.get("References", "").split()):
            hit = self.state.foreign_for(mid)
            if hit and hit[0] == NETWORK:
                ev = await self.matrix.event(rid, hit[1])
                if ev:
                    return ev
        return None

    async def send(self, art: Article) -> str:
        rid = await self.room_id_of(self.rooms[art.group])
        if await self.matrix.membership(rid) != "join":
            raise ExportError(f"not a member of {self.rooms[art.group]}")
        who = author_line(art)
        text = art.body.rstrip("\n")
        content: dict = {
            "msgtype": "m.text",
            "body": f"{who}:\n{text}",
            FROM_UNSEENET_KEY: art.message_id,
        }
        parent = await self._parent(rid, art)
        if parent is not None:
            root = thread_root(parent.get("content") or {})
            if root:                                   # answer inside the thread
                content["m.relates_to"] = {"rel_type": "m.thread", "event_id": root,
                                           "is_falling_back": False,
                                           "m.in_reply_to": {"event_id": parent["event_id"]}}
            else:
                content["m.relates_to"] = {"m.in_reply_to": {"event_id": parent["event_id"]}}
        try:
            return await self.matrix.send(rid, content, txn_id(art.message_id))
        except MatrixError as exc:
            raise ExportError(str(exc)) from None
