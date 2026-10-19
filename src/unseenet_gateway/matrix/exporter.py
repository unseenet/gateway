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
import html
import logging

from unseenet.core import crypto
from unseenet.core.article import Article
from unseenet.core.markup import is_markdown

from ..core.adapter import ExportError
from ..core.state import State
from .client import Matrix, MatrixError
from .convert import FROM_UNSEENET_KEY, NETWORK, thread_root

log = logging.getLogger(__name__)


def author_line(art: Article) -> str:
    fp = crypto.fingerprint(art.author_key)[:4]
    return f"{art.get('From', 'anonymous')} ({fp}) on Unseenet"


def markdown_html(text: str, kind: str = "post") -> str:
    """Unseenet Markdown as HTML for Matrix's formatted_body: raw HTML is never passed
    through (the parser has it off) and images are left out (Matrix shows mxc:// only)."""
    from unseenet.core.markup import _parser
    md = _parser(kind == "chat").disable("image")
    # the core parser filters links itself, after parsing; HTML needs its own guard
    md.validateLink = lambda url: url.strip().lower().startswith(("http://", "https://", "mailto:"))
    return md.render(text).strip()


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

    async def already_there(self, rid: str, message_id: str, pages: int = 3) -> str | None:
        """The event id if the room already has this article, sent by any gateway
        (UN-RFC 0038 section 5): another gateway's turn came first."""
        token = None
        for _ in range(pages):
            page = await self.matrix.messages(rid, start=token, limit=100, types=["m.room.message"])
            for ev in page.get("chunk", []):
                if (ev.get("content") or {}).get(FROM_UNSEENET_KEY) == message_id:
                    return ev.get("event_id")
            token = page.get("end")
            if not token or not page.get("chunk"):
                break
        return None

    async def send(self, art: Article) -> str:
        rid = await self.room_id_of(self.rooms[art.group])
        if await self.matrix.membership(rid) != "join":
            raise ExportError(f"not a member of {self.rooms[art.group]}")
        there = await self.already_there(rid, art.message_id)
        if there:
            log.info("%s is already in %s as %s", art.message_id, self.rooms[art.group], there)
            return there
        who = author_line(art)
        text = art.body.rstrip("\n")
        head = f"{who}:"
        subject = art.get("Subject", "").strip()
        if (subject and art.get("Message-Kind", "post") != "chat"
                and not art.get("References") and not subject.lower().startswith("re:")):
            head = f"{who}: {subject}"           # a new thread: its subject says what it is about
        content: dict = {
            "msgtype": "m.text",
            "body": f"{head}\n{text}",
            FROM_UNSEENET_KEY: art.message_id,
        }
        if is_markdown(art.get("Content-Type")):         # UN-RFC 0031: show it formatted
            content["format"] = "org.matrix.custom.html"
            content["formatted_body"] = (f"<p><b>{html.escape(head)}</b></p>"
                                         + markdown_html(text, art.get("Message-Kind", "post")))
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
