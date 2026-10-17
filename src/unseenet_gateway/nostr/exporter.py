"""Export to NIP-29 Nostr groups: Unseenet article -> Nostr event.

The gateway has one Nostr key and joins each group it exports to with a
join request (kind 9021). The group's relay and admins decide whether it may
write: that is the other side's consent (UN-RFC 0023 section 6.1).

Every exported event names its Unseenet author in the text and carries the
`unseenet` tag with the Unseenet Message-ID, so importing gateways never
bring it back (loop prevention) and readers can find the original.
"""

from __future__ import annotations

import logging

from unseenet.core import crypto
from unseenet.core.article import Article

from ..core.state import State
from .convert import CHAT, COMMENT, FROM_UNSEENET_TAG, NETWORK, THREAD
from .event import pubkey_of, sign_event
from .relay import Relay

log = logging.getLogger(__name__)
JOIN = 9021


class ExportError(Exception):
    pass


def signature_line(art: Article) -> str:
    fp = crypto.fingerprint(art.author_key)[:4]
    return f"\n\n— {art.get('From', 'anonymous')} ({fp}), on Unseenet"


class NostrSender:
    def __init__(self, *, relay: Relay, secret: bytes, state: State,
                 groups: dict[str, str], public_url: str | None = None):
        self.relay, self.secret, self.state = relay, secret, state
        # the relay's address as Nostr clients know it, for tags (the gateway
        # itself may reach the relay by another address, e.g. on the LAN)
        self.url = (public_url or relay.url).rstrip("/")
        self.groups = groups            # Unseenet Group ID -> NIP-29 group id on this relay
        self.pubkey = pubkey_of(secret).hex()

    async def ensure_member(self, group: str) -> None:
        flag = f"joined:{self.relay.url}'{group}"
        if self.state.get_cursor(NETWORK, flag):
            return
        ev = sign_event(self.secret, JOIN, "Unseenet gateway (UN-RFC 0023)", [["h", group]])
        ok, msg = await self.relay.publish(ev)
        if not ok and not msg.startswith("duplicate"):
            raise ExportError(f"join refused by {self.relay.url}: {msg}")
        self.state.set_cursor(NETWORK, flag, 1)
        log.info("joined %s'%s as %s", self.relay.url, group, self.pubkey[:12])

    async def _parent(self, art: Article):
        """The Nostr event this article answers, if it answers one we know."""
        for mid in reversed(art.get("References", "").split()):
            hit = self.state.foreign_for(mid)
            if hit and hit[0] == NETWORK:
                found = await self.relay.query({"ids": [hit[1]]})
                if found:
                    return found[0]
        return None

    async def send(self, art: Article) -> str:
        group = self.groups[art.group]
        await self.ensure_member(group)
        parent = await self._parent(art)
        content = art.body.rstrip("\n") + signature_line(art)
        tags = [["h", group], [FROM_UNSEENET_TAG, art.message_id]]
        if parent is None:
            kind = THREAD
            tags.append(["title", art.get("Subject", "")[:200]])
        elif parent.kind == CHAT:
            kind = CHAT
            tags.append(["q", parent.id, self.url, parent.pubkey])
        else:
            kind = COMMENT
            if parent.kind == COMMENT:
                root_id, root_kind, root_pk = parent.tag("E"), parent.tag("K"), parent.tag("P")
            else:
                root_id, root_kind, root_pk = parent.id, str(parent.kind), parent.pubkey
            tags += [["E", root_id, self.url, root_pk or ""], ["K", root_kind or "11"],
                     ["P", root_pk or parent.pubkey],
                     ["e", parent.id, self.url, parent.pubkey], ["k", str(parent.kind)],
                     ["p", parent.pubkey]]
        ev = sign_event(self.secret, kind, content, tags)
        ok, msg = await self.relay.publish(ev)
        if not ok:
            raise ExportError(msg)
        return ev.id
