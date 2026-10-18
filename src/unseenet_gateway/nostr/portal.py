"""Portals to Nostr: the NIP-29 counterpart of an Unseenet group (UN-RFC 0026 section 7).

What is the same for every network (the manifest, the delay, what may be
exported) is in ``core/portal.py``. This is only the Nostr side: create the
NIP-29 group on a relay where the gateway's Nostr key may create groups,
keep its metadata current, send and read.
"""

from __future__ import annotations

import logging

from unseenet.core.article import Article

from ..core.adapter import Counterpart, ExportError
from ..core.portal import (Portal, PortalStats, exportable, may_have_portal,  # noqa: F401
                           portal_entry)
from ..core.state import State
from .convert import NETWORK
from .event import sign_event
from .exporter import NostrSender
from .feed import METADATA, NostrFeed
from .relay import Relay

log = logging.getLogger(__name__)
CREATE_GROUP, EDIT_METADATA = 9007, 9002


class NostrCounterpart(Counterpart):
    network = NETWORK

    def __init__(self, *, state: State, relay: Relay, public_url: str, secret: bytes,
                 group_id: str, nostr_group: str, profile_relays: list[str] | None = None,
                 proxy: str | None = None):
        self.state, self.relay = state, relay
        self.public_url = public_url.rstrip("/")
        self.group_id, self.nostr_group = group_id, nostr_group
        self.source = f"{self.public_url}'{nostr_group}"
        self.sender = NostrSender(relay=relay, secret=secret, state=state,
                                  groups={group_id: nostr_group}, public_url=self.public_url)
        self.feed = NostrFeed(state=state, relay=relay, carried={nostr_group: group_id},
                              start="new", profile_relays=profile_relays, proxy=proxy,
                              label=f"portal {group_id}")
        self._meta_for = ""

    async def ensure(self, manifest) -> None:
        """Create the NIP-29 group if needed; (re)publish its metadata for each new manifest."""
        m = manifest
        if m is not None and self._meta_for == m.message_id:
            return
        meta = await self.relay.query({"kinds": [METADATA], "#d": [self.nostr_group]})
        if not meta:
            ev = sign_event(self.sender.secret, CREATE_GROUP, "", [["h", self.nostr_group]])
            ok, msg = await self.relay.publish(ev)
            if not ok and not msg.startswith("duplicate"):
                raise ExportError(f"cannot create {self.source}: {msg}")
        name = m.name if m else self.group_id
        about = (f"Portal to the Unseenet group {m.name if m else self.group_id} "
                 f"({self.group_id}). Posts are copied both ways by an Unseenet gateway: "
                 "what you write here appears in Unseenet, and Unseenet posts appear here "
                 "with their author's name. https://unseenet.org")
        ev = sign_event(self.sender.secret, EDIT_METADATA, "",
                        [["h", self.nostr_group], ["name", f"{name} (Unseenet)"],
                         ["about", about]])
        ok, msg = await self.relay.publish(ev)
        if not ok:
            raise ExportError(f"cannot set metadata on {self.source}: {msg}")
        self._meta_for = m.message_id if m else ""
        self.state.set_cursor(NETWORK, f"joined:{self.relay.url}'{self.nostr_group}", 1)
        log.info("portal counterpart %s ready", self.source)

    async def send(self, art: Article) -> str:
        return await self.sender.send(art)
