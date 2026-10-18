"""The gateway core with a loopback adapter: no network, no Tor, no node.

The loopback adapter is also the smallest complete example of an adapter.
"""

import asyncio

from unseenet.core import crypto
from unseenet.core.article import new_article
from unseenet.core.groups import make_group_id
from unseenet.nntp import NNTPError

from unseenet_gateway.core.adapter import (Adapter, Capabilities, Carried, Feed, Incoming,
                                           Retraction, Skip, Source)
from unseenet_gateway.core.importer import Importer
from unseenet_gateway.core.origin import origin_headers
from unseenet_gateway.core.registry import adapters
from unseenet_gateway.core.state import State

GW = crypto.Identity.generate()
OWNER = crypto.Identity.generate()
GROUP = make_group_id("loop.test", OWNER.public_key)


class LoopFeed(Feed):
    """Messages are dicts {id, text, reply_to?}; ``gone`` lists ids the network deleted."""
    network = "loop"
    label = "loop"

    def __init__(self, state, messages):
        self.state, self.messages, self.gone = state, messages, set()

    def sources(self):
        return [Source("room", GROUP)]

    async def fetch(self, source):
        for m in self.messages:
            yield Incoming(m["id"], m, label=m["id"])

    def convert(self, source, item):
        m = item.payload
        if not m["text"]:
            raise Skip("empty")
        refs = [self.state.lookup("loop", m["reply_to"])] if m.get("reply_to") else None
        return new_article(source.group_id, "Loop", m["text"], references=refs,
                           extra=origin_headers("loop", m["id"]))

    async def retractions(self, source):
        return [Retraction(fid, self.state.lookup("loop", fid), "Deleted.")
                for fid in sorted(self.gone) if self.state.lookup("loop", fid)]


class LoopAdapter(Adapter):
    network = "loop"
    capabilities = Capabilities(retractions=True)

    def carried(self):
        return [Carried("room", "loop.test", self.group_id("loop.test"), "import", "Loop", "")]

    def feeds(self, *, state, node, gateway, pow_bits):
        return [LoopFeed(state, self.section.get("messages", []))]


class FakeNode:
    def __init__(self, refuse=()):
        self.posted, self.refuse = [], set(refuse)

    async def post(self, art):
        if art.body.strip() in self.refuse:
            raise NNTPError(441, "too large: no")
        self.posted.append(art)
        return "ok"


def run(importer):
    return asyncio.run(importer.run())


def test_import_duplicates_skips_refusals_and_threads(tmp_path):
    state = State(tmp_path / "gw.db")
    msgs = [{"id": "a", "text": "first"}, {"id": "b", "text": "reply", "reply_to": "a"},
            {"id": "c", "text": ""}, {"id": "d", "text": "refused"}]
    node = FakeNode(refuse={"refused"})
    imp = Importer(feed=LoopFeed(state, msgs), state=state, node=node, gateway=GW, pow_bits=0)

    st = run(imp)
    assert (st.imported, st.skipped, st.refused, st.duplicate) == (2, 1, 1, 0)
    first, reply = node.posted
    assert first.author_key == GW.public_key            # signed by the gateway
    assert reply["References"] == first.message_id      # threads through the id map
    assert state.stats()["skipped"]["loop"] == {"empty": 1, "node-too large": 1}

    st = run(imp)                                       # nothing new the second time
    assert (st.imported, st.duplicate) == (0, 2)


def test_retraction_cancels_once(tmp_path):
    state = State(tmp_path / "gw.db")
    feed = LoopFeed(state, [{"id": "a", "text": "first"}])
    node = FakeNode()
    imp = Importer(feed=feed, state=state, node=node, gateway=GW, pow_bits=0)
    run(imp)
    feed.gone.add("a")
    assert run(imp).cancelled == 1
    assert node.posted[-1]["Control"] == f"cancel {node.posted[0].message_id}"
    assert run(imp).cancelled == 0


def test_adapter_reads_its_own_section():
    cfg = {"gateway": {"group_owner": OWNER.key_text}, "loop": {"prefix": "test.loop"}}
    ad = LoopAdapter(cfg)
    assert ad.prefix == "test.loop"
    assert ad.carried()[0].group_id == GROUP


def test_builtin_adapters_are_registered():
    known = adapters()
    assert list(known)[:2] == ["usenet", "nostr"]
    assert known["nostr"].capabilities.portals and "nostr-key" in known["nostr"].commands
    assert not known["usenet"].capabilities.export
