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
    assert list(known)[:3] == ["usenet", "nostr", "matrix"]
    assert known["matrix"].capabilities.export and "matrix-login" in known["matrix"].commands
    assert known["nostr"].capabilities.portals and "nostr-key" in known["nostr"].commands
    assert not known["usenet"].capabilities.export


# --- portals: the delay survives one-off passes --------------------------------
from unseenet.core.groups import manifest_article  # noqa: E402

from unseenet_gateway.core import portal as portal_mod  # noqa: E402
from unseenet_gateway.core.adapter import Counterpart  # noqa: E402

PORTAL = make_group_id("loop.portal", OWNER.public_key)
USER = crypto.Identity.generate()


class GroupClient:
    def __init__(self, arts):
        self.arts = arts

    async def group(self, gid):
        return len(self.arts), 1, len(self.arts)

    async def article(self, n):
        return self.arts[int(n) - 1].to_bytes()


class PortalNode(FakeNode):
    def __init__(self, arts):
        super().__init__()
        self.client = GroupClient(arts)

    async def _conn(self):
        return self.client


class LoopCounterpart(Counterpart):
    network, source = "loop", "room"

    def __init__(self, state):
        self.feed = LoopFeed(state, [])
        self.sent = []

    async def ensure(self, manifest):
        pass

    async def send(self, art):
        self.sent.append(art.message_id)
        return f"loop-{len(self.sent)}"


def test_portal_delay_survives_one_off_passes(tmp_path, monkeypatch):
    manifest = manifest_article(OWNER, PORTAL, {
        "v": 1, "name": "loop.portal", "type": "open", "owner": OWNER.key_text, "serial": 1,
        "min_pow": 0, "retention_days": 90,
        "portals": [{"network": "loop", "source": "room", "gateway": [GW.key_text]}]}, 0)
    post = new_article(PORTAL, "Hello", "Through the portal.")
    post.finalize(USER, 0)
    state = State(tmp_path / "gw.db")
    clock = [1_000_000.0]
    monkeypatch.setattr(portal_mod.time, "time", lambda: clock[0])
    monkeypatch.setattr(portal_mod.random, "uniform", lambda lo, hi: 12.0)

    def one_pass():                       # a fresh Portal each time, as import-once
        cp = LoopCounterpart(state)
        p = portal_mod.Portal(state=state, node=PortalNode([manifest, post]), gateway=GW,
                              counterpart=cp, group_id=PORTAL, pow_bits=0, delay_max=20)
        return asyncio.run(p.run()), cp

    st, cp = one_pass()                   # due in 12 s
    assert (st.exported, st.waiting) == (0, 1)
    clock[0] += 5
    assert one_pass()[0].waiting == 1     # the same due time, not drawn again
    clock[0] += 10
    st, cp = one_pass()
    assert st.exported == 1 and cp.sent == [post.message_id]
    st, cp = one_pass()
    assert st.exported == 0 and st.waiting == 0
    assert state.get_cursor("unseenet", f"portal-due:{PORTAL}:{post.message_id}") is None
