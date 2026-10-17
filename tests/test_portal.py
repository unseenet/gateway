from unseenet.core import crypto
from unseenet.core.article import new_article
from unseenet.core.groups import Manifest

from unseenet_gateway.nostr.portal import exportable, may_have_portal, portal_entry

GW = crypto.Identity.generate()
OWNER = crypto.Identity.generate()
SRC = "wss://nostr.unseenet.org'test-portal"


def test_portal_entry_needs_network_source_and_gateway():
    m = {"portals": [{"network": "nostr", "source": SRC, "gateway": [GW.key_text]}]}
    assert portal_entry(m, "nostr", SRC, GW.key_text)
    assert portal_entry(m, "nostr", SRC + "x", GW.key_text) is None
    assert portal_entry(m, "matrix", SRC, GW.key_text) is None
    assert portal_entry(m, "nostr", SRC, OWNER.key_text) is None
    assert portal_entry({}, "nostr", SRC, GW.key_text) is None
    assert portal_entry({"portals": "junk"}, "nostr", SRC, GW.key_text) is None


def _m(gtype, moderators=(), local=False):
    return Manifest(group_id="g@x", name="g", type=gtype, owner=OWNER.public_key, serial=1,
                    moderators=list(moderators), local=local)


def test_which_groups_may_have_portals():
    assert may_have_portal(_m("open"), GW.public_key) is None
    assert may_have_portal(_m("moderated", [GW.public_key]), GW.public_key) is None
    assert may_have_portal(_m("moderated"), GW.public_key)
    for t in ("closed", "inbox", "channel"):
        assert may_have_portal(_m(t), GW.public_key)
    assert may_have_portal(_m("open", local=True), GW.public_key)


def _art(author, body="hello", **headers):
    a = new_article("test.portal@x", "Hi", body)
    for k, v in headers.items():
        a.set(k.replace("_", "-"), v)
    a.finalize(author, 0)
    return a


def test_what_never_goes_out():
    assert exportable(_art(OWNER), GW.public_key) is None
    assert exportable(_art(GW), GW.public_key) == "came from another network"
    assert exportable(_art(OWNER, Origin_Network="nostr"), GW.public_key)
    assert exportable(_art(OWNER, Encrypted="x"), GW.public_key) == "encrypted"
    assert exportable(_art(OWNER, body="  "), GW.public_key) == "empty"
