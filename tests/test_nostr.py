"""Nostr adapter: signatures, encoding, conversion. Synthetic events only."""

import json
import os
from datetime import datetime, timezone

import pytest

from unseenet.core import crypto
from unseenet.core.article import Article, validate_structure
from unseenet.core.groups import make_group_id

from unseenet_gateway.nostr.convert import (Skip, cancel_article, convert, npub,
                                            unseenet_name)
from unseenet_gateway.nostr.event import (Event, pubkey_of, schnorr_sign, schnorr_verify,
                                          sign_event)

OWNER, GW = crypto.Identity.generate(), crypto.Identity.generate()
GROUP_ID = make_group_id("test.nostr.lab", OWNER.public_key)
NOW = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
ALICE, BOB = os.urandom(32), os.urandom(32)


def test_bip340_vector_0():
    sk = (3).to_bytes(32, "big")
    pk = bytes.fromhex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
    sig = bytes.fromhex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
    assert pubkey_of(sk) == pk
    assert schnorr_sign(sk, bytes(32), bytes(32)) == sig
    assert schnorr_verify(pk, bytes(32), sig)
    assert not schnorr_verify(pk, b"\x01" + bytes(31), sig)


def test_npub_known_value():
    assert npub("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d") == \
        "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"


def test_event_roundtrip_and_tamper():
    ev = sign_event(ALICE, 11, "Hej æøå\nline two", [["h", "lab"], ["title", "T"]])
    again = Event.from_dict(json.loads(ev.to_json()))
    assert again.verify()
    again.content += "!"
    assert not again.verify()


def test_names():
    assert unseenet_name("unseenet-lab", "nostr") == "nostr.unseenet-lab"
    assert unseenet_name("Pizza Lovers", "nostr") == "nostr.pizza-lovers"
    assert unseenet_name("___", "nostr") is None


def conv(ev, ids=None, titles=None, names=None):
    return convert(ev, group_id=GROUP_ID, id_map=(ids or {}).get,
                   title_of=(titles or {}).get, name_of=(names or {}).get, now=NOW)


def test_thread_is_valid_unseenet_and_proof_verifies():
    ev = sign_event(ALICE, 11, "Body text.", [["h", "lab"], ["title", "Hello"]])
    art = conv(ev, names={ev.pubkey: "Alice"}).finalize(GW, 8)
    raw = art.to_bytes()
    validate_structure(Article.from_bytes(raw), raw_size=len(raw), now=NOW)
    assert art["Subject"] == "Hello" and art["From"] == "Alice"
    assert art["Origin-Network"] == "nostr" and art["Origin-ID"] == ev.id
    assert art["Origin-From"] == npub(ev.pubkey)
    assert art["Nostr-Kind"] == "11"
    proof = Event.from_dict(json.loads(art["Origin-Proof"]))
    assert proof.verify() and proof.content == "Body text."


def test_comment_threads_under_root():
    root = sign_event(ALICE, 11, "Root", [["h", "lab"], ["title", "Topic"]])
    c = sign_event(BOB, 1111, "Reply", [["h", "lab"], ["E", root.id], ["K", "11"],
                                       ["e", root.id], ["k", "11"]])
    mid = "<" + "a" * 32 + "@unseenet>"
    art = conv(c, ids={root.id: mid}, titles={root.id: "Topic"})
    assert art["Subject"] == "Re: Topic"
    assert art["References"] == mid
    assert art["From"].startswith("npub1")


def test_chat_message():
    ev = sign_event(BOB, 9, "just chatting\nmore", [["h", "lab"]])
    art = conv(ev)
    assert art.get("Subject", "") == ""               # no made-up subject (UN-RFC 0028 3.3)
    assert art["Message-Kind"] == "chat"
    thread = conv(sign_event(BOB, 11, "body", [["h", "lab"], ["title", "Topic"]]))
    assert thread["Message-Kind"] == "post" and thread["Subject"] == "Topic"


@pytest.mark.parametrize("kind,tags,content,reason", [
    (9007, [["h", "lab"]], "x", "kind"),
    (11, [["h", "lab"], ["unseenet", "<x@unseenet>"]], "x", "loop"),
    (11, [["h", "lab"]], "   ", "empty"),
])
def test_never_imported(kind, tags, content, reason):
    with pytest.raises(Skip) as e:
        conv(sign_event(ALICE, kind, content, tags))
    assert e.value.reason == reason


def test_cancel_article_signs():
    art = cancel_article(GROUP_ID, "<" + "b" * 32 + "@unseenet>", "Deleted.", now=NOW)
    art.finalize(GW, 8)
    assert art["Control"].startswith("cancel <")


def test_nip40_expiration_becomes_expires():
    exp = int(NOW.timestamp()) + 3600
    art = conv(sign_event(ALICE, 9, "short-lived", [["h", "lab"], ["expiration", str(exp)]]))
    assert art["Expires"] == "Sat, 17 Oct 2026 13:00:00 +0000"
    far = conv(sign_event(ALICE, 9, "long", [["h", "lab"], ["expiration", str(exp + 30 * 86400)]]))
    assert far["Expires"] == "Sat, 24 Oct 2026 12:00:00 +0000"


def test_names_from_profile_relay(monkeypatch):
    import asyncio, json as _json
    from unseenet_gateway.nostr import feed as imp

    class FakeRelay:
        def __init__(self, url, proxy=None, events=None, fail=False):
            self.url, self.events, self.fail = url, events or [], fail
        async def query(self, *f):
            if self.fail:
                raise RuntimeError("blocked: invalid query")
            return self.events
        async def close(self):
            pass

    old = sign_event(ALICE, 0, _json.dumps({"name": "old"}), [])
    new = sign_event(ALICE, 0, _json.dumps({"display_name": "Alice  A."}), [])
    new.created_at = old.created_at + 10
    profiles = FakeRelay("wss://p", events=[new, old])
    monkeypatch.setattr(imp, "Relay", lambda url, proxy=None: profiles)
    i = imp.NostrFeed.__new__(imp.NostrFeed)
    i.relay, i.names, i.looked, i.proxy = FakeRelay("ws://g", fail=True), {}, {}, None
    i.profile_relays = ["wss://p"]
    msg = sign_event(ALICE, 9, "hi", [["h", "lab"]])
    asyncio.run(i._fill_names([msg]))
    assert i.names[msg.pubkey] == "Alice A."


def test_markdown_where_the_note_is_markdown():
    """gateway#26: links, emphasis, code or lists go in as Markdown; plain stays plain."""
    from unseenet_gateway.nostr.convert import looks_like_markdown
    md = conv(sign_event(ALICE, 11, "See [the site](https://example.org) **now**",
                         [["h", "lab"], ["title", "T"]]))
    assert md["Content-Type"].startswith("text/markdown")
    plain = conv(sign_event(BOB, 9, "2*3 is 6 and snake_case_name", [["h", "lab"]]))
    assert plain["Content-Type"].startswith("text/plain")
    assert looks_like_markdown("- one\n- two") and looks_like_markdown("use `x`")
    assert not looks_like_markdown("#nostr is fun") and not looks_like_markdown("a * b")


def test_nip29_groups_are_shown_as_chat():
    from unseenet_gateway.nostr.adapter import NostrAdapter
    from unseenet_gateway.usenet.adapter import UsenetAdapter
    gw = {"group_owner": OWNER.key_text, "gateway_key": "/nonexistent/gw.key"}
    ad = NostrAdapter({"gateway": gw, "nostr": {"prefix": "test.nostr",
                       "relays": [{"url": "wss://relay.example", "groups": ["lab"]}]}})
    [(_, c)] = ad._relay_groups(ad.relays()[0], "host")
    assert c.view == "chat"
    us = UsenetAdapter({"gateway": gw, "usenet": {"prefix": "test.usenet", "groups": ["comp.misc"]}})
    assert [c.view for c in us.carried()] == ["threads"]


# --- several gateways for one group (UN-RFC 0038, gateway#16) ----------------------

def test_npub_back_to_hex():
    from unseenet_gateway.nostr.convert import npub_hex
    pk = pubkey_of(ALICE).hex()
    assert npub_hex(npub(pk)) == pk and npub_hex(pk) == pk
    broken = npub(pk)[:-1] + ("q" if npub(pk)[-1] != "q" else "p")
    assert npub_hex(broken) is None and npub_hex("nsec1abc") is None


def _adapter(groups):
    from unseenet_gateway.nostr.adapter import NostrAdapter
    gw = {"group_owner": OWNER.key_text, "gateway_key": "/nonexistent/gw.key"}
    return NostrAdapter({"gateway": gw, "nostr": {"prefix": "test.nostr", "relays": [
        {"url": "wss://relay.example", "groups": groups}]}})


def test_joining_another_gateways_group():
    shared = make_group_id("nostr.shared", OWNER.public_key)
    ad = _adapter(["own", {"id": "shared", "group": shared}])
    own, joined = ad.carried()
    assert not own.joined and joined.joined and joined.group_id == shared
    assert joined.source == "wss://relay.example'shared" and joined.view == "chat"


class _Relay:
    url = "wss://relay.example"

    def __init__(self, events):
        self.events, self.queries, self.published = events, [], []

    async def query(self, *filters):
        self.queries.append(filters)
        return self.events

    async def publish(self, ev):
        self.published.append(ev)
        return True, ""


def test_the_group_lists_say_whether_another_gateway_may_take_part():
    import asyncio
    from types import SimpleNamespace
    ad = _adapter(["shared"])
    other = pubkey_of(BOB).hex()
    members = sign_event(ALICE, 39002, "", [["d", "shared"], ["p", other]])
    feed = SimpleNamespace(relay=_Relay([members]))
    src = "wss://relay.example'shared"
    assert asyncio.run(ad.is_member([feed], src, npub(other))) is True
    assert asyncio.run(ad.is_member([feed], src, npub(pubkey_of(ALICE).hex()))) is False
    assert feed.relay.queries[0][0] == {"kinds": [39002, 39001], "#d": ["shared"]}
    assert asyncio.run(ad.is_member([SimpleNamespace(relay=_Relay([]))], src, npub(other))) is None
    assert asyncio.run(ad.is_member([feed], src, "not-a-key")) is None


def test_export_is_skipped_when_another_gateway_sent_it_first():
    import asyncio
    from unseenet_gateway.core.state import State
    from unseenet_gateway.nostr.exporter import NostrSender
    mid = "<" + "c" * 32 + "@unseenet>"
    theirs = sign_event(BOB, 9, "hi", [["h", "lab"], ["unseenet", mid]])
    relay = _Relay([theirs])
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as d:
        state = State(Path(d) / "s.json")
        state.set_cursor("nostr", "joined:wss://relay.example'lab", 1)
        sender = NostrSender(relay=relay, secret=ALICE, state=state, groups={"g": "lab"})

        class Art:
            group, message_id = "g", mid
            body = "hi\n"

            @staticmethod
            def get(name, default=None):
                return default
        assert asyncio.run(sender.send(Art)) == theirs.id
    assert relay.published == []                       # nothing sent twice
    assert asyncio.run(sender.retract(Art, theirs.id)) is False   # and theirs is not ours


def test_usenet_joins_and_says_it_has_no_consent_of_its_own():
    from unseenet_gateway.usenet.adapter import UsenetAdapter
    shared = make_group_id("usenet.comp.misc", OWNER.public_key)
    gw = {"group_owner": OWNER.key_text, "gateway_key": "/nonexistent/gw.key"}
    us = UsenetAdapter({"gateway": gw, "usenet": {"prefix": "usenet", "groups": [
        "alt.test", {"name": "comp.misc", "group": shared}]}})
    own, joined = us.carried()
    assert not own.joined and joined.joined and joined.group_id == shared
    assert "approval alone" in us.consent_note


# --- pictures in from NIP-29 groups (gateway#26) -----------------------------------

def test_pictures_of_a_note():
    from unseenet_gateway.nostr.convert import pictures_of
    ev = sign_event(ALICE, 9, "Look https://nostr.build/i/cat.jpg and https://x.org/page "
                    "http://plain.example/a.png https://nostr.build/i/cat.jpg",
                    [["h", "lab"], ["imeta", "url https://img.example/dog", "m image/webp",
                                    "alt A dog"]])
    assert pictures_of(ev) == [("https://img.example/dog", "A dog"),
                               ("https://nostr.build/i/cat.jpg", "")]
    many = sign_event(ALICE, 9, " ".join(f"https://h.example/{i}.png" for i in range(6)), [["h", "lab"]])
    assert len(pictures_of(many)) == 4
    assert conv(ev)["Gateway-Media"] == "1"
    assert "Gateway-Media" not in conv(sign_event(ALICE, 9, "no pictures", [["h", "lab"]]))


def test_the_feed_fetches_them_and_the_importer_attaches_them():
    import asyncio
    import io
    from unseenet_gateway.core import files as fl
    from unseenet_gateway.core.importer import Importer
    from unseenet_gateway.nostr.feed import NostrFeed
    if not fl.core_posts_files():
        pytest.skip("this core cannot post files (unseenet 0.5)")
    Image = pytest.importorskip("PIL.Image")
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), (1, 2, 3)).save(buf, "PNG")
    asked = []

    async def fetch(url, limit):
        asked.append(url)
        if "broken" in url:
            raise OSError("HTTP 404")
        return buf.getvalue()

    class R:
        url = "wss://relay.example"
    feed = NostrFeed(state=None, relay=R(), carried={}, fetch=fetch)
    ev = sign_event(ALICE, 9, "https://p.example/ok.png https://p.example/broken.png", [["h", "lab"]])
    item = type("I", (), {"payload": ev, "label": "#1"})()
    media = asyncio.run(feed.media(None, item))
    assert [m.name for m in media] == ["ok.png"] and len(asked) == 2

    class Node:
        async def post(self, art, **kw):
            return "ok"
    imp = Importer(feed=feed, state=None, node=Node(), gateway=GW, pow_bits=8, pictures_max=1 << 20)
    art = conv(ev)
    blobs, _ = asyncio.run(imp._pictures(None, item, art))
    assert len(blobs) == 1 and art["Attachment-1"].startswith(blobs[0][0])


def test_nothing_is_fetched_without_tor_or_from_plain_http():
    import asyncio
    from unseenet_gateway.core.files import fetch_over_tor
    with pytest.raises(OSError, match="no Tor"):
        asyncio.run(fetch_over_tor("https://p.example/a.png", None, 1000))
    with pytest.raises(ValueError, match="only https"):
        asyncio.run(fetch_over_tor("http://p.example/a.png", 9050, 1000))
