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
    assert conv(ev)["Subject"] == "just chatting"


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
