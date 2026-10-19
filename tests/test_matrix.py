"""Matrix adapter: names and conversion. Synthetic events only."""

from datetime import datetime, timezone

import pytest

from unseenet.core import crypto
from unseenet.core.article import Article, validate_structure
from unseenet.core.groups import make_group_id

from unseenet_gateway.core.adapter import Skip
from unseenet_gateway.matrix.adapter import MatrixAdapter
from unseenet_gateway.matrix.convert import (FROM_UNSEENET_KEY, convert, strip_reply_fallback,
                                             unseenet_name)
from unseenet_gateway.matrix.exporter import txn_id

OWNER, GW = crypto.Identity.generate(), crypto.Identity.generate()
GROUP_ID = make_group_id("test.matrix.lab", OWNER.public_key)
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
TS = int(NOW.timestamp() * 1000) - 60_000
ROOM = "!lab:example.org"
MID = "<" + "a" * 32 + "@unseenet>"
MID2 = "<" + "b" * 32 + "@unseenet>"


def ev(body="Hello there", *, eid="$e1", sender="@alice:example.org", msgtype="m.text",
       rel=None, etype="m.room.message", **extra):
    content = {"msgtype": msgtype, "body": body, **extra}
    if rel:
        content["m.relates_to"] = rel
    return {"type": etype, "event_id": eid, "sender": sender, "room_id": ROOM,
            "origin_server_ts": TS, "content": content}


def conv(e, ids=None, names=None, gateway_user=None):
    return convert(e, group_id=GROUP_ID, id_map=(ids or {}).get, name_of=(names or {}).get,
                   gateway_user=gateway_user, now=NOW)


def test_names():
    assert unseenet_name("#python:matrix.org", "matrix") == "matrix.matrix-org.python"
    assert unseenet_name("#Dk.Snak:example.org:8448", "test.matrix") == \
        "test.matrix.example-org-8448.dk-snak"
    assert unseenet_name("!abcdef:matrix.org", "matrix") is None     # ids need a chosen name
    assert unseenet_name("#___:matrix.org", "matrix") is None


def test_text_is_a_valid_chat_line():
    art = conv(ev(), names={"@alice:example.org": "Alice"}).finalize(GW, 8)
    raw = art.to_bytes()
    validate_structure(Article.from_bytes(raw), raw_size=len(raw), now=NOW)
    assert art["Message-Kind"] == "chat" and art["Subject"] == ""
    assert art["From"] == "Alice" and art.body.rstrip("\n") == "Hello there"
    assert art["Origin-Network"] == "matrix" and art["Origin-ID"] == "$e1"
    assert art["Origin-From"] == "@alice:example.org" and art["Matrix-Room"] == ROOM
    assert "Origin-Proof" not in art


def test_from_falls_back_to_localpart_and_emote():
    art = conv(ev("waves", msgtype="m.emote"))
    assert art["From"] == "alice" and art.body.startswith("* alice waves")
    assert art["Matrix-Msgtype"] == "m.emote"


@pytest.mark.parametrize("e,reason", [
    (ev(msgtype="m.image", url="mxc://x/y"), "media"),
    (ev(msgtype="m.file"), "media"),
    (ev(etype="m.room.encrypted"), "encrypted"),
    (ev(etype="m.reaction"), "type"),
    (ev("   "), "empty"),
    ({"type": "m.room.message", "event_id": "$r", "sender": "@a:x", "content": {}}, "redacted"),
    (ev(**{FROM_UNSEENET_KEY: MID}), "loop"),
])
def test_skips(e, reason):
    with pytest.raises(Skip) as s:
        conv(e)
    assert s.value.reason == reason


def test_own_account_is_a_loop():
    with pytest.raises(Skip):
        conv(ev(sender="@gw:example.org"), gateway_user="@gw:example.org")


def test_reply_strips_fallback_and_references_parent():
    body = "> <@bob:example.org> original\n> second line\n\nMy answer"
    art = conv(ev(body, eid="$e2", rel={"m.in_reply_to": {"event_id": "$e1"}}),
               ids={"$e1": MID})
    assert art.body.rstrip("\n") == "My answer" and art["References"] == MID


def test_fallback_left_alone_without_reply():
    assert strip_reply_fallback("plain\ntext") == "plain\ntext"


def test_thread_references_root_then_parent():
    rel = {"rel_type": "m.thread", "event_id": "$root", "is_falling_back": False,
           "m.in_reply_to": {"event_id": "$p"}}
    art = conv(ev(rel=rel), ids={"$root": MID, "$p": MID2})
    assert art["References"] == f"{MID} {MID2}"


def test_thread_fallback_reply_is_ignored():
    rel = {"rel_type": "m.thread", "event_id": "$root", "is_falling_back": True,
           "m.in_reply_to": {"event_id": "$latest"}}
    art = conv(ev(rel=rel), ids={"$root": MID, "$latest": MID2})
    assert art["References"] == MID


def test_edit_becomes_new_article_referring_to_the_old():
    e = ev("* fixed", eid="$e3", rel={"rel_type": "m.replace", "event_id": "$e1"},
           **{"m.new_content": {"msgtype": "m.text", "body": "fixed"}})
    art = conv(e, ids={"$e1": MID})
    assert art.body.rstrip("\n") == "fixed" and art["References"] == MID
    assert art["Matrix-Edit"] == "$e1"
    with pytest.raises(Skip) as s:
        conv(e)
    assert s.value.reason == "edit"


def test_txn_id_is_stable():
    assert txn_id(MID) == txn_id(MID) != txn_id(MID2)


def test_adapter_rooms_and_manifest_fields(tmp_path):
    cfg = {"gateway": {"group_owner": OWNER.key_text, "gateway_key": str(tmp_path / "gw.key")},
           "matrix": {"homeserver": "https://example.org", "user": "@gw:example.org",
                      "prefix": "test.matrix", "direction": "both",
                      "rooms": ["#lab:example.org", {"room": ROOM, "name": "lab2"}]}}
    ad = MatrixAdapter(cfg)
    carried = ad.carried()
    assert [c.name for c in carried] == ["test.matrix.example-org.lab", "test.matrix.lab2"]
    assert all(c.view == "chat" and c.kinds == ("chat",) for c in carried)
    assert ad.host() == "@gw:example.org"
    assert ad.token_path() == tmp_path / "matrix.token"
    assert "kick this account" in ad.announcement("#lab:example.org", carried[0].name)


# --- consent and openness -------------------------------------------------------

from unseenet_gateway.matrix.client import Matrix
from unseenet_gateway.matrix.feed import openness


def st(join_rule=None, encrypted=False):
    out = []
    if join_rule:
        out.append({"type": "m.room.join_rules", "content": {"join_rule": join_rule}})
    if encrypted:
        out.append({"type": "m.room.encryption", "content": {"algorithm": "m.megolm.v1.aes-sha2"}})
    return out


def test_openness():
    assert openness(st("public")) is None
    assert openness(st("public", encrypted=True)) == "encrypted"
    assert "not public" in openness(st("invite"))
    assert "not public" in openness(st("knock"))
    assert openness(st()) == "of unknown join rule"


def test_invites_are_tracked_across_incremental_syncs():
    import asyncio
    replies = [
        {"next_batch": "s1", "rooms": {"invite": {"!a:x": {"invite_state": {"events": st("public")}}}}},
        {"next_batch": "s2", "rooms": {"invite": {"!b:x": {"invite_state": {"events": []}}}}},
        {"next_batch": "s3", "rooms": {"join": {"!a:x": {}}}},
    ]
    seen = []

    class Fake(Matrix):
        def _call(self, method, path, params=None, body=None):
            seen.append((params or {}).get("since"))
            assert (params or {}).get("set_presence") == "offline"    # never shows as online
            return replies.pop(0)

    m = Fake("https://x")
    assert set(asyncio.run(m.invites())) == {"!a:x"}
    assert set(asyncio.run(m.invites())) == {"!a:x", "!b:x"}     # earlier invite kept
    assert set(asyncio.run(m.invites())) == {"!b:x"}             # joined elsewhere: gone
    assert seen == [None, "s1", "s2"]


def test_alias_is_pinned_to_its_first_room(tmp_path):
    import asyncio
    from unseenet_gateway.core.state import State
    from unseenet_gateway.matrix.feed import MatrixFeed, RoomMoved

    class FakeMatrix:
        base, user_id, target = "https://x", "@gw:x", "!one:x"
        async def resolve(self, room):
            return self.target

    st, mx = State(tmp_path / "s.db"), FakeMatrix()
    assert asyncio.run(MatrixFeed(state=st, matrix=mx, carried={}).room_id("#lab:x")) == "!one:x"
    mx.target = "!two:x"
    with pytest.raises(RoomMoved):
        asyncio.run(MatrixFeed(state=st, matrix=mx, carried={}).room_id("#lab:x"))
