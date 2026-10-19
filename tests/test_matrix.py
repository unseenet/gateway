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
    space = st("public") + [{"type": "m.room.create", "content": {"type": "m.space"}}]
    assert openness(space) == "a space, not a room"


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


def test_portal_counterpart_needs_an_alias(tmp_path):
    from unseenet_gateway.core.state import State
    from unseenet_gateway.matrix.portal import MatrixCounterpart, portal_topic
    with pytest.raises(ValueError):
        MatrixCounterpart(state=State(tmp_path / "s.db"), matrix=None, alias="!id:x",
                          group_id=GROUP_ID)
    cp = MatrixCounterpart(state=State(tmp_path / "s.db"), matrix=None,
                           alias="#unseenet:unseenet.org", group_id=GROUP_ID,
                           admins=["@a:example.org"])
    assert cp.source == "#unseenet:unseenet.org" and cp.network == "matrix"
    t = portal_topic("unseenet", GROUP_ID)
    assert GROUP_ID in t and "late" in t and "unseenet.org" in t


def test_new_thread_carries_its_subject():
    import asyncio
    from unseenet_gateway.matrix.exporter import MatrixSender
    from unseenet.core.article import new_article

    sent = {}

    class FakeMatrix:
        async def membership(self, rid):
            return "join"

        async def send(self, rid, content, txn):
            sent[txn] = content["body"]
            return "$x"

    class FakeState:
        def foreign_for(self, mid):
            return None

    async def rid(_):
        return "!r:x"

    s = MatrixSender(matrix=FakeMatrix(), state=FakeState(), rooms={GROUP_ID: "#r:x"},
                     room_id_of=rid)
    me = crypto.Identity.generate()
    post = new_article(GROUP_ID, "Topic", "Body", from_name="Dora").finalize(me, 0)
    chat = new_article(GROUP_ID, "", "Line", from_name="Dora",
                       extra=[("Message-Kind", "chat")]).finalize(me, 0)
    asyncio.run(s.send(post)), asyncio.run(s.send(chat))
    bodies = list(sent.values())
    assert bodies[0].split("\n")[0].endswith("on Unseenet: Topic")
    assert bodies[1].split("\n")[0].endswith("on Unseenet:")


def test_join_survives_a_room_where_the_gateway_may_not_write(tmp_path):
    import asyncio
    from unseenet_gateway.core.state import State
    from unseenet_gateway.matrix.client import MatrixError
    from unseenet_gateway.matrix.feed import MatrixFeed

    class FakeMatrix:
        base, user_id = "https://x", "@gw:x"
        joined = False
        async def resolve(self, room): return "!r:x"
        async def membership(self, rid): return "join" if self.joined else None
        async def invites(self): return {"!r:x": st("public")}
        async def whoami(self): return self.user_id
        async def join(self, rid): self.joined = True
        async def send(self, *a, **k): raise MatrixError(403, "M_FORBIDDEN", "send_level 100")

    feed = MatrixFeed(state=State(tmp_path / "s.db"), matrix=FakeMatrix(), carried={},
                      announce={"#r:x": "hello"})
    assert asyncio.run(feed.ensure_joined("#r:x")) == "!r:x"


def test_markdown_goes_to_matrix_formatted_and_safe():
    import asyncio
    from unseenet.core.article import new_article
    from unseenet.core.markup import MARKDOWN_TYPE
    from unseenet_gateway.core.adapter import is_text
    from unseenet_gateway.matrix.exporter import MatrixSender, markdown_html

    html = markdown_html("**bold** [ok](https://unseenet.org) [bad](javascript:alert(1)) "
                         "<script>x</script> ![img](https://x/y.png)")
    assert "<strong>bold</strong>" in html and 'href="https://unseenet.org"' in html
    assert "javascript:" not in html.split("href=")[-1][:20] and "<script>" not in html
    assert "<img" not in html

    sent = {}

    class FakeMatrix:
        async def membership(self, rid):
            return "join"

        async def send(self, rid, content, txn):
            sent.update(content)
            return "$x"

    class FakeState:
        def foreign_for(self, mid):
            return None

    async def rid(_):
        return "!r:x"

    art = new_article(GROUP_ID, "", "Hej **verden**", from_name="Andreas",
                      extra=[("Content-Type", MARKDOWN_TYPE), ("Message-Kind", "chat")]
                      ).finalize(crypto.Identity.generate(), 0)
    assert is_text(art)
    asyncio.run(MatrixSender(matrix=FakeMatrix(), state=FakeState(), rooms={GROUP_ID: "#r:x"},
                             room_id_of=rid).send(art))
    assert sent["body"].endswith("Hej **verden**")
    assert sent["format"] == "org.matrix.custom.html"
    assert "<strong>verden</strong>" in sent["formatted_body"] and "Andreas" in sent["formatted_body"]
