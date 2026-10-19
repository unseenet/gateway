"""The exporter asks the group before it sends to the other network (unseenet #116)."""

import asyncio

from unseenet.core import crypto
from unseenet.core.article import new_article
from unseenet.core.groups import Manifest, make_manifest
from unseenet_gateway.core.state import State
from unseenet_gateway.core.submissions import Exporter

OWNER, GW, ALICE, MALLORY = (crypto.Identity.generate() for _ in range(4))


class Node:
    def __init__(self, manifest):
        self.m, self.posted = manifest, []

    async def manifest(self, gid):
        return self.m

    async def post(self, art):
        self.posted.append(art)
        return "ok"


def setup(tmp_path, *, kinds=None, banned=(), min_pow=0):
    art = make_manifest(OWNER, "matrix.lab.room", "moderated", moderators=[GW.key_text],
                        kinds=kinds, pow_bits=0, min_pow=min_pow)
    m = Manifest.from_article(art)
    m.banned = [k.public_key for k in banned]
    node, sent = Node(m), []

    async def send(a):
        sent.append(a.message_id)
        return f"$event{len(sent)}"

    ex = Exporter(state=State(tmp_path / "gw.db"), node=node, gateway=GW,
                  targets={m.group_id: ("matrix", send)}, min_pow=0, delay_max=0)
    return ex, node, sent, m.group_id


def submission(gid, author, kind="chat"):
    art = new_article(gid, "" if kind == "chat" else "Hi", "hello",
                      extra=[("Message-Kind", kind), ("Content-Type", "text/plain; charset=utf-8")])
    art.finalize(author, 0)
    return art


def run(ex, *arts):
    async def subs():
        return list(enumerate(arts, 1))
    ex._submissions = subs
    return asyncio.run(ex.run())


def test_a_permitted_submission_goes_out_and_in(tmp_path):
    ex, node, sent, gid = setup(tmp_path)
    st = run(ex, submission(gid, ALICE))
    assert st.exported == 1 and len(sent) == 1 and len(node.posted) == 1
    assert node.posted[0]["Approved-By"] == GW.key_text


def test_banned_author_is_never_sent(tmp_path):
    ex, node, sent, gid = setup(tmp_path, banned=[MALLORY])
    st = run(ex, submission(gid, MALLORY))
    assert st.refused == 1 and sent == [] and node.posted == []


def test_wrong_kind_is_never_sent(tmp_path):
    ex, node, sent, gid = setup(tmp_path, kinds=["post"])
    st = run(ex, submission(gid, ALICE, "chat"))
    assert st.refused == 1 and sent == []


def test_too_little_postage_is_never_sent(tmp_path):
    ex, node, sent, gid = setup(tmp_path, min_pow=12)
    st = run(ex, submission(gid, ALICE))
    assert st.refused == 1 and sent == []
