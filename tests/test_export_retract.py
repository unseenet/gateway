"""A message the other network took is taken back when the node refuses the approved
copy (#18), by the sender that sent it, and only what this gateway sent."""

import asyncio

from unseenet.core.groups import Manifest, make_manifest
from unseenet.nntp import NNTPError
from unseenet_gateway.core.state import State
from unseenet_gateway.core.submissions import Exporter
from unseenet_gateway.matrix.exporter import MatrixSender

from test_export_checks import ALICE, GW, OWNER, run, submission


class RefusingNode:
    def __init__(self, manifest):
        self.m = manifest

    async def manifest(self, gid):
        return self.m

    async def post(self, art):
        raise NNTPError(441, "blocked in this hierarchy")


class Sender:
    def __init__(self, can_retract=True):
        self.sent, self.retracted, self.can = [], [], can_retract

    async def send(self, art):
        self.sent.append(art.message_id)
        return f"$event{len(self.sent)}"

    async def retract(self, art, foreign_id):
        self.retracted.append(foreign_id)
        return self.can


def setup(tmp_path, sender):
    art = make_manifest(OWNER, "matrix.lab.room", "moderated", moderators=[GW.key_text],
                        pow_bits=0, min_pow=0)
    m = Manifest.from_article(art)
    state = State(tmp_path / "gw.db")
    ex = Exporter(state=state, node=RefusingNode(m), gateway=GW,
                  targets={m.group_id: ("matrix", sender.send)}, min_pow=0, delay_max=0)
    return ex, state, m.group_id


def test_refused_by_the_node_is_taken_back(tmp_path):
    sender = Sender()
    ex, state, gid = setup(tmp_path, sender)
    art = submission(gid, ALICE)
    st = run(ex, art)
    assert sender.retracted == ["$event1"]
    assert st.retracted == 1 and st.exported == 0 and st.unmatched == 0
    assert state.foreign_for(art.message_id) is None      # not remembered as exported


def test_when_it_cannot_be_taken_back_it_is_unmatched(tmp_path):
    sender = Sender(can_retract=False)
    ex, state, gid = setup(tmp_path, sender)
    art = submission(gid, ALICE)
    st = run(ex, art)
    assert st.unmatched == 1 and st.retracted == 0 and st.exported == 1
    assert state.foreign_for(art.message_id) is not None


def test_a_sender_without_retract_leaves_it_unmatched(tmp_path):
    sent = []

    async def send(a):
        sent.append(a)
        return "$event1"
    art_m = make_manifest(OWNER, "matrix.lab.room", "moderated", moderators=[GW.key_text],
                          pow_bits=0, min_pow=0)
    m = Manifest.from_article(art_m)
    ex = Exporter(state=State(tmp_path / "gw.db"), node=RefusingNode(m), gateway=GW,
                  targets={m.group_id: ("matrix", send)}, min_pow=0, delay_max=0)
    st = run(ex, submission(m.group_id, ALICE))
    assert st.unmatched == 1 and len(sent) == 1


class FakeMatrix:
    def __init__(self):
        self.redacted = []

    async def redact(self, room_id, event_id, txn, reason=None):
        self.redacted.append(event_id)
        return "$redaction"


def test_matrix_takes_back_only_its_own_events():
    mx = FakeMatrix()

    async def room_id_of(alias):
        return "!room:lab"
    sender = MatrixSender(matrix=mx, state=None, rooms={"g": "#room:lab"}, room_id_of=room_id_of)
    sender._sent.add("$mine")

    class Art:
        group, message_id = "g", "<x@unseenet>"
    assert asyncio.run(sender.retract(Art, "$someone-elses")) is False
    assert asyncio.run(sender.retract(Art, "$mine")) is True
    assert mx.redacted == ["$mine"]


def test_nostr_takes_back_with_a_deletion_of_its_own_event():
    from unseenet_gateway.nostr.exporter import DELETION, NostrSender

    class Relay:
        url = "wss://relay.lab"

        def __init__(self):
            self.events = []

        async def publish(self, ev):
            self.events.append(ev)
            return True, ""
    relay = Relay()
    sender = NostrSender(relay=relay, secret=bytes(range(1, 33)), state=None,
                         groups={"g": "lab-room"})

    class Art:
        group, message_id = "g", "<x@unseenet>"
    assert asyncio.run(sender.retract(Art, "cd" * 32)) is False    # not ours: left alone
    assert relay.events == []
    sender._sent.add("ab" * 32)
    assert asyncio.run(sender.retract(Art, "ab" * 32)) is True
    ev = relay.events[0]
    assert ev.kind == DELETION and ["e", "ab" * 32] in ev.tags and ["h", "lab-room"] in ev.tags
    assert ev.pubkey == sender.pubkey
