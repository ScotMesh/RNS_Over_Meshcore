"""
Learning a route from the packets that already arrive.

The radio reports every packet it handled on push 0x88, together with the
repeater hashes that packet crossed. Reverse those and you have the way back,
so raw sends can be routed without a single extra packet on air -- which
matters because CMD_SEND_PATH_DISCOVERY_REQ is accepted and relayed but never
answered on v1.17.1 or on a `main` build, leaving out_path unknown for ever.

The frames below are real, captured from companion firmware on a two-hop
chain in MeshBench. They are fixtures rather than hand-written examples
because the layout was got wrong once already, by reading path_len four bytes
early -- which produced fourteen-hop paths and parsed "successfully".

    pip install rns pytest
    pytest tests/
"""

import os
import sys

import pytest
import RNS
from RNS.Interfaces.Interface import Interface

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
MODULE = os.path.join(HERE, "..", "Interface", "MeshCore_Raw_Interface.py")


def load_module():
    g = {"RNS": RNS, "Interface": Interface, "__name__": "MeshCore_Raw_Interface"}
    with open(MODULE) as fh:
        exec(compile(fh.read(), MODULE, "exec"), g)
    return g


M = load_module()
_Companion = M["_Companion"]

# Captured on a C1 - R1 - R2 - C2 chain. R1 hashes to 0x97, R2 to 0x76.
# C2 hears C1 over [97 76]; C1 hears C2 over [76 97] -- exact mirrors.
TWO_HOP_AT_C2 = bytes.fromhex(
    "88009c189fa60000029776eda6a8f73385157c671a0160060ace28d78e8a47ef"
    "61c112a4774504352f6e834a15182f8f0980a3fc72999f4a58e64c468d13")
TWO_HOP_AT_C1 = bytes.fromhex(
    "88009c181bf80000027697ed1ee895b1b8c75d5b071d57beb67cd511f52eda80"
    "e56a108d8dbef97411ebddf04e2ee674debca68b49df42fe2d23b2f989a6a287"
    "1dd5b37d7e6af09ef58dd0a6dd3a8e165c271789150ac73c8d0a95f344b3")
# One hop: each node also hears its own packet come back off the near repeater.
ONE_HOP_AT_C1 = bytes.fromhex(
    "88009c185cf800000176edc4616baeecef7a65f23e8ae8bb928f3c2a5ba9dece"
    "289cb1fd83b669cb3513c5dce6415121ebcc946021628951d938783a1f10daf1"
    "31bba288fb110334081729aa15")
# A different 0x88 subtype, which is not a packet-path report at all.
OTHER_SUBTYPE = bytes.fromhex(
    "88009c3e0197521051a083d7aeca9dcfc57e00010200c3a6e559a45d9a725994")


def paths_from(frames):
    """Every path the companion parser reports for these frames."""
    got = []
    c = _Companion.__new__(_Companion)
    c.on_packet_path = got.append
    c.contacts = {}
    for f in frames:
        if not f:          # _handle_frame drops these before dispatching
            continue
        _Companion._handle_push(c, f[0], f)
    return got


def test_two_hop_path_is_read_at_the_right_offset():
    assert paths_from([TWO_HOP_AT_C2]) == [bytes([0x97, 0x76])]


def test_each_end_sees_the_mirror_of_the_other():
    out = paths_from([TWO_HOP_AT_C2])[0]
    back = paths_from([TWO_HOP_AT_C1])[0]
    assert bytes(reversed(out)) == back, "the way back is the way in, reversed"


def test_single_hop_is_reported_as_one_hop():
    assert paths_from([ONE_HOP_AT_C1]) == [bytes([0x76])]


def test_other_subtypes_are_left_alone():
    assert paths_from([OTHER_SUBTYPE]) == []


@pytest.mark.parametrize("frame", [
    b"",
    b"\x88",
    TWO_HOP_AT_C2[:9],                                   # truncated mid-path
    TWO_HOP_AT_C2[:3] + b"\xff" + TWO_HOP_AT_C2[4:],     # wrong subtype byte
    TWO_HOP_AT_C2[:6] + b"\x01\x00" + TWO_HOP_AT_C2[8:], # padding not zero
])
def test_malformed_frames_report_nothing(frame):
    assert paths_from([frame]) == []


def test_a_packet_must_follow_the_path():
    # The byte after the path is the MeshCore packet header, 0xed. Without it
    # this is not a packet-path report and the "path" is somebody else's data.
    n = TWO_HOP_AT_C2[8]
    bad = bytearray(TWO_HOP_AT_C2)
    bad[9 + n] = 0x00
    assert paths_from([bytes(bad)]) == []


def test_set_contact_path_writes_hop_count_and_hashes():
    sent = []

    class FakeCompanion(_Companion):
        def __init__(self):
            self.contacts = {}

        async def command(self, frame, want):
            sent.append(frame)
            return bytes([_Companion.RESP_OK])

        def _check(self, resp, what):
            return resp

    import asyncio
    c = FakeCompanion()
    pubkey = bytes(range(32))
    n = asyncio.run(c.set_contact_path(pubkey, bytes([0x76, 0x97])))

    assert n == 2
    frame = sent[0]
    assert frame[0] == _Companion.CMD_ADD_UPDATE_CONTACT
    assert frame[1:33] == pubkey
    # type(1) flags(1) then the path length, which add_contact leaves as
    # OUT_PATH_UNKNOWN and nothing else ever overwrote.
    assert frame[35] == 2
    assert frame[36:38] == bytes([0x76, 0x97])
    assert frame[38:100] == b"\x00" * 62, "path field is padded, not truncated"
