"""
Offline tests for MeshCore_Raw_Interface: framing, command byte layouts,
size budgets, and an end-to-end loopback over a fake companion mesh.

    pip install rns pytest
    pytest tests/
"""

import asyncio
import os
import struct
import sys
import threading
import time

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
_Frame, _Companion, IfaceCls = M["_Frame"], M["_Companion"], M["interface_class"]


# ----------------------------------------------------------------------------- framing

def test_frame_roundtrip_sizes():
    src, dst = b"\x01\x02\x03\x04", b"\xaa\xbb\xcc\xdd"
    for n in (1, 4, 255):
        data = os.urandom(148 * n - 5)
        frags = _Frame.fragments(_Frame.T_DATA, src, dst, 0xBEEF, data, 148, can_route=True)
        assert len(frags) == n
        parsed = [_Frame.parse(f) for f in frags]
        assert all(p is not None for p in parsed)
        assert all(p["src"] == src and p["dst"] == dst and p["pkt_id"] == 0xBEEF for p in parsed)
        assert [p["idx"] for p in parsed] == list(range(n))
        assert all(p["total"] == n and p["can_route"] for p in parsed)
        assert b"".join(p["payload"] for p in parsed) == data
    with pytest.raises(ValueError):
        _Frame.fragments(_Frame.T_DATA, src, dst, 1, os.urandom(148 * 256), 148)


def test_frame_rejects_bad_magic_and_short():
    ok = _Frame.fragments(_Frame.T_DATA, b"\x00" * 4, b"\x00" * 4, 1, b"abcd", 148)[0]
    assert _Frame.parse(ok) is not None
    assert _Frame.parse(b"X" + ok[1:]) is None
    assert _Frame.parse(ok[:13]) is None
    bad_idx = bytearray(ok); bad_idx[12] = 5   # idx >= total
    assert _Frame.parse(bytes(bad_idx)) is None


def test_bind_carries_full_key_and_flags():
    key = os.urandom(32)
    f = _Frame.build(_Frame.T_BIND_REQ, key[:4], _Frame.BROADCAST, 9, [key], can_route=False)[0]
    p = _Frame.parse(f)
    assert p["type"] == _Frame.T_BIND_REQ and p["can_route"] is False and p["payload"] == key
    assert len(f) == 14 + 32 <= _Companion.MAX_GROUP_DATA


# ----------------------------------------------------------------------------- companion frames

class _Capture(_Companion):
    """Companion with the link replaced by a byte sink and a canned reply."""
    def __init__(self, reply=b"\x00"):
        super().__init__({"transport": "tcp"}, lambda *a, **k: None, asyncio.new_event_loop())
        self.connected = True
        self.sent = []
        self.reply = reply

    async def _write_frame(self, data):
        self.sent.append(bytes(data))
        self._handle_frame(self.reply)


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_send_channel_data_layout_matches_firmware():
    # MyMesh.cpp CMD_SEND_CHANNEL_DATA: [62][chan][path_len|0xFF][data_type LE16][payload]
    c = _Capture()
    c.loop = asyncio.new_event_loop()
    c.loop.run_until_complete(c.send_channel_data(3, 0xFFFF, b"hello"))
    assert c.sent[0] == bytes([62, 3, 0xFF]) + b"\xff\xff" + b"hello"


def test_send_raw_data_layout_matches_firmware():
    # MyMesh.cpp CMD_SEND_RAW_DATA: [25][path_len][path][payload>=4]
    c = _Capture(); c.loop = asyncio.new_event_loop()
    c.loop.run_until_complete(c.send_raw_data(b"\x11\x22", b"abcd"))
    assert c.sent[0] == bytes([25, 2, 0x11, 0x22]) + b"abcd"
    with pytest.raises(Exception):
        c.loop.run_until_complete(c.send_raw_data(b"", b"abc"))


def test_path_discovery_and_contact_layouts():
    key = os.urandom(32)
    c = _Capture(reply=bytes([6, 1]) + b"\x00" * 8); c.loop = asyncio.new_event_loop()
    async def go():
        t = asyncio.ensure_future(c.path_discovery(key, timeout=0.2))
        await asyncio.sleep(0.05)
        # firmware push 0x8D: [0x8D][res][pubkey_pre 6][opl][out_path][ipl][in_path]
        c._handle_frame(bytes([0x8D, 0]) + key[:6] + bytes([2]) + b"\xaa\xbb" + bytes([0]))
        return await t
    res = c.loop.run_until_complete(go())
    assert c.sent[0] == bytes([52, 0]) + key
    assert res["out_path_len"] == 2 and res["out_path"] == "aabb"

    c2 = _Capture(); c2.loop = asyncio.new_event_loop()
    c2.loop.run_until_complete(c2.add_contact(key, "RNS-test"))
    f = c2.sent[0]
    assert f[0] == 9 and f[1:33] == key and f[33] == 1 and f[35] == 0xFF and len(f) == 1 + 32 + 3 + 64 + 32 + 12


def test_set_channel_and_appstart_layouts():
    c = _Capture(); c.loop = asyncio.new_event_loop()
    c.loop.run_until_complete(c.set_channel(0, "RNSTunnel", b"\x01" * 16))
    f = c.sent[0]
    assert f[0] == 32 and f[1] == 0 and f[2:34] == b"RNSTunnel".ljust(32, b"\x00") and f[34:50] == b"\x01" * 16
    key = os.urandom(32)
    self_info = bytes([5, 1, 20, 22]) + key + b"\x00" * 22 + b"radio-1"   # 58 fixed bytes, then name
    c3 = _Capture(reply=self_info); c3.loop = asyncio.new_event_loop()
    info = c3.loop.run_until_complete(c3.app_start())
    assert c3.sent[0][:2] == b"\x01\x03" and info["public_key"] == key.hex() and info["name"] == "radio-1"


def test_inbound_parsers():
    got = {}
    c = _Capture(); c.loop = asyncio.new_event_loop()
    c.on_raw_data = lambda p, snr, rssi: got.update(raw=p, snr=snr, rssi=rssi)
    c.on_channel_data = lambda idx, dt, p: got.update(chan=(idx, dt, p))
    c._handle_frame(bytes([0x84, 0x14, 0xC8, 0xFF]) + b"payload")
    assert got["raw"] == b"payload" and got["snr"] == 5.0 and got["rssi"] == -56
    c._handle_frame(bytes([27, 0, 0, 0, 2, 1]) + b"\xff\xff" + bytes([3]) + b"abc")
    assert got["chan"] == (2, 0xFFFF, b"abc")
    key = os.urandom(32)
    frame = bytes([3]) + key + bytes([1, 0, 0x42]) + (b"\x11\x22\x33\x44").ljust(64, b"\x00") + b"n".ljust(32, b"\x00") + b"\x00" * 16
    c._handle_frame(frame)
    ct = c.contacts[key.hex()]
    assert ct["out_path_hash_mode"] == 1 and ct["out_path_len"] == 2 and ct["out_path"] == "11223344"


# ----------------------------------------------------------------------------- path handling & budgets

class _Owner:
    def __init__(self):
        self.received = []
        self.event = threading.Event()
    def inbound(self, data, iface):
        self.received.append(bytes(data)); self.event.set()


def _iface_stub():
    obj = IfaceCls.__new__(IfaceCls)
    return obj


def test_path_for_native_and_1byte_forms():
    ifc = _iface_stub()
    assert ifc._path_for(None) is None
    assert ifc._path_for({"out_path_len": -1}) is None
    assert ifc._path_for({"out_path_len": 0, "out_path": ""}) == (b"", 0)
    one = {"out_path_len": 2, "out_path_hash_mode": 0, "out_path": "aabb"}
    assert ifc._path_for(one) == (b"\xaa\xbb", 2) == ifc._path_for(one, native=False)
    two = {"out_path_len": 2, "out_path_hash_mode": 1, "out_path": "aa11bb22"}
    # firmware dev / openHop: encoded path_len = mode<<6 | hops, full hashes kept
    assert ifc._path_for(two, native=True) == (b"\xaa\x11\xbb\x22", 0x42)
    # firmware v1.17.1: byte count, hashes truncated to their first byte
    assert ifc._path_for(two, native=False) == (b"\xaa\xbb", 2)
    assert ifc._path_for({"out_path_len": 3, "out_path_hash_mode": 1, "out_path": "aa11"}) is None


def test_send_raw_data_encoded_path_len():
    c = _Capture(); c.loop = asyncio.new_event_loop()
    c.loop.run_until_complete(c.send_raw_data(b"\xaa\x11\xbb\x22", b"abcd", 0x42))
    assert c.sent[0] == bytes([25, 0x42, 0xaa, 0x11, 0xbb, 0x22]) + b"abcd"


def test_default_sizes_fit_ble_frames():
    raw_frag = 14 + 140
    assert 2 + 17 + raw_frag <= _Companion.MAX_FRAME          # cmd frame, 17 hops
    assert 4 + raw_frag <= _Companion.MAX_FRAME               # PUSH_CODE_RAW_DATA
    chan_frag = 14 + 148
    assert chan_frag <= _Companion.MAX_GROUP_DATA             # on air
    assert 5 + chan_frag <= _Companion.MAX_FRAME              # CMD_SEND_CHANNEL_DATA
    assert 9 + chan_frag <= _Companion.MAX_FRAME              # RESP_CODE_CHANNEL_DATA_RECV


# ----------------------------------------------------------------------------- loopback

def _rns_packet(ptype, dest_type, dest16, body):
    flags = (dest_type << 2) | ptype           # header type 0, no context flag
    return bytes([flags, 0]) + dest16 + body


def _reticulum_instance(tmp_path_factory):
    """RNS >= 1.5 Interface.__init__ needs a live Reticulum; make a silent, isolated one."""
    if RNS.Reticulum.get_instance() is not None:
        return RNS.Reticulum.get_instance()
    d = tmp_path_factory.mktemp("rns")
    (d / "config").write_text("[reticulum]\n  share_instance = No\n  enable_transport = No\n[logging]\n  loglevel = 1\n[interfaces]\n")
    return RNS.Reticulum(configdir=str(d), loglevel=1)


@pytest.mark.timeout(90)
def test_loopback_two_nodes_over_fake_mesh(tmp_path_factory):
    from fake_companion import FakeMesh
    _reticulum_instance(tmp_path_factory)

    loop = asyncio.new_event_loop()
    mesh = FakeMesh(["alpha", "beta"], base_port=47210)
    loop.run_until_complete(mesh.start())
    t = threading.Thread(target=loop.run_forever, daemon=True); t.start()

    secret = os.urandom(16).hex()
    def cfg(port, name):
        return {"name": name, "transport": "tcp", "host": "127.0.0.1", "tcp_port": port,
                "channel_secret": secret, "fragment_delay": 0.05, "direct_frag_delay": 0.05,
                "path_discovery_rate": 1, "outgoing_announce_rate": 0, "outgoing_path_req_rate": 0,
                "announce_retransmit_extra": 0}
    oa, ob = _Owner(), _Owner()
    IfaceCls.BIND_RESP_WINDOW_S = 3
    IfaceCls.BIND_BACKOFF_MIN, IfaceCls.BIND_BACKOFF_MAX = 0.2, 0.5
    a = IfaceCls(oa, cfg(47210, "A")); b = IfaceCls(ob, cfg(47211, "B"))
    try:
        assert a.online and b.online
        assert a._own_key == mesh.nodes[0].pubkey and b._own_key == mesh.nodes[1].pubkey

        # 1. discovery: both sides bind
        deadline = time.time() + 20
        while time.time() < deadline and not (a._peers and b._peers):
            time.sleep(0.2)
        assert a._peers.get(b._own_prefix) == b._own_key
        assert b._peers.get(a._own_prefix) == a._own_key

        # 2. broadcast: an announce from A reaches B via channel datagrams, reassembled
        dest = os.urandom(16)
        announce = _rns_packet(1, 0, dest, os.urandom(400))
        a.process_outgoing(announce)
        assert ob.event.wait(20) and ob.received[-1] == announce
        assert mesh.nodes[0].sent_channel >= 3 and mesh.nodes[0].sent_raw == 0

        # 3. unicast: B now knows `dest` lives behind A -> raw path after discovery
        assert b._rns_to_peer.get(dest) == a._own_prefix
        data = _rns_packet(0, 0, dest, os.urandom(300))
        oa.event.clear()
        b.process_outgoing(data)                       # first pass: no path yet -> channel + discovery
        assert oa.event.wait(20) and oa.received[-1] == data
        deadline = time.time() + 10
        while time.time() < deadline and b._path_for(b._mc.contact_by_prefix(a._own_prefix.hex())) is None:
            time.sleep(0.2)
        oa.event.clear(); before = mesh.nodes[1].sent_raw
        b.process_outgoing(data)                       # second pass: raw
        assert oa.event.wait(20) and oa.received[-1] == data
        assert mesh.nodes[1].sent_raw >= before + 3

        assert mesh.violations == []
    finally:
        a.detach(); b.detach()
        asyncio.run_coroutine_threadsafe(mesh.stop(), loop).result(5)
        loop.call_soon_threadsafe(loop.stop)
