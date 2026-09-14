"""
MeshCore_Raw_Interface -- Reticulum over MeshCore using binary payloads.

A Reticulum custom interface that tunnels RNS traffic over a MeshCore mesh
without touching MeshCore's text-message machinery. Fragments travel as:

  * PAYLOAD_TYPE_RAW_CUSTOM (0x0F) packets, sent with CMD_SEND_RAW_DATA (25),
    for unicast traffic to a peer whose repeater path we know. Direct route
    only, no MeshCore encryption or ACK -- RNS already provides both.
  * PAYLOAD_TYPE_GRP_DATA (0x06) channel datagrams, sent with
    CMD_SEND_CHANNEL_DATA (62), for everything that must reach every peer:
    announces, path requests and peer discovery. Flood-routed by repeaters,
    encrypted with the channel secret.

MeshCore firmware rejects flood routing for raw-custom packets and receivers
drop any that arrive by flood, which is why the two primitives are needed.

The file is self-contained: it speaks the companion frame protocol itself
over serial (pyserial), TCP (asyncio) or BLE (bleak), so the same file runs
under rnsd, as a MeshChatX custom interface module, and from a Sideband
service plugin. Frame layouts follow meshcore_py (MIT, Florent de Lamotte)
and were checked against MeshCore firmware v1.17.1 (examples/companion_radio/
MyMesh.cpp) and openHop's virtual companion frame server.

WIRE FORMAT
-----------
Every datagram, on either primitive, starts with a 14-byte tunnel header:

    off size field
    0   1    magic       0x52 ('R')
    1   1    type/flags  low nibble: 0 = RNS fragment, 1 = BIND_REQ, 2 = BIND
                         bit 4: sender can route transit traffic
    2   4    src         first 4 bytes of the sender's MeshCore public key
    6   4    dst         first 4 bytes of the target's key; zeros = broadcast
    10  2    pkt_id      big-endian, per-sender rolling counter
    12  1    frag_idx
    13  1    frag_total
    14  ...  payload     RNS fragment, or BIND body (32-byte full public key)

Raw-custom packets carry no addressing of their own and every radio in
earshot of the final hop hands them to its app, so the dst prefix is what
keeps a fragment from being fed to the wrong Reticulum instance.

SIZES
-----
Companion frames must fit one BLE ATT write (MTU 176 -> 173 bytes), so the
defaults keep every command and push frame at or under 173 bytes:

    raw_payload_size     140  ->  cmd = 2 + hops + 14 + 140  (<= 173 to 17 hops)
    channel_payload_size 148  ->  on air 162 <= MAX_GROUP_DATA_LENGTH (165)

A 500-byte RNS packet is 4 fragments instead of the 8 the text tunnel needs.

CONFIGURATION
-------------
  [[MeshCore Raw]]
    type = MeshCore_Raw_Interface
    interface_enabled = yes
    mode = access_point

    transport = tcp            # tcp | serial | ble
    host = 127.0.0.1           # tcp: companion (or openHop virtual companion)
    tcp_port = 5000
    port = /dev/ttyUSB0        # serial
    baudrate = 115200
    ble_name =                 # ble: substring of the advertised name, or
    ble_address =              #      a MAC / UUID. Blank = first MeshCore found
    ble_pin =                  # optional pairing PIN

    channel_idx = 0
    channel_name = RNSTunnel
    channel_secret = <32 hex characters>   # openssl rand -hex 16
    data_type = 0xFFFF         # GRP_DATA data_type; 0xFFFF is the app namespace

    raw_payload_size = 140
    channel_payload_size = 148
    fragment_delay = 2.5
    direct_frag_delay = 0.5
    fragment_timeout = 300
    outgoing_announce_rate = 600
    outgoing_path_req_rate = 1800
    announce_max_hops = 2      # see "Announce hop limit" below
    rate_limit = 0
    allow_direct = yes
    raw_path_hashes = auto     # auto | native | 1byte -- see "Raw paths" below
    path_discovery_rate = 600
    path_discovery_timeout = 20
    advert_on_start = yes
    can_route = yes
    peer_ttl = 86400
    debug_level = info

RAW PATHS
---------
CMD_SEND_RAW_DATA takes the repeater path plus a path_len byte. Firmware
v1.17.1 (release) reads that byte as a plain byte count, so only 1-byte
repeater hashes work; firmware `dev` and openHop read MeshCore's encoded
form (hash_mode << 6 | hops) and accept multi-byte hashes. For 1-byte-hash
paths the two agree. With raw_path_hashes = auto the interface sends the
contact's native hash size and, if the radio rejects it, truncates every hop
to its first byte for the rest of the session (a 1-byte hash is a prefix of
the longer one, so repeaters still match, with a slightly higher collision
risk).

Requires companion firmware with CMD_SEND_RAW_DATA and CMD_SEND_CHANNEL_DATA
(v1.17 has both) or openHop's virtual companion. Older firmware answers those
commands with ERR_CODE_UNSUPPORTED_CMD; the interface logs that and keeps
running channel-only (text-tunnel peers are NOT compatible with this format).

ANNOUNCE HOP LIMIT
-------------------
On a Reticulum transport node (enable_transport = yes), this interface's
"mode" setting controls announce propagation same as any RNS interface. The
restrictive modes (access_point, internal, roaming, boundary) block proactive
announce broadcast outright; every other mode -- including full and gateway --
lets RNS relay an individual announce for every destination the transport
node knows about as each one periodically re-announces. On a node that also
carries a large backbone (thousands of known routes via other interfaces),
running this interface in one of those less-restrictive modes means all of
that route table eventually gets announced onto this MeshCore channel too --
observed directly during development of this feature: switching a transport
node's MeshCore interface to full mode produced a sustained ~30 packets/minute
of announce traffic onto a real, shared community LoRa channel serving other
operators' traffic.

announce_max_hops caps this independently of whatever mode allows: any
outgoing announce that has already travelled more than the configured number
of RNS hops to reach this node is dropped before it reaches the radio, in
process_outgoing(), regardless of the interface's mode. Path responses are
exempt, so on-demand path lookups for far-away destinations still work; only
proactive re-announces are capped. Default is 2 hops. Set higher for more
reach at the cost of relaying more of what a transport node's other
interfaces bring in, or unset (announce_max_hops = 0 disables the check
entirely) if you understand the tradeoff and want it off, e.g. on a node
that isn't also a transport node for another large network.
"""

import asyncio
import hashlib
import queue
import random
import struct
import threading
import time

import RNS

try:
    Interface  # injected by RNS's external-interface loader (and by the Sideband plugin)
except NameError:  # imported directly (tests, other hosts)
    from RNS.Interfaces.Interface import Interface


# =============================================================================
# Tunnel framing
# =============================================================================

class _Frame:
    """Pure functions for the 14-byte tunnel header."""

    MAGIC       = 0x52
    HEADER_SIZE = 14
    HDR_FMT     = ">BB4s4sHBB"

    T_DATA     = 0
    T_BIND_REQ = 1
    T_BIND     = 2
    F_ROUTER   = 0x10

    BROADCAST = b"\x00\x00\x00\x00"

    @classmethod
    def build(cls, ftype, src, dst, pkt_id, chunks, can_route=False):
        """Return the list of datagrams for one logical packet."""
        flags = (ftype & 0x0F) | (cls.F_ROUTER if can_route else 0)
        total = len(chunks)
        if total == 0 or total > 255:
            raise ValueError("fragment count out of range")
        return [
            struct.pack(cls.HDR_FMT, cls.MAGIC, flags, src, dst,
                        pkt_id & 0xFFFF, idx, total) + chunk
            for idx, chunk in enumerate(chunks)
        ]

    @classmethod
    def fragments(cls, ftype, src, dst, pkt_id, data, payload_size, can_route=False):
        chunks = [data[i:i + payload_size] for i in range(0, len(data), payload_size)] or [b""]
        return cls.build(ftype, src, dst, pkt_id, chunks, can_route)

    @classmethod
    def parse(cls, data):
        """-> dict or None. Does not apply src/dst policy; the caller does."""
        if len(data) < cls.HEADER_SIZE:
            return None
        magic, flags, src, dst, pkt_id, idx, total = struct.unpack(cls.HDR_FMT, data[:cls.HEADER_SIZE])
        if magic != cls.MAGIC or total == 0 or idx >= total:
            return None
        return {
            "type": flags & 0x0F, "can_route": bool(flags & cls.F_ROUTER),
            "src": src, "dst": dst, "pkt_id": pkt_id, "idx": idx, "total": total,
            "payload": data[cls.HEADER_SIZE:],
        }


# =============================================================================
# Minimal companion-protocol client
# =============================================================================

class _CompanionError(Exception):
    pass


def region_scope_key(name):
    """16-byte MeshCore transport key for a public region/scope name.

    ``sha256("#" + name)[:16]`` - matches firmware's
    ``TransportKeyStore::getAutoKeyFor`` and openhop_core's
    ``get_auto_key_for``/``set_flood_region``, so a name like ``"sco"`` here
    reproduces exactly the key an openHop repeater derives from
    ``mesh.default_region: sco`` (see ``region_map_builder.py`` upstream) or a
    real MeshCore repeater's region config. Only for *public* regions - one
    whose name does not start with ``$``; a private ``$region`` is keyed with
    material the name can't reproduce, so use ``flood_scope_key`` (a literal
    32-hex-char key) for those instead.
    """
    canonical = name if name.startswith("#") else f"#{name}"
    if len(canonical) > 64:
        raise ValueError("region/scope name too long (max 64 characters)")
    return hashlib.sha256(canonical.encode("ascii")).digest()[:16]


class _Companion:
    """
    Just enough of the MeshCore companion protocol for this interface.

    Frames: serial and TCP wrap each frame as '<' + LE16 length + data
    (app -> radio) and '>' + LE16 length + data (radio -> app). BLE carries
    one bare frame per ATT write / notification.
    """

    # commands
    CMD_APP_START            = 1
    CMD_GET_CONTACTS         = 4
    CMD_SEND_SELF_ADVERT     = 7
    CMD_ADD_UPDATE_CONTACT   = 9
    CMD_SYNC_NEXT_MESSAGE    = 10
    CMD_DEVICE_QUERY         = 22
    CMD_SEND_RAW_DATA        = 25
    CMD_GET_CHANNEL          = 31
    CMD_SET_CHANNEL          = 32
    CMD_SEND_PATH_DISCOVERY  = 52
    CMD_SET_FLOOD_SCOPE      = 54
    CMD_SEND_CHANNEL_DATA    = 62
    CMD_SET_DEFAULT_FLOOD_SCOPE = 63

    # responses
    RESP_OK                  = 0
    RESP_ERR                 = 1
    RESP_CONTACT_START       = 2
    RESP_CONTACT             = 3
    RESP_CONTACT_END         = 4
    RESP_SELF_INFO           = 5
    RESP_SENT                = 6
    RESP_CONTACT_MSG_RECV    = 7
    RESP_CHANNEL_MSG_RECV    = 8
    RESP_NO_MORE_MSGS        = 10
    RESP_DEVICE_INFO         = 13
    RESP_CONTACT_MSG_RECV_V3 = 16
    RESP_CHANNEL_MSG_RECV_V3 = 17
    RESP_CHANNEL_INFO        = 18
    RESP_CHANNEL_DATA_RECV   = 27

    # pushes
    PUSH_ADVERT              = 0x80
    PUSH_PATH_UPDATED        = 0x81
    PUSH_MSG_WAITING         = 0x83
    PUSH_RAW_DATA            = 0x84
    PUSH_NEW_ADVERT          = 0x8A
    PUSH_PATH_DISCOVERY_RESP = 0x8D

    ERR_NAMES = {1: "UNSUPPORTED_CMD", 2: "NOT_FOUND", 3: "TABLE_FULL",
                 4: "BAD_STATE", 5: "FILE_IO_ERROR", 6: "ILLEGAL_ARG"}

    OUT_PATH_UNKNOWN = 0xFF
    MAX_FRAME        = 173     # one BLE ATT write at the firmware's MTU of 176
    MAX_GROUP_DATA   = 165     # MAX_PACKET_PAYLOAD - CIPHER_BLOCK_SIZE - 3
    SYNC_MSG_CODES   = (7, 8, 16, 17, 27, 10)

    BLE_SERVICE = "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
    BLE_RX_CHAR = "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"   # app -> radio
    BLE_TX_CHAR = "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"   # radio -> app

    def __init__(self, cfg, log, loop):
        self.cfg  = cfg
        self.log  = log
        self.loop = loop
        self.transport = cfg["transport"]

        self.connected = False
        self.self_info = {}
        self.contacts  = {}          # pubkey hex -> contact dict

        self._cmd_lock   = asyncio.Lock()
        self._waiter     = None      # (set_of_codes, future)
        self._disc_waits = {}        # pubkey prefix(12 hex) -> future
        self._rxbuf      = b""
        self._contact_batch = {}
        self._sync_task  = None
        self._sync_pending = False

        # callbacks set by the interface
        self.on_raw_data     = None  # (payload: bytes, snr, rssi)
        self.on_channel_data = None  # (chan_idx, data_type, payload: bytes)
        self.on_disconnect   = None

        # transport handles
        self._serial = None
        self._serial_thread = None
        self._tcp_writer = None
        self._tcp_reader_task = None
        self._ble = None
        self._ble_rx_char = None
        self._closing = False

    # ---------------------------------------------------------------- connect

    async def connect(self):
        self._closing = False
        if self.transport == "tcp":
            await self._connect_tcp()
        elif self.transport == "serial":
            await self._connect_serial()
        elif self.transport == "ble":
            await self._connect_ble()
        else:
            raise _CompanionError(f"unknown transport '{self.transport}'")
        self.connected = True

    async def close(self):
        self._closing = True
        self.connected = False
        try:
            if self._tcp_writer:
                self._tcp_writer.close()
            if self._serial:
                self._serial.close()
            if self._ble:
                await self._ble.disconnect()
        except Exception:
            pass

    async def _connect_tcp(self):
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.cfg["host"], self.cfg["tcp_port"]), timeout=15)
        self._tcp_writer = writer

        async def _reader():
            try:
                while not self._closing:
                    data = await reader.read(4096)
                    if not data:
                        break
                    self._feed_framed(data)
            except Exception as e:
                self.log(f"TCP reader ended: {e}", RNS.LOG_DEBUG)
            self._lost()

        self._tcp_reader_task = self.loop.create_task(_reader())

    async def _connect_serial(self):
        import serial  # pyserial
        self._serial = serial.Serial(self.cfg["port"], self.cfg["baudrate"], timeout=0.2)
        try:
            self._serial.rts = False
        except Exception:
            pass

        def _reader():
            try:
                while not self._closing and self._serial.is_open:
                    data = self._serial.read(512)
                    if data:
                        self.loop.call_soon_threadsafe(self._feed_framed, data)
            except Exception as e:
                self.loop.call_soon_threadsafe(self.log, f"serial reader ended: {e}", RNS.LOG_DEBUG)
            self.loop.call_soon_threadsafe(self._lost)

        self._serial_thread = threading.Thread(target=_reader, daemon=True, name="MCRaw-serial")
        self._serial_thread.start()

    async def _connect_ble(self):
        from bleak import BleakClient, BleakScanner

        want_name = (self.cfg.get("ble_name") or "").strip()
        want_addr = (self.cfg.get("ble_address") or "").strip()

        def _match(dev, adv):
            name = (adv.local_name or dev.name or "")
            if want_addr and dev.address.lower() == want_addr.lower():
                return True
            if not name.startswith("MeshCore"):
                return False
            return (want_name in name) if want_name else True

        self.log("BLE: scanning for a MeshCore companion...", RNS.LOG_INFO)
        device = await BleakScanner.find_device_by_filter(_match, timeout=20)
        if device is None:
            raise _CompanionError("no MeshCore BLE device found")

        def _on_disc(_client):
            self.loop.call_soon_threadsafe(self._lost)

        client = BleakClient(device, disconnected_callback=_on_disc)
        await client.connect()
        pin = (self.cfg.get("ble_pin") or "").strip()
        if pin:
            try:
                await client.pair()
            except Exception as e:
                await client.disconnect()
                raise _CompanionError(f"BLE pairing failed: {e}")

        nus = client.services.get_service(self.BLE_SERVICE)
        if nus is None:
            await client.disconnect()
            raise _CompanionError("BLE device has no Nordic UART service")
        self._ble_rx_char = nus.get_characteristic(self.BLE_RX_CHAR)

        def _notify(_char, data):
            # BLE delivers whole frames, no length prefix
            self.loop.call_soon_threadsafe(self._handle_frame, bytes(data))

        await client.start_notify(self.BLE_TX_CHAR, _notify)
        self._ble = client
        self.log(f"BLE: connected to {device.name} [{device.address}]", RNS.LOG_INFO)

    def _lost(self):
        if not self.connected:
            return
        self.connected = False
        self._fail_waiters("connection lost")
        if self.on_disconnect and not self._closing:
            self.loop.create_task(self.on_disconnect())

    # ---------------------------------------------------------------- framing

    def _feed_framed(self, data):
        """Serial/TCP byte stream -> frames ('>' + LE16 len + payload)."""
        self._rxbuf += data
        while True:
            start = self._rxbuf.find(b">")
            if start < 0:
                self._rxbuf = b""
                return
            if start > 0:
                self._rxbuf = self._rxbuf[start:]
            if len(self._rxbuf) < 3:
                return
            flen = int.from_bytes(self._rxbuf[1:3], "little")
            if flen == 0 or flen > 300:
                self._rxbuf = self._rxbuf[1:]      # not a real header, resync
                continue
            if len(self._rxbuf) < 3 + flen:
                return
            frame = self._rxbuf[3:3 + flen]
            self._rxbuf = self._rxbuf[3 + flen:]
            self._handle_frame(frame)

    async def _write_frame(self, data):
        if len(data) > self.MAX_FRAME:
            raise _CompanionError(f"frame too long ({len(data)} > {self.MAX_FRAME})")
        if self.transport == "ble":
            await self._ble.write_gatt_char(self._ble_rx_char, bytes(data), response=True)
            return
        wire = b"<" + len(data).to_bytes(2, "little") + bytes(data)
        if self.transport == "tcp":
            self._tcp_writer.write(wire)
            await self._tcp_writer.drain()
        else:
            await self.loop.run_in_executor(None, self._serial.write, wire)

    # ---------------------------------------------------------------- commands

    async def command(self, data, expect, timeout=8.0):
        """Send one command frame and return the first response whose code is in `expect`."""
        if not self.connected:
            raise _CompanionError("not connected")
        expect = set(expect)
        async with self._cmd_lock:
            fut = self.loop.create_future()
            self._waiter = (expect, fut)
            try:
                await self._write_frame(data)
                return await asyncio.wait_for(fut, timeout)
            finally:
                self._waiter = None

    def _fail_waiters(self, reason):
        if self._waiter and not self._waiter[1].done():
            self._waiter[1].set_exception(_CompanionError(reason))
        for fut in self._disc_waits.values():
            if not fut.done():
                fut.set_exception(_CompanionError(reason))
        self._disc_waits.clear()

    def _check(self, resp, what):
        """Raise on an ERR frame; return the frame otherwise."""
        if resp[0] == self.RESP_ERR:
            code = resp[1] if len(resp) > 1 else -1
            raise _CompanionError(f"{what}: ERR_CODE_{self.ERR_NAMES.get(code, code)}")
        return resp

    async def app_start(self):
        resp = self._check(await self.command(
            b"\x01\x03" + b" " * 6 + b"rnsraw", (self.RESP_SELF_INFO, self.RESP_ERR)), "APP_START")
        # code(1) adv_type(1) tx(1) max_tx(1) pubkey(32) lat(4) lon(4) multi_acks(1)
        # loc_policy(1) telemetry(1) manual_add(1) freq(4) bw(4) sf(1) cr(1) name...
        info = {"public_key": resp[4:36].hex()}
        if len(resp) > 58:
            info["name"] = resp[58:].split(b"\x00")[0].decode("utf-8", "ignore")
        else:
            info["name"] = ""
        self.self_info = info
        return info

    async def device_query(self):
        try:
            resp = await self.command(b"\x16\x03", (self.RESP_DEVICE_INFO, self.RESP_ERR), timeout=5)
        except Exception:
            return {}
        if resp[0] != self.RESP_DEVICE_INFO:
            return {}
        # code(1) fw_ver(1) max_contacts/? ... firmware-version string lives further in;
        # keep only what we can rely on across versions.
        return {"fw_ver_code": resp[1] if len(resp) > 1 else None, "raw": resp.hex()}

    async def set_channel(self, idx, name, secret16):
        name_b = name.encode("utf-8")[:32].ljust(32, b"\x00")
        frame = bytes([self.CMD_SET_CHANNEL, idx]) + name_b + secret16
        return self._check(await self.command(frame, (self.RESP_OK, self.RESP_ERR)), "SET_CHANNEL")

    async def set_flood_scope(self, key16):
        """CMD_SET_FLOOD_SCOPE_KEY, mode 0: set this companion's transient flood
        scope override. Every subsequent flood send (channel datagrams, self
        adverts, BIND/BIND_REQ broadcasts) carries this key's transport codes
        instead of going out unscoped, so a repeater with a matching named
        region (or ``mesh.default_region``, on openHop) will relay it while one
        scoped/configured for a different region silently won't.
        `key16` of None resets to unscoped (mirrors firmware's else-branch for
        a mode-0 frame with no key bytes)."""
        frame = bytes([self.CMD_SET_FLOOD_SCOPE, 0]) + (key16 if key16 else b"")
        return self._check(await self.command(frame, (self.RESP_OK, self.RESP_ERR)), "SET_FLOOD_SCOPE")

    async def set_default_flood_scope(self, name, key16):
        """CMD_SET_DEFAULT_FLOOD_SCOPE (63): the *persistent* scope self-adverts
        and other firmware auto-replies use - separate from set_flood_scope's
        transient per-session override, which SEND_SELF_ADVERT does not consult
        (confirmed in openhop_core: advertise() calls _apply_default_flood_scope,
        never the transient key). Both need setting for every flood this
        companion originates to actually carry the same scope.
        `name` of None/empty clears it (mirrors firmware's short-frame branch)."""
        if name:
            name_b = name.encode("utf-8")[:31].ljust(31, b"\x00")
            frame = bytes([self.CMD_SET_DEFAULT_FLOOD_SCOPE]) + name_b + key16
        else:
            frame = bytes([self.CMD_SET_DEFAULT_FLOOD_SCOPE])
        return self._check(await self.command(frame, (self.RESP_OK, self.RESP_ERR)), "SET_DEFAULT_FLOOD_SCOPE")

    async def send_advert(self, flood=True):
        frame = bytes([self.CMD_SEND_SELF_ADVERT]) + (b"\x01" if flood else b"")
        return self._check(await self.command(frame, (self.RESP_OK, self.RESP_ERR)), "SEND_SELF_ADVERT")

    async def get_contacts(self, timeout=20.0):
        """Full contact download. Returns the refreshed cache."""
        if not self.connected:
            raise _CompanionError("not connected")
        async with self._cmd_lock:
            fut = self.loop.create_future()
            self._waiter = ({self.RESP_CONTACT_END, self.RESP_ERR}, fut)
            self._contact_batch = {}
            try:
                await self._write_frame(bytes([self.CMD_GET_CONTACTS]))
                resp = await asyncio.wait_for(fut, timeout)
            finally:
                self._waiter = None
        if resp[0] == self.RESP_ERR:
            raise _CompanionError("GET_CONTACTS failed")
        self.contacts = getattr(self, "_contact_batch", {})
        return self.contacts

    async def add_contact(self, pubkey32, name):
        """CMD_ADD_UPDATE_CONTACT with an unknown out-path (flood) for a chat node."""
        name_b = name.encode("utf-8")[:32].ljust(32, b"\x00")
        frame = (bytes([self.CMD_ADD_UPDATE_CONTACT]) + pubkey32
                 + b"\x01"                             # type: CHAT
                 + b"\x00"                             # flags
                 + bytes([self.OUT_PATH_UNKNOWN])
                 + b"\x00" * 64
                 + name_b
                 + int(time.time()).to_bytes(4, "little")
                 + b"\x00" * 8)                        # lat, lon
        resp = self._check(await self.command(frame, (self.RESP_OK, self.RESP_ERR)), "ADD_UPDATE_CONTACT")
        self.contacts[pubkey32.hex()] = {
            "public_key": pubkey32.hex(), "type": 1, "flags": 0,
            "out_path_len": -1, "out_path_hash_mode": -1, "out_path": "", "adv_name": name,
        }
        return resp

    async def send_channel_data(self, chan_idx, data_type, payload):
        if len(payload) > self.MAX_GROUP_DATA:
            raise _CompanionError("channel payload too long")
        frame = (bytes([self.CMD_SEND_CHANNEL_DATA, chan_idx, self.OUT_PATH_UNKNOWN])
                 + (data_type & 0xFFFF).to_bytes(2, "little") + payload)
        return self._check(await self.command(frame, (self.RESP_OK, self.RESP_ERR)), "SEND_CHANNEL_DATA")

    async def send_raw_data(self, path, payload, path_len_byte=None):
        """
        CMD_SEND_RAW_DATA. `path_len_byte` is the value written to the frame:
        firmware v1.17.1 reads it as a byte count (1-byte hashes only); firmware
        `dev` and openHop read it as MeshCore's encoded form, hash-mode << 6 |
        hop count. For 1-byte-hash paths the two are the same number.
        """
        if len(payload) < 4:
            raise _CompanionError("raw payload must be at least 4 bytes")
        if len(path) > 64:
            raise _CompanionError("path too long")
        if path_len_byte is None:
            path_len_byte = len(path)
        frame = bytes([self.CMD_SEND_RAW_DATA, path_len_byte & 0xFF]) + path + payload
        return self._check(await self.command(frame, (self.RESP_OK, self.RESP_ERR)), "SEND_RAW_DATA")

    async def path_discovery(self, pubkey32, timeout=20.0):
        """Ask the radio to discover a path to `pubkey32`. Returns the 0x8D result or None."""
        prefix = pubkey32[:6].hex()
        fut = self.loop.create_future()
        self._disc_waits[prefix] = fut
        try:
            resp = await self.command(bytes([self.CMD_SEND_PATH_DISCOVERY, 0]) + pubkey32,
                                      (self.RESP_SENT, self.RESP_ERR))
            self._check(resp, "SEND_PATH_DISCOVERY_REQ")
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            return None
        finally:
            self._disc_waits.pop(prefix, None)

    # ---------------------------------------------------------------- inbound

    def _handle_frame(self, frame):
        if not frame:
            return
        code = frame[0]
        try:
            if code >= 0x80:
                self._handle_push(code, frame)
                return

            if code == self.RESP_CONTACT_START:
                self._contact_batch = {}
                return
            if code == self.RESP_CONTACT:
                c = self._parse_contact(frame)
                if c:
                    self._contact_batch[c["public_key"]] = c
                    self.contacts[c["public_key"]] = c
                return
            if code == self.RESP_CHANNEL_DATA_RECV:
                self._handle_channel_data(frame)
            elif code in self.SYNC_MSG_CODES and code != self.RESP_NO_MORE_MSGS:
                pass  # text messages on the channel / to this node: not ours, drop

            if self._waiter is not None:
                expect, fut = self._waiter
                if code in expect and not fut.done():
                    fut.set_result(frame)
                    return
            if code not in self.SYNC_MSG_CODES:
                self.log(f"unexpected response code 0x{code:02x} ({len(frame)}b)", RNS.LOG_DEBUG)
        except Exception as e:
            self.log(f"frame handler error on code 0x{code:02x}: {e}", RNS.LOG_DEBUG)

    def _handle_push(self, code, frame):
        if code == self.PUSH_MSG_WAITING:
            self._schedule_sync()
        elif code == self.PUSH_RAW_DATA:
            if len(frame) >= 4 and self.on_raw_data:
                snr  = int.from_bytes(frame[1:2], "little", signed=True) / 4
                rssi = int.from_bytes(frame[2:3], "little", signed=True)
                self.on_raw_data(frame[4:], snr, rssi)
        elif code in (self.PUSH_NEW_ADVERT, self.PUSH_ADVERT):
            c = self._parse_contact(frame)
            if c:
                self.contacts[c["public_key"]] = c
        elif code == self.PUSH_PATH_UPDATED:
            self._schedule_contact_refresh()
        elif code == self.PUSH_PATH_DISCOVERY_RESP:
            res = self._parse_path_discovery(frame)
            if res:
                self._apply_discovered_path(res)
                fut = self._disc_waits.get(res["pubkey_pre"])
                if fut and not fut.done():
                    fut.set_result(res)

    def _handle_channel_data(self, frame):
        # code(1) snr(1) res(2) chan(1) path_len(1) data_type(2 LE) data_len(1) payload
        if len(frame) < 9:
            return
        chan_idx  = frame[4]
        data_type = int.from_bytes(frame[6:8], "little")
        dlen      = frame[8]
        payload   = frame[9:9 + dlen]
        if self.on_channel_data:
            self.on_channel_data(chan_idx, data_type, payload)

    def _parse_contact(self, frame):
        # code(1) pubkey(32) type(1) flags(1) path_len(1) path(64) name(32) last_advert(4) lat(4) lon(4) [lastmod(4)]
        if len(frame) < 1 + 32 + 3 + 64 + 32:
            return None
        pk   = frame[1:33].hex()
        plen = frame[35]
        c = {"public_key": pk, "type": frame[33], "flags": frame[34]}
        if plen == self.OUT_PATH_UNKNOWN:
            c["out_path_hash_mode"] = -1
            c["out_path_len"] = -1
            c["out_path"] = ""
        else:
            mode  = plen >> 6
            count = plen & 0x3F
            c["out_path_hash_mode"] = mode
            c["out_path_len"] = count
            c["out_path"] = frame[36:36 + count * (mode + 1)].hex()
        c["adv_name"] = frame[100:132].split(b"\x00")[0].decode("utf-8", "ignore")
        return c

    def _parse_path_discovery(self, frame):
        # code(1) reserved(1) pubkey_pre(6) opl(1) out_path ipl(1) in_path
        if len(frame) < 9:
            return None
        i = 2
        pre = frame[i:i + 6].hex(); i += 6
        opl = frame[i]; i += 1
        o_mode, o_cnt = opl >> 6, opl & 0x3F
        out_path = frame[i:i + o_cnt * (o_mode + 1)]; i += o_cnt * (o_mode + 1)
        return {"pubkey_pre": pre, "out_path_hash_mode": o_mode, "out_path_len": o_cnt,
                "out_path": out_path.hex()}

    def _apply_discovered_path(self, res):
        for pk, c in self.contacts.items():
            if pk.startswith(res["pubkey_pre"]):
                c["out_path_hash_mode"] = res["out_path_hash_mode"]
                c["out_path_len"] = res["out_path_len"]
                c["out_path"] = res["out_path"]

    def _schedule_sync(self):
        """Drain queued messages (CHANNEL_DATA_RECV arrives this way)."""
        self._sync_pending = True
        if self._sync_task is None or self._sync_task.done():
            self._sync_task = self.loop.create_task(self._sync_drain())

    async def _sync_drain(self):
        while self._sync_pending and self.connected:
            self._sync_pending = False
            for _ in range(64):
                try:
                    resp = await self.command(bytes([self.CMD_SYNC_NEXT_MESSAGE]),
                                              set(self.SYNC_MSG_CODES) | {self.RESP_ERR}, timeout=6)
                except Exception as e:
                    self.log(f"message sync stopped: {e}", RNS.LOG_DEBUG)
                    return
                if resp[0] in (self.RESP_NO_MORE_MSGS, self.RESP_ERR):
                    break

    def _schedule_contact_refresh(self):
        async def _refresh():
            await asyncio.sleep(0.5)
            try:
                await self.get_contacts()
            except Exception as e:
                self.log(f"contact refresh failed: {e}", RNS.LOG_DEBUG)
        self.loop.create_task(_refresh())

    def contact_by_prefix(self, prefix_hex):
        for pk, c in self.contacts.items():
            if pk.startswith(prefix_hex):
                return c
        return None


# =============================================================================
# The interface
# =============================================================================

class MeshCore_Raw_Interface(Interface):

    DEFAULT_IFAC_SIZE   = 8
    DEFAULT_IFAC_NAME   = ""
    DEFAULT_IFAC_NETKEY = b""

    OUTQUEUE_MAXSIZE = 512
    SETUP_TIMEOUT_S  = 45
    RECONNECT_MIN_S  = 5
    RECONNECT_MAX_S  = 120

    BIND_BACKOFF_MIN   =  3.0
    BIND_BACKOFF_MAX   = 15.0
    BIND_HEARTBEAT_S   = 3600.0
    BIND_RESP_WINDOW_S = 60.0
    BIND_MAX_RETRIES   = 3
    UNBOUND_REQ_RETRY_S = 120.0

    DEDUPLICATION_TTL_S = 30.0

    _RNS_DST_LEN = 16
    _RNS_PTYPE_DATA     = 0x00
    _RNS_PTYPE_ANNOUNCE = 0x01
    _RNS_PTYPE_LINK_REQ = 0x02
    _RNS_PTYPE_PROOF    = 0x03
    _RNS_DTYPE_SINGLE = 0x00
    _RNS_DTYPE_GROUP  = 0x01
    _RNS_DTYPE_PLAIN  = 0x02
    _RNS_DTYPE_LINK   = 0x03

    _RNS_MAP_MAX = 512
    _PENDING_TOKENS_MAX_SENDERS    = 64
    _PENDING_TOKENS_MAX_PER_SENDER = 16

    # ---------------------------------------------------------------- init

    def __init__(self, owner, configuration):
        super().__init__()
        self.owner = owner
        cfg = configuration
        self.name = cfg.get("name", "MeshCore Raw")

        def _bool(key, default="yes"):
            return str(cfg.get(key, default)).strip().lower() not in ("no", "false", "0", "off")

        # transport
        self.transport = str(cfg.get("transport", "tcp")).strip().lower()
        self.link_cfg = {
            "transport":   self.transport,
            "host":        cfg.get("host", "127.0.0.1"),
            "tcp_port":    int(cfg.get("tcp_port", 5000)),
            "port":        cfg.get("port", "/dev/ttyUSB0"),
            "baudrate":    int(cfg.get("baudrate", 115200)),
            "ble_name":    cfg.get("ble_name", ""),
            "ble_address": cfg.get("ble_address", ""),
            "ble_pin":     cfg.get("ble_pin", ""),
        }

        # channel
        self.channel_idx    = int(str(cfg.get("channel_idx", 0)).strip())
        self.channel_name   = cfg.get("channel_name", "RNSTunnel")
        self.channel_secret = bytes.fromhex(str(cfg.get("channel_secret", "00" * 16)).strip())
        if len(self.channel_secret) != 16:
            raise ValueError("channel_secret must be 32 hex characters (16 bytes)")
        self.data_type = int(str(cfg.get("data_type", "0xFFFF")).strip(), 0) & 0xFFFF
        if self.data_type == 0:
            raise ValueError("data_type 0 is reserved by MeshCore")

        # flood scope - confines flood sends (adverts, BIND broadcasts, channel
        # datagrams) to a named MeshCore region, e.g. "sco". Unset = unscoped,
        # today's behaviour. flood_scope_key (32 hex chars) overrides the
        # derived key for a private "$region" whose key the name can't
        # reproduce; flood_scope alone is enough for a public region name.
        flood_scope = str(cfg.get("flood_scope", "")).strip()
        flood_scope_key = str(cfg.get("flood_scope_key", "")).strip()
        if flood_scope_key:
            self.flood_scope_key = bytes.fromhex(flood_scope_key)
            if len(self.flood_scope_key) != 16:
                raise ValueError("flood_scope_key must be 32 hex characters (16 bytes)")
        elif flood_scope:
            self.flood_scope_key = region_scope_key(flood_scope)
        else:
            self.flood_scope_key = None
        self.flood_scope_name = flood_scope or None

        # sizes
        self.raw_payload_size     = int(cfg.get("raw_payload_size", 140))
        self.channel_payload_size = int(cfg.get("channel_payload_size", 148))
        if self.channel_payload_size + _Frame.HEADER_SIZE > _Companion.MAX_GROUP_DATA:
            raise ValueError(f"channel_payload_size must be <= {_Companion.MAX_GROUP_DATA - _Frame.HEADER_SIZE}")
        if self.raw_payload_size + _Frame.HEADER_SIZE + 2 > _Companion.MAX_FRAME:
            raise ValueError(f"raw_payload_size must be <= {_Companion.MAX_FRAME - _Frame.HEADER_SIZE - 2}")

        # pacing / limits
        self.fragment_delay_s    = float(cfg.get("fragment_delay", 2.5))
        self.direct_frag_delay_s = float(cfg.get("direct_frag_delay", 0.5))
        self.fragment_timeout_s  = float(cfg.get("fragment_timeout", 300.0))
        self.rate_limit_bps      = int(cfg.get("rate_limit", 0))
        self._announce_rate_s    = float(cfg.get("outgoing_announce_rate", 600))
        self._path_req_rate_s    = float(cfg.get("outgoing_path_req_rate", 1800))
        self._path_req_burst_window_s = float(cfg.get("path_req_burst_window", 60))
        self._path_response_bypass_s  = float(cfg.get("path_response_bypass_window", 15))
        self.announce_retransmit_extra = int(cfg.get("announce_retransmit_extra", 2))
        self.path_req_retransmit_extra = int(cfg.get("path_req_retransmit_extra", 0))
        # See "ANNOUNCE HOP LIMIT" above. Defaults on: a transport node that
        # picks a less-restrictive mode (full, gateway, ...) without setting
        # this can end up relaying its entire known route table onto a shared
        # channel. 0 disables the check for callers who understand the tradeoff.
        self.announce_max_hops = int(cfg.get("announce_max_hops", 2))
        self.retransmit_jitter_min_s   = float(cfg.get("retransmit_jitter_min", 8.0))
        self.retransmit_jitter_max_s   = float(cfg.get("retransmit_jitter_max", 20.0))

        self.allow_direct   = _bool("allow_direct")
        # auto: send the contact's native hash size, fall back to 1-byte hops if the
        # radio rejects it. native: always encoded (firmware dev / openHop).
        # 1byte: always truncate (firmware v1.17.1 release).
        self.raw_path_hashes = str(cfg.get("raw_path_hashes", "auto")).strip().lower()
        if self.raw_path_hashes not in ("auto", "native", "1byte"):
            raise ValueError("raw_path_hashes must be auto, native or 1byte")
        self._raw_native_paths = self.raw_path_hashes != "1byte"
        self.can_route      = _bool("can_route")
        self.advert_on_start = _bool("advert_on_start")
        self.path_discovery_rate_s    = float(cfg.get("path_discovery_rate", 600))
        self.path_discovery_timeout_s = float(cfg.get("path_discovery_timeout", 20))
        self.peer_ttl_s = float(cfg.get("peer_ttl", 86400))
        self.debug = str(cfg.get("debug_level", "info")).lower() == "debug"

        # RNS interface contract
        self.IN      = True
        self.OUT     = False
        self.online  = False
        self.rxb     = 0
        self.txb     = 0
        self.bitrate = int(cfg.get("bitrate", 1200))
        self.HW_MTU  = RNS.Reticulum.MTU

        # state
        self._mc = None
        self._own_key    = b""      # 32 bytes
        self._own_prefix = b""      # 4 bytes
        self._own_name   = ""

        self._outqueue = queue.Queue(maxsize=self.OUTQUEUE_MAXSIZE)
        self._pkt_id = random.randint(0, 0xFFFF)
        self._pkt_id_lock = threading.Lock()

        self._assembly, self._assembly_meta = {}, {}
        self._asm_lock = threading.Lock()
        self._seen_pkts = {}
        self._seen_lock = threading.Lock()

        # peers: prefix(4 bytes) -> full key(32 bytes)
        self._peers, self._peer_caps, self._peer_last_seen = {}, {}, {}
        self._rns_to_peer = {}      # RNS token (16 bytes) -> peer prefix
        self._peer_lock = threading.Lock()
        self._pending_tokens = {}   # prefix -> set(tokens) seen before BIND
        self._pending_tokens_lock = threading.Lock()
        self._last_unbound_req = {}
        self._last_unbound_req_lock = threading.Lock()
        self._last_path_disc = {}   # prefix -> monotonic
        self._path_disc_inflight = set()

        self._announce_sent_times, self._announce_sent_lock = {}, threading.Lock()
        self._path_req_sent_times, self._path_req_sent_lock = {}, threading.Lock()
        self._path_response_pending, self._path_response_pending_lock = {}, threading.Lock()
        self._pending_resp_task = None
        self._tasks = []
        self._detached = False

        self._setup_done = threading.Event()
        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self._run_loop, daemon=True, name=f"MCRaw-{self.name}")
        self._loop_thread.start()
        fut = asyncio.run_coroutine_threadsafe(self._async_setup(), self._loop)

        def _done(f):
            if f.done() and not f.cancelled() and f.exception() is not None:
                self._log(f"setup failed: {f.exception()}", RNS.LOG_ERROR)
                self._setup_done.set()
        fut.add_done_callback(_done)

        if not self._setup_done.wait(timeout=self.SETUP_TIMEOUT_S):
            self._log("setup timed out; will keep trying in the background", RNS.LOG_WARNING)

    def _log(self, msg, level=RNS.LOG_INFO):
        RNS.log(f"MeshCore_Raw_Interface [{self.name}]: {msg}", level)

    def _dbg(self, msg):
        if self.debug:
            RNS.log(f"MeshCore_Raw_Interface [{self.name}]: {msg}", RNS.LOG_DEBUG)

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_forever()
        except Exception as e:
            self._log(f"event loop crashed: {e}", RNS.LOG_ERROR)

    # ---------------------------------------------------------------- setup / link

    async def _async_setup(self):
        self._mc = _Companion(self.link_cfg, self._log, self._loop)
        self._mc.on_raw_data     = self._on_raw_data
        self._mc.on_channel_data = self._on_channel_data
        self._mc.on_disconnect   = self._on_link_lost
        await self._bring_up(first=True)
        self._tasks.append(self._loop.create_task(self._outgoing_worker()))
        self._tasks.append(self._loop.create_task(self._bind_discovery_loop()))
        self._tasks.append(self._loop.create_task(self._cleanup_loop()))
        self._setup_done.set()

    async def _bring_up(self, first=False):
        delay = self.RECONNECT_MIN_S
        while not self._detached:
            try:
                await self._mc.connect()
                info = await self._mc.app_start()
                self._own_key    = bytes.fromhex(info["public_key"])
                self._own_prefix = self._own_key[:4]
                self._own_name   = info.get("name", "")
                self._log(f"companion '{self._own_name}' key {info['public_key'][:16]}... "
                          f"via {self.transport} [{'router' if self.can_route else 'edge'}]")
                try:
                    await self._mc.set_channel(self.channel_idx, self.channel_name, self.channel_secret)
                except Exception as e:
                    self._log(f"SET_CHANNEL failed ({e}); assuming channel {self.channel_idx} is already configured", RNS.LOG_WARNING)
                if self.flood_scope_key is not None:
                    try:
                        await self._mc.set_flood_scope(self.flood_scope_key)
                        self._log(f"flood scope set to '{self.flood_scope_name}' "
                                  f"({self.flood_scope_key.hex()})")
                    except Exception as e:
                        self._log(f"SET_FLOOD_SCOPE failed ({e}); floods will go out unscoped "
                                  f"and a scoped repeater won't relay them", RNS.LOG_WARNING)
                    try:
                        await self._mc.set_default_flood_scope(self.flood_scope_name, self.flood_scope_key)
                    except Exception as e:
                        self._log(f"SET_DEFAULT_FLOOD_SCOPE failed ({e}); self-adverts will "
                                  f"go out unscoped even though other sends are scoped", RNS.LOG_WARNING)
                try:
                    await self._mc.get_contacts()
                    self._dbg(f"{len(self._mc.contacts)} contacts cached")
                except Exception as e:
                    self._log(f"contact download failed: {e}", RNS.LOG_WARNING)
                if self.advert_on_start and first:
                    try:
                        await self._mc.send_advert(flood=True)
                    except Exception as e:
                        self._log(f"self-advert failed: {e}", RNS.LOG_WARNING)
                self._mc._schedule_sync()          # drain anything queued while we were away
                self.online = True
                return
            except Exception as e:
                self.online = False
                self._log(f"link setup failed: {e}; retrying in {delay:.0f}s", RNS.LOG_WARNING)
                try:
                    await self._mc.close()
                except Exception:
                    pass
                await asyncio.sleep(delay)
                delay = min(delay * 2, self.RECONNECT_MAX_S)
                first = False

    async def _on_link_lost(self):
        if self._detached:
            return
        self.online = False
        self._log("companion link lost; reconnecting", RNS.LOG_WARNING)
        await self._bring_up()

    def detach(self):
        self._detached = True
        self.online = False
        try:
            fut = asyncio.run_coroutine_threadsafe(self._mc.close(), self._loop)
            fut.result(timeout=5)
        except Exception:
            pass
        async def _shutdown():
            for t in self._tasks:
                t.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)
            self._loop.stop()
        try:
            self._loop.call_soon_threadsafe(lambda: self._loop.create_task(_shutdown()))
        except RuntimeError:
            pass
        self.detached = True

    # ---------------------------------------------------------------- peers & discovery

    def _own_flags(self):
        return self.can_route

    async def _send_bind(self, is_req):
        if not self.online or not self._own_key:
            return
        ftype = _Frame.T_BIND_REQ if is_req else _Frame.T_BIND
        frame = _Frame.build(ftype, self._own_prefix, _Frame.BROADCAST, self._next_pkt_id(),
                             [self._own_key], can_route=self.can_route)[0]
        await self._mc.send_channel_data(self.channel_idx, self.data_type, frame)

    async def _bind_discovery_loop(self):
        await asyncio.sleep(5)
        retries = 0
        while not self._detached:
            with self._peer_lock:
                have_peers = bool(self._peers)
            try:
                if not have_peers and retries < self.BIND_MAX_RETRIES:
                    self._log(f"no peers -- sending BIND_REQ ({retries + 1}/{self.BIND_MAX_RETRIES})")
                    await self._send_bind(is_req=True)
                    retries += 1
                    await asyncio.sleep(self.BIND_RESP_WINDOW_S)
                else:
                    retries = 0
                    await self._send_bind(is_req=False)
                    await asyncio.sleep(self.BIND_HEARTBEAT_S)
            except asyncio.CancelledError:
                return
            except Exception as e:
                self._log(f"discovery send failed: {e}", RNS.LOG_WARNING)
                await asyncio.sleep(30)

    async def _delayed_bind_response(self):
        delay = random.uniform(self.BIND_BACKOFF_MIN, self.BIND_BACKOFF_MAX)
        await asyncio.sleep(delay)
        try:
            await self._send_bind(is_req=False)
            self._dbg(f"sent BIND after {delay:.1f}s backoff")
        except Exception as e:
            self._log(f"BIND response failed: {e}", RNS.LOG_WARNING)

    async def _opportunistic_bind_req(self, prefix):
        now = time.monotonic()
        with self._last_unbound_req_lock:
            if now - self._last_unbound_req.get(prefix, 0) < self.UNBOUND_REQ_RETRY_S:
                return
            self._last_unbound_req[prefix] = now
        try:
            await self._send_bind(is_req=True)
            self._log(f"traffic from unbound peer {prefix.hex()} -- sent BIND_REQ")
        except Exception as e:
            self._log(f"BIND_REQ failed: {e}", RNS.LOG_WARNING)

    async def _handle_bind(self, f):
        pubkey = f["payload"][:32]
        if len(pubkey) != 32:
            return
        prefix = f["src"]
        if pubkey[:4] != prefix:
            return
        is_req = f["type"] == _Frame.T_BIND_REQ
        with self._peer_lock:
            existing = self._peers.get(prefix)
            cap_changed = self._peer_caps.get(prefix) != f["can_route"]
            self._peers[prefix] = pubkey
            self._peer_caps[prefix] = f["can_route"]
            self._peer_last_seen[prefix] = time.monotonic()
        with self._pending_tokens_lock:
            pending = self._pending_tokens.pop(prefix, None)
        if pending:
            with self._peer_lock:
                for tok in pending:
                    self._rns_to_peer.setdefault(tok, prefix)
            self._log(f"backfilled {len(pending)} RNS token(s) for peer {prefix.hex()}")
        if existing != pubkey or cap_changed:
            self._log(f"{'BIND_REQ from' if is_req else 'peer'} {pubkey.hex()[:16]}... "
                      f"[{'router' if f['can_route'] else 'edge'}]")
        # make sure the radio has a contact so raw sends / path discovery can work
        if self.allow_direct and self._mc.contact_by_prefix(pubkey.hex()[:8]) is None:
            try:
                await self._mc.add_contact(pubkey, f"RNS-{pubkey.hex()[:8]}")
                self._dbg(f"added contact for {pubkey.hex()[:8]}")
            except Exception as e:
                self._log(f"add_contact failed for {pubkey.hex()[:8]}: {e}", RNS.LOG_WARNING)
        if is_req:
            if self._pending_resp_task is None or self._pending_resp_task.done():
                self._pending_resp_task = self._loop.create_task(self._delayed_bind_response())

    # ---------------------------------------------------------------- paths

    def _path_for(self, contact, native=True):
        """
        (path_bytes, path_len_byte) for CMD_SEND_RAW_DATA, or None if no path is known.

        native=True keeps the contact's hash size and encodes path_len as
        hash_mode << 6 | hops (firmware `dev`, openHop). native=False truncates
        every hop to its first byte and sends a plain hop count, which is all
        firmware v1.17.1 understands. Identical for 1-byte-hash paths.
        """
        if contact is None:
            return None
        n = contact.get("out_path_len", -1)
        if n is None or n < 0:
            return None
        if n == 0:
            return b"", 0
        mode = max(0, contact.get("out_path_hash_mode", 0) or 0)
        raw = bytes.fromhex(contact.get("out_path", "") or "")
        step = mode + 1
        if len(raw) < n * step:
            return None
        if native and mode > 0:
            path = raw[:n * step]
            if len(path) > 64:
                return None
            return path, (mode << 6) | (n & 0x3F)
        hops = [raw[i:i + 1] for i in range(0, n * step, step)]
        return b"".join(hops)[:64], n & 0x3F

    async def _ensure_path(self, prefix):
        """Rate-limited path discovery for a peer; adds a contact first if needed."""
        pubkey = self._peers.get(prefix)
        if pubkey is None:
            return
        now = time.monotonic()
        if now - self._last_path_disc.get(prefix, 0) < self.path_discovery_rate_s:
            return
        if prefix in self._path_disc_inflight:
            return
        self._last_path_disc[prefix] = now
        self._path_disc_inflight.add(prefix)
        try:
            if self._mc.contact_by_prefix(pubkey.hex()[:8]) is None:
                await self._mc.add_contact(pubkey, f"RNS-{pubkey.hex()[:8]}")
            res = await self._mc.path_discovery(pubkey, timeout=self.path_discovery_timeout_s)
            if res:
                self._log(f"path to {prefix.hex()}: {res['out_path_len']} hop(s) [{res['out_path']}]")
            else:
                self._dbg(f"path discovery for {prefix.hex()} timed out")
        except Exception as e:
            self._log(f"path discovery for {prefix.hex()} failed: {e}", RNS.LOG_WARNING)
        finally:
            self._path_disc_inflight.discard(prefix)

    # ---------------------------------------------------------------- inbound

    def _on_raw_data(self, payload, snr, rssi):
        self._loop.create_task(self._on_frame(payload, "RAW", snr))

    def _on_channel_data(self, chan_idx, data_type, payload):
        if chan_idx != self.channel_idx or data_type != self.data_type:
            return
        self._loop.create_task(self._on_frame(payload, "CHANNEL", None))

    async def _on_frame(self, data, rx_mode, snr):
        f = _Frame.parse(data)
        if f is None:
            return
        if f["src"] == self._own_prefix:
            return
        if f["dst"] != _Frame.BROADCAST and f["dst"] != self._own_prefix:
            return
        if f["type"] in (_Frame.T_BIND, _Frame.T_BIND_REQ):
            await self._handle_bind(f)
            return
        if f["type"] != _Frame.T_DATA:
            return

        src, key = f["src"], (f["src"], f["pkt_id"])
        now = time.monotonic()
        with self._peer_lock:
            if src in self._peer_last_seen:
                self._peer_last_seen[src] = now

        with self._seen_lock:
            exp = self._seen_pkts.get(key)
            if exp is not None:
                if now < exp:
                    return
                del self._seen_pkts[key]

        with self._asm_lock:
            if key not in self._assembly:
                self._assembly[key] = {}
                self._assembly_meta[key] = (f["total"], now)
            if f["idx"] in self._assembly[key]:
                return
            self._assembly[key][f["idx"]] = f["payload"]
            if len(self._assembly[key]) < self._assembly_meta[key][0]:
                return
            try:
                packet = b"".join(self._assembly[key][i] for i in range(f["total"]))
            except KeyError:
                return
            finally:
                self._assembly.pop(key, None)
                self._assembly_meta.pop(key, None)
        with self._seen_lock:
            self._seen_pkts[key] = now + self.DEDUPLICATION_TTL_S
        if not packet:
            return

        # learn which peer answers for which RNS destination
        token = self._extract_rns_token(packet)
        if token is not None:
            with self._peer_lock:
                bound = src in self._peers
                if bound:
                    if token not in self._rns_to_peer:
                        self._rns_to_peer[token] = src
                        if len(self._rns_to_peer) > self._RNS_MAP_MAX:
                            for t in list(self._rns_to_peer)[: self._RNS_MAP_MAX // 2]:
                                del self._rns_to_peer[t]
                    if packet[0] & 0x03 == self._RNS_PTYPE_LINK_REQ:
                        link_id = self._link_id_from_lr_packet(packet)
                        if link_id is not None:
                            self._rns_to_peer.setdefault(link_id, src)
            if not bound:
                with self._pending_tokens_lock:
                    bucket = self._pending_tokens.get(src)
                    if bucket is None and len(self._pending_tokens) < self._PENDING_TOKENS_MAX_SENDERS:
                        bucket = self._pending_tokens[src] = set()
                    if bucket is not None and len(bucket) < self._PENDING_TOKENS_MAX_PER_SENDER:
                        bucket.add(token)
                self._loop.create_task(self._opportunistic_bind_req(src))

        ptype = packet[0] & 0x03
        dest_type = (packet[0] >> 2) & 0x03
        self._log(f"RX {rx_mode} from {src.hex()} {len(packet)}b "
                  f"{ {0: 'DATA', 1: 'ANNOUNCE', 2: 'LINK_REQ', 3: 'PROOF'}[ptype] }"
                  f"{f' snr={snr:.1f}' if snr is not None else ''}")
        if ptype == self._RNS_PTYPE_DATA and dest_type == self._RNS_DTYPE_PLAIN and len(packet) >= 12:
            with self._path_response_pending_lock:
                self._path_response_pending[bytes(packet[2:12])] = now + self._path_response_bypass_s
        try:
            self.process_incoming(packet)
        except Exception as e:
            self._log(f"delivery error: {e}", RNS.LOG_ERROR)

    def process_incoming(self, data):
        if self.online and not self._detached:
            self.rxb += len(data)
            self.owner.inbound(data, self)

    # ---------------------------------------------------------------- RNS header helpers

    def _is_broadcast_packet(self, data):
        if len(data) < 1:
            return True
        ptype = data[0] & 0x03
        dest_type = (data[0] >> 2) & 0x03
        return ptype == self._RNS_PTYPE_ANNOUNCE or (ptype == self._RNS_PTYPE_DATA and dest_type == self._RNS_DTYPE_PLAIN)

    def _extract_rns_token(self, data):
        if len(data) < 2:
            return None
        header_type = (data[0] & 0x40) >> 6
        d = self._RNS_DST_LEN
        if header_type == 1:
            return bytes(data[2 + d:2 + 2 * d]) if len(data) >= 2 + 2 * d else None
        return bytes(data[2:2 + d]) if len(data) >= 2 + d else None

    def _link_id_from_lr_packet(self, raw):
        if len(raw) < 2:
            return None
        d = self._RNS_DST_LEN
        header_type = (raw[0] & 0x40) >> 6
        hashable = bytes([raw[0] & 0b00001111])
        if header_type == 1:
            if len(raw) < 2 + d:
                return None
            hashable += raw[2 + d:]
        else:
            hashable += raw[2:]
        return hashlib.sha256(hashable).digest()[:d]

    def _next_pkt_id(self):
        with self._pkt_id_lock:
            self._pkt_id = (self._pkt_id + 1) & 0xFFFF
            return self._pkt_id

    # ---------------------------------------------------------------- outbound

    @staticmethod
    def announce_exceeds_hops(data, max_hops):
        """True for an RNS announce that has travelled more than max_hops to reach
        this node. Path responses are exempt so on-demand path lookups still work.
        max_hops of None or 0 disables the check (always returns False)."""
        if not max_hops or len(data) < 19 or data[0] & 0x03 != 0x01:  # 0x01 = RNS_PTYPE_ANNOUNCE
            return False
        context_offset = 34 if data[0] & 0b01000000 else 18  # HEADER_2 carries a 16-byte transport id
        if len(data) > context_offset and data[context_offset] == RNS.Packet.PATH_RESPONSE:
            return False
        return data[1] > max_hops

    def process_outgoing(self, data):
        if not self.online or not self._own_prefix:
            return
        if self.announce_exceeds_hops(data, self.announce_max_hops):
            return
        hdr = data[0] if data else 0
        ptype, dest_type = hdr & 0x03, (hdr >> 2) & 0x03
        now = time.monotonic()

        if self._announce_rate_s > 0 and len(data) >= 12 and ptype == self._RNS_PTYPE_ANNOUNCE:
            dest_id = bytes(data[2:12])
            with self._path_response_pending_lock:
                expiry = self._path_response_pending.pop(dest_id, None)
            answering = expiry is not None and now < expiry
            if not answering:
                with self._announce_sent_lock:
                    last = self._announce_sent_times.get(dest_id, 0)
                    if now - last < self._announce_rate_s:
                        self._dbg(f"suppressing announce for {dest_id.hex()[:8]} ({now - last:.0f}s < {self._announce_rate_s:.0f}s)")
                        return
            with self._announce_sent_lock:
                self._announce_sent_times[dest_id] = now

        if self._path_req_rate_s > 0 and len(data) >= 12 and ptype == self._RNS_PTYPE_DATA and dest_type == self._RNS_DTYPE_PLAIN:
            dest_id = bytes(data[2:12])
            with self._path_req_sent_lock:
                entry = self._path_req_sent_times.get(dest_id)
                if entry is None:
                    self._path_req_sent_times[dest_id] = (now, now)
                else:
                    first, last = entry
                    if now - first < self._path_req_burst_window_s:
                        self._path_req_sent_times[dest_id] = (first, now)
                    elif now - last < self._path_req_rate_s:
                        return
                    else:
                        self._path_req_sent_times[dest_id] = (now, now)

        broadcast = self._is_broadcast_packet(data)
        target = None
        if not broadcast and self.allow_direct:
            token = self._extract_rns_token(data)
            if token is not None:
                with self._peer_lock:
                    target = self._rns_to_peer.get(token)

        pkt_id = self._next_pkt_id()
        if target is None:
            frags = _Frame.fragments(_Frame.T_DATA, self._own_prefix, _Frame.BROADCAST, pkt_id,
                                     data, self.channel_payload_size, self.can_route)
            route = ("channel", None)
            self._dbg(f"TX CHANNEL {len(data)}b in {len(frags)} fragment(s)")
        else:
            frags = _Frame.fragments(_Frame.T_DATA, self._own_prefix, target, pkt_id,
                                     data, self.raw_payload_size, self.can_route)
            route = ("direct", target)
            self._dbg(f"TX RAW -> {target.hex()} {len(data)}b in {len(frags)} fragment(s)")

        for frag in frags:
            try:
                self._outqueue.put((route[0], route[1], frag), block=True, timeout=5)
            except queue.Full:
                self._log("outgoing queue full; dropping fragment", RNS.LOG_WARNING)

        extra = 0
        if broadcast:
            if ptype == self._RNS_PTYPE_ANNOUNCE:
                extra = self.announce_retransmit_extra
            elif ptype == self._RNS_PTYPE_DATA and dest_type == self._RNS_DTYPE_PLAIN:
                extra = self.path_req_retransmit_extra
        if extra > 0:
            asyncio.run_coroutine_threadsafe(self._delayed_retransmits(frags, route, extra), self._loop)
        self.txb += len(data)

    # RNS calls processOutgoing on older versions
    def processOutgoing(self, data):
        return self.process_outgoing(data)

    async def _delayed_retransmits(self, frags, route, count):
        for i in range(count):
            await asyncio.sleep(random.uniform(self.retransmit_jitter_min_s, self.retransmit_jitter_max_s))
            if not self.online:
                return
            for frag in frags:
                try:
                    self._outqueue.put_nowait((route[0], route[1], frag))
                except queue.Full:
                    pass
            self._dbg(f"retransmit pass {i + 1}/{count} ({len(frags)} fragment(s))")

    async def _outgoing_worker(self):
        while not self._detached:
            if not self.online or self._mc is None:
                await asyncio.sleep(0.5)
                continue
            mode, target, frag = await self._loop.run_in_executor(None, self._outqueue.get)
            sent_mode = mode
            try:
                if mode == "direct":
                    contact = self._mc.contact_by_prefix(target.hex())
                    route = self._path_for(contact, native=self._raw_native_paths)
                    if route is None:
                        self._dbg(f"no path to {target.hex()}; sending via CHANNEL and discovering")
                        self._loop.create_task(self._ensure_path(target))
                        await self._mc.send_channel_data(self.channel_idx, self.data_type, frag)
                        sent_mode = "channel"
                    else:
                        path, plen = route
                        frame_len = 2 + len(path) + len(frag)
                        if frame_len > _Companion.MAX_FRAME:
                            self._dbg(f"raw frame would be {frame_len}b with a {len(path)}-byte path; using CHANNEL")
                            await self._mc.send_channel_data(self.channel_idx, self.data_type, frag)
                            sent_mode = "channel"
                        else:
                            try:
                                await self._mc.send_raw_data(path, frag, plen)
                            except _CompanionError as e:
                                # A v1.17.1-era radio reads path_len as a byte count and rejects
                                # the encoded form for multi-byte hashes. Drop to 1-byte hops for
                                # the rest of the session and resend this fragment that way.
                                rejected = ("UNSUPPORTED_CMD" in str(e)) or ("ILLEGAL_ARG" in str(e))
                                if (self.raw_path_hashes == "auto" and self._raw_native_paths
                                        and plen >= 0x40 and rejected):
                                    self._raw_native_paths = False
                                    self._log("radio rejected multi-byte raw paths; using 1-byte hop hashes from now on "
                                              "(firmware v1.17.1 behaviour)", RNS.LOG_WARNING)
                                    path, plen = self._path_for(contact, native=False)
                                    await self._mc.send_raw_data(path, frag, plen)
                                else:
                                    raise
                else:
                    await self._mc.send_channel_data(self.channel_idx, self.data_type, frag)
            except Exception as e:
                self._log(f"{mode} send failed: {e}", RNS.LOG_WARNING)
                if mode == "direct":
                    try:
                        self._outqueue.put_nowait(("channel", None, frag))
                    except queue.Full:
                        pass
                self._outqueue.task_done()
                await asyncio.sleep(0.2)
                continue

            delay = self.direct_frag_delay_s if sent_mode == "direct" else self.fragment_delay_s
            if self.rate_limit_bps > 0:
                delay = max(delay, (len(frag) * 8) / self.rate_limit_bps)
            await asyncio.sleep(delay)
            self._outqueue.task_done()

    # ---------------------------------------------------------------- housekeeping

    async def _cleanup_loop(self):
        while not self._detached:
            await asyncio.sleep(30)
            now = time.monotonic()
            with self._asm_lock:
                for k in [k for k, (_, ts) in self._assembly_meta.items() if ts < now - self.fragment_timeout_s]:
                    self._assembly.pop(k, None)
                    self._assembly_meta.pop(k, None)
            with self._seen_lock:
                for k in [k for k, exp in self._seen_pkts.items() if now >= exp]:
                    del self._seen_pkts[k]
            deadline = now - self.peer_ttl_s
            with self._peer_lock:
                expired = [p for p, ts in self._peer_last_seen.items() if ts < deadline]
                for p in expired:
                    self._peers.pop(p, None)
                    self._peer_caps.pop(p, None)
                    self._peer_last_seen.pop(p, None)
                    for t in [t for t, q in self._rns_to_peer.items() if q == p]:
                        del self._rns_to_peer[t]
            if expired:
                self._log(f"expired {len(expired)} stale peer(s)")
            with self._announce_sent_lock:
                for k in [k for k, ts in self._announce_sent_times.items() if ts < now - 2 * self._announce_rate_s]:
                    del self._announce_sent_times[k]
            with self._path_req_sent_lock:
                for k in [k for k, (_, last) in self._path_req_sent_times.items() if last < now - 2 * self._path_req_rate_s]:
                    del self._path_req_sent_times[k]
            with self._last_unbound_req_lock:
                stale = [p for p, ts in self._last_unbound_req.items() if ts < deadline]
                for p in stale:
                    del self._last_unbound_req[p]
            if stale:
                with self._pending_tokens_lock:
                    for p in stale:
                        self._pending_tokens.pop(p, None)
            with self._path_response_pending_lock:
                for k in [k for k, exp in self._path_response_pending.items() if now >= exp]:
                    del self._path_response_pending[k]

    def should_ingress_limit(self):
        return False

    def __str__(self):
        return f"MeshCore_Raw_Interface[{self.name}]"


interface_class = MeshCore_Raw_Interface

# Harmless if this file is dropped into a Sideband plugins directory: Sideband
# exec's every .py there and reads plugin_class without a guard.
plugin_class = None
