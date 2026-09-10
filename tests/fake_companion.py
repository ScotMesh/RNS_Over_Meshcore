"""
A fake MeshCore companion mesh for testing MeshCore_Raw_Interface offline.

FakeMesh hosts N "companions", each listening on its own TCP port and
speaking the companion frame protocol ('<'/'>' + LE16 length). Anything one
companion puts on the air is delivered to every other one, mimicking a set
of radios all in range of each other (zero hops):

  * CMD_SEND_CHANNEL_DATA -> OK, then RESP_CODE_CHANNEL_DATA_RECV queued on the
    others behind a PUSH_CODE_MSG_WAITING tickle (drained by SYNC_NEXT_MESSAGE),
    exactly as firmware queues group datagrams.
  * CMD_SEND_RAW_DATA -> OK, then PUSH_CODE_RAW_DATA pushed to the others
    immediately, as firmware does for raw-custom packets.
  * CMD_SEND_PATH_DISCOVERY_REQ -> RESP_CODE_SENT, then a PUSH 0x8D with a
    zero-hop path, and the contact's out_path is updated.

Byte layouts follow examples/companion_radio/MyMesh.cpp (v1.17.1). Frames
longer than 173 bytes are recorded in `violations` so tests can assert the
BLE frame budget was respected.
"""

import asyncio
import os
import struct
import time


class FakeCompanion:
    MAX_FRAME = 173

    def __init__(self, mesh, name, port):
        self.mesh = mesh
        self.name = name
        self.port = port
        self.pubkey = os.urandom(32)
        self.contacts = {}       # pubkey bytes -> dict(type, flags, path_len_byte, path, name)
        self.channels = {}       # idx -> (name, secret)
        self.inbox = []          # queued frames for SYNC_NEXT_MESSAGE
        self.writer = None
        self.server = None
        self.rx_frames = []      # every command frame received (for assertions)
        self.sent_raw = 0
        self.sent_channel = 0

    async def start(self):
        self.server = await asyncio.start_server(self._on_client, "127.0.0.1", self.port)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _on_client(self, reader, writer):
        self.writer = writer
        buf = b""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                buf += data
                while True:
                    i = buf.find(b"<")
                    if i < 0:
                        buf = b""
                        break
                    buf = buf[i:]
                    if len(buf) < 3:
                        break
                    n = int.from_bytes(buf[1:3], "little")
                    if len(buf) < 3 + n:
                        break
                    frame = buf[3:3 + n]
                    buf = buf[3 + n:]
                    await self._handle(frame)
        except (ConnectionResetError, asyncio.CancelledError):
            pass
        finally:
            self.writer = None

    async def _send(self, frame):
        if len(frame) > self.MAX_FRAME:
            self.mesh.violations.append((self.name, "tx", len(frame), frame[0]))
        if self.writer is not None:
            self.writer.write(b">" + len(frame).to_bytes(2, "little") + frame)
            try:
                await self.writer.drain()
            except Exception:
                pass

    async def _handle(self, frame):
        self.rx_frames.append(frame)
        if len(frame) > self.MAX_FRAME:
            self.mesh.violations.append((self.name, "rx", len(frame), frame[0]))
        cmd = frame[0]

        if cmd == 1:      # APP_START -> SELF_INFO
            body = (bytes([1, 20, 22]) + self.pubkey + b"\x00" * 8 + bytes([0, 0, 0, 0])
                    + (868000000).to_bytes(4, "little") + (125000).to_bytes(4, "little") + bytes([9, 5])
                    + self.name.encode())
            await self._send(bytes([5]) + body)
        elif cmd == 22:   # DEVICE_QUERY: pretend older firmware
            await self._send(bytes([1, 1]))
        elif cmd == 32:   # SET_CHANNEL
            idx = frame[1]
            self.channels[idx] = (frame[2:34].rstrip(b"\x00").decode(), frame[34:50])
            await self._send(b"\x00")
        elif cmd == 7:    # SEND_SELF_ADVERT -> others learn us (path unknown, like a repeated advert)
            for other in self.mesh.others(self):
                other.contacts.setdefault(self.pubkey, {"type": 1, "flags": 0, "path_len": 0xFF,
                                                        "path": b"", "name": self.name})
                await other._send(bytes([0x8A]) + other._contact_frame(self.pubkey))
            await self._send(b"\x00")
        elif cmd == 4:    # GET_CONTACTS
            await self._send(bytes([2]) + len(self.contacts).to_bytes(4, "little"))
            for pk in list(self.contacts):
                await self._send(bytes([3]) + self._contact_frame(pk))
            await self._send(bytes([4]) + b"\x00" * 4)
        elif cmd == 9:    # ADD_UPDATE_CONTACT
            pk = frame[1:33]
            plen = frame[35]
            c = self.contacts.get(pk, {})
            c.update({"type": frame[33], "flags": frame[34], "path_len": plen,
                      "path": frame[36:36 + (0 if plen == 0xFF else (plen & 0x3F) * ((plen >> 6) + 1))],
                      "name": frame[100:132].rstrip(b"\x00").decode("utf-8", "ignore")})
            self.contacts[pk] = c
            await self._send(b"\x00")
        elif cmd == 10:   # SYNC_NEXT_MESSAGE
            if self.inbox:
                await self._send(self.inbox.pop(0))
            else:
                await self._send(bytes([10]))
        elif cmd == 62:   # SEND_CHANNEL_DATA
            idx, plen = frame[1], frame[2]
            if idx not in self.channels:
                await self._send(bytes([1, 2]))       # ERR NOT_FOUND
                return
            i = 3 + (0 if plen == 0xFF else (plen & 0x3F) * ((plen >> 6) + 1))
            data_type = int.from_bytes(frame[i:i + 2], "little")
            payload = frame[i + 2:]
            if data_type == 0 or len(payload) > 165:
                await self._send(bytes([1, 6]))       # ERR ILLEGAL_ARG
                return
            self.sent_channel += 1
            await self._send(b"\x00")
            secret = self.channels[idx][1]
            for other in self.mesh.others(self):
                for oidx, (_, osecret) in other.channels.items():
                    if osecret == secret:
                        recv = (bytes([27, 0, 0, 0, oidx, 1]) + data_type.to_bytes(2, "little")
                                + bytes([len(payload)]) + payload)
                        other.inbox.append(recv)
                        await other._send(bytes([0x83]))
        elif cmd == 25:   # SEND_RAW_DATA
            if len(frame) < 6:
                await self._send(bytes([1, 1]))
                return
            plen = frame[1]
            if 2 + plen + 4 > len(frame):
                await self._send(bytes([1, 1]))       # ERR UNSUPPORTED_CMD (flood / short)
                return
            payload = frame[2 + plen:]
            self.sent_raw += 1
            await self._send(b"\x00")
            for other in self.mesh.others(self):
                await other._send(bytes([0x84, 0x14, 0xC8, 0xFF]) + payload)
        elif cmd == 52:   # SEND_PATH_DISCOVERY_REQ
            pk = frame[2:34]
            if pk not in self.contacts:
                await self._send(bytes([1, 2]))
                return
            tag = os.urandom(4)
            await self._send(bytes([6, 1]) + tag + (3000).to_bytes(4, "little"))
            # the target answers: zero-hop path
            self.contacts[pk]["path_len"] = 0
            self.contacts[pk]["path"] = b""
            await asyncio.sleep(0.05)
            await self._send(bytes([0x8D, 0]) + pk[:6] + bytes([0]) + bytes([0]))
        else:
            await self._send(bytes([1, 1]))           # ERR UNSUPPORTED_CMD

    def _contact_frame(self, pk):
        c = self.contacts[pk]
        path = c["path"].ljust(64, b"\x00")[:64]
        return (pk + bytes([c["type"], c["flags"], c["path_len"]]) + path
                + c["name"].encode()[:32].ljust(32, b"\x00")
                + int(time.time()).to_bytes(4, "little") + b"\x00" * 8 + b"\x00" * 4)


class FakeMesh:
    def __init__(self, names, base_port=47000):
        self.nodes = [FakeCompanion(self, n, base_port + i) for i, n in enumerate(names)]
        self.violations = []

    def others(self, node):
        return [n for n in self.nodes if n is not node]

    async def start(self):
        for n in self.nodes:
            await n.start()

    async def stop(self):
        for n in self.nodes:
            await n.stop()
