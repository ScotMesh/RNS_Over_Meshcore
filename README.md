![ScotMesh Reticulum](https://raw.githubusercontent.com/ScotMesh/branding/main/networks/reticulum/readme-header.png)

# RNS over MeshCore — ScotMesh fork

> **This is a fork of [comms-engineer/RNS_Over_Meshcore](https://github.com/comms-engineer/RNS_Over_Meshcore), maintained by ScotMesh for our own deployment. It is not going back upstream** — no pull request is planned, and this repository will not track upstream changes. If you want the original, use the link above.
>
> **What is different here**
>
> | | Original (`comms-engineer`) | This fork (`ScotMesh`) |
> |---|---|---|
> | Transport on the air | MeshCore **text** messages: base64 fragments inside channel text and direct messages | Adds `Interface/MeshCore_Raw_Interface.py`: **binary payloads** — raw-custom packets (`CMD_SEND_RAW_DATA`) for unicast on an explicit repeater path, binary channel datagrams (`CMD_SEND_CHANNEL_DATA`) for broadcast. No base64, no `"RNS:"`/name prefixes, no MeshCore ACK round-trips |
> | Fragment size | 64 B payload (≈128-char text limit); a 500-byte RNS packet is 8 fragments | 140 B raw / 148 B channel; the same packet is 4 fragments. Every companion frame ≤ 173 B so BLE works |
> | Dependencies | `meshcore` Python library | None beyond `rns` — the raw interface carries its own minimal companion client for serial, TCP and BLE |
> | Hosts | rnsd | rnsd, **MeshChatX** (custom interface module) and **Sideband** (service plugin in `sideband/`, TCP-only on Android) |
> | Repeaters | Stock MeshCore | Stock MeshCore **and openHop virtual companions**, verified against both code bases |
> | Tests | none | `tests/`: framing, byte-exact command layouts, and a loopback over a fake companion mesh |
> | Original interfaces | — | Kept **unchanged** (`MeshCore_Dynamic_Interface.py`, `MeshCore_Channel_Interface.py`, `MeshCore_Interface.py`). The text and raw formats do not interoperate; every node on a tunnel must use the same one |
>
> The rest of this README is the original project's documentation for the text interface, left as it was, with a **Raw transport** section further down for ours. Credit for the discovery/routing design and the original code goes to [comms-engineer](https://github.com/comms-engineer).

# MeshCore Dynamic Interface

A [Reticulum Network Stack (RNS)](https://reticulum.network/) custom interface that tunnels RNS traffic over a [MeshCore](https://meshcore.co.uk/) LoRa mesh. It requires no static remote-node configuration — peers discover each other dynamically over the air — and uses a hybrid channel-broadcast / unicast-direct routing strategy to keep airtime usage on a shared, half-duplex LoRa channel as low as possible.

## Why this exists

RNS ships interfaces for TCP, serial, I2P, packet radio, and a handful of others, but nothing that speaks directly to MeshCore firmware. This interface fills that gap: it fragments and re-assembles RNS binary packets into MeshCore channel/direct messages, and layers a lightweight peer-discovery and routing protocol on top so that Reticulum can run natively over a MeshCore LoRa network — including in mixed deployments where a MeshCore mesh acts as the "last mile" for an existing RNS transport backbone.

## Features

- **Zero static config peer discovery** — nodes find each other with a demand-driven `RNSBIND_REQ` / `RNSBIND` handshake instead of periodic broadcast, based on the RFC 2236 (IGMP) report-suppression pattern to avoid response storms on a shared channel.
- **Hybrid routing** — channel broadcast for announces/discovery, unicast direct messages for established peer-to-peer sessions, with automatic fallback from direct to channel if a unicast send fails or goes unacknowledged.
- **RNS Link ID aware routing** — correctly follows Reticulum's ephemeral Link ID once a Link handshake completes, deriving the destination hash locally so routing doesn't break mid-session.
- **Capability-aware discovery** — peers advertise whether they can carry transit traffic (`R` router / `E` edge) at discovery time, useful for distinguishing infrastructure nodes from battery-powered edge devices.
- **Delivery-aware direct sends** — waits on the MeshCore firmware's `expected_ack` / `ACK` event pair for unicast messages rather than trusting the immediate `MSG_SENT` result, with a bounded timeout so a single slow/flood-mode peer can't stall the shared outgoing queue.
- **Configurable fragmentation** — RNS packets are split into MeshCore-message-sized fragments with a compact 6-byte binary header, sized to fit under firmware channel-message character limits.
- **Rate limiting** — independent throttles for outgoing announces, path requests, and (optionally) a hard bitrate cap, to keep the interface well-behaved on congested or bandwidth-constrained channels.
- **Multiple transports** — connects to the MeshCore node over serial, TCP, or BLE.

## Requirements

- Python 3.9+
- [Reticulum (`rns`)](https://pypi.org/project/rns/)
- The [`meshcore`](https://pypi.org/project/meshcore/) Python library
- A MeshCore-flashed radio (or a MeshCore companion app reachable over TCP/BLE) reachable from the host running `rnsd`

```bash
pip install rns meshcore
```

## Installation

1. Copy `MeshCore_Dynamic_Interface.py` into your Reticulum config's `interfaces` directory (typically `~/.reticulum/interfaces/`).
2. Add an interface block to `~/.reticulum/config` (see [Configuration](#configuration) below).
3. Restart `rnsd`, or reload interfaces if your setup supports it.
4. Every node participating in the same tunnel must use the same `channel_idx`, `channel_name`, and `channel_secret`.

## Configuration

Every node needs at minimum a transport block and matching channel identity. A full infrastructure/transport-node example:

```ini
[reticulum]
  enable_transport = yes
  share_instance = yes

[logging]
  loglevel = 4    # increase to 7 for debug

[interfaces]

  [[MeshCore Dynamic Interface]]
    type = MeshCore_Dynamic_Interface
    interface_enabled = yes

    # Role
    mode = access_point
    can_route = yes

    # Transport — uncomment exactly one block
    # Serial (most common):
    transport = serial
    port = /dev/ttyUSB0
    baudrate = 115200
    #
    # TCP (MeshCore node reachable over IP):
    # transport = tcp
    # host = 127.0.0.1
    # tcp_port = 4403
    #
    # BLE:
    # transport = ble
    # ble_name =            # blank = connect to first found device

    # Channel — all nodes on the same tunnel must share these values
    channel_idx = 0
    channel_name = RNSTunnel
    channel_secret = <32 hex chars>   # openssl rand -hex 16

    # Radio overrides — all four must be non-zero to take effect.
    # Leave commented to use the values already stored on the MeshCore node.
    # freq = 915.0        # MHz centre frequency
    # bw   = 250.0        # kHz bandwidth (125 / 250 / 500)
    # sf   = 10            # spreading factor (7-12)
    # cr   = 5             # coding rate denominator (5=4/5 ... 8=4/8)

    # Fragmentation
    payload_size = 64         # bytes/fragment - see "Payload size" below
    fragment_delay = 2.5      # seconds between channel-mode fragments
    direct_frag_delay = 0.5   # seconds between direct-message fragments
    fragment_timeout = 300    # 5-minute reassembly window for high-latency meshes

    # Outgoing rate limiting (set to 0 to disable)
    outgoing_announce_rate = 600     # min seconds between announces per dest
    outgoing_path_req_rate = 1800    # min seconds between path requests per dest

    # Optional hard bandwidth cap in bits per second (0 = disabled)
    # rate_limit = 1200

    # Peer discovery
    allow_direct = yes    # use unicast direct messages when a route is known
    peer_ttl = 86400      # seconds before a silent peer expires

    debug_level = info    # info | debug

  [[Backbone Interface]]
    type = BackboneInterface
    interface_enabled = yes
    mode = boundary
    target_host = <backbone-server-hostname-or-ip>
    target_port = 4242
    # Rate-limit announce re-propagation from the fast network
    announce_rate_target  = 3600
    announce_rate_grace   = 2
    announce_rate_penalty = 7200
```

### Interface mode

Mode selection has a real impact on announce traffic, path expiry, and channel load — get it wrong and a LoRa channel can be flooded indefinitely.

**`access_point`** (recommended for infrastructure/transport nodes with backbone connectivity)
Announces are not automatically re-broadcast on this interface, and paths to destinations behind it expire faster, matching the transient nature of battery-powered or intermittently-connected field devices. Path requests from clients are still forwarded and resolved on their behalf.

> **Note:** AP mode only suppresses `ANNOUNCE` re-broadcasting. `DATA`+`PLAIN` path requests from the wider mesh for a recently-offline node still pass through AP mode onto the LoRa channel. Use `outgoing_path_req_rate` to throttle these independently.

> ⚠️ **Never use `gateway` mode on a LoRa interface on a node that is also connected to a high-connectivity backbone.** Gateway mode proactively pushes *all* known announces to clients on that interface — with thousands of routes on the public Reticulum mesh, this will flood a shared LoRa channel indefinitely.

**`boundary`**
Applied to the backbone/TCP interface connecting the slow radio segment to a fast LAN or the internet. Marks the network edge so the transport node doesn't treat the backbone as a client-facing interface for proactive path distribution.

Add announce rate control to the backbone interface to throttle how quickly announces from the wider network are re-propagated onto the radio side:

```ini
announce_rate_target  = 3600   # min seconds between re-announces per dest
announce_rate_grace   = 2      # violations tolerated before enforcement
announce_rate_penalty = 7200   # extended quiet period after a violation
```

### Payload size

MeshCore firmware silently truncates channel messages beyond a hardware-dependent character limit (commonly ~128 chars). The firmware also prepends the sender's node name when relaying channel messages, so the usable character budget for the encoded fragment is:

```
budget = firmware_limit - len(node_name) - 2        # ": " separator
```

Encoded message length for a given payload size:

```
msg_len = ceil((payload_size + HEADER_SIZE) * 4/3) + len("RNS:")
```

With the default 6-byte header and `payload_size = 64`:

```
msg_len = ceil(70 * 4/3) + 4 = 98 chars   →  safe for node names up to ~28 characters at a 128-char firmware limit
```

To size `payload_size` for your own node name length:

```
budget      = firmware_limit - len(node_name) - 2
max_payload = floor((budget - 4) * 3/4) - HEADER_SIZE
```

## How it works

### Wire format

Each RNS binary packet is split into `payload_size`-byte chunks. Each chunk is encoded as a MeshCore channel (or direct) message:

```
"RNS:" + base64url( [frag_idx:1][pkt_id:4][frag_total:1] + payload )
```

Base64 padding is stripped before transmission and restored on receipt.

### Peer discovery

Discovery is demand-driven rather than push/periodic, to minimize channel airtime:

1. A node with no known peers sends `RNSBIND_REQ:<pubkey>:<cap>` on the channel, advertising its own routing capability alongside its identity.
2. Overhearing nodes immediately record the requester (passive learning), wait a random backoff (`BIND_BACKOFF_MIN`–`BIND_BACKOFF_MAX` seconds), then reply with `RNSBIND:<pubkey>:<cap>`. The randomized backoff spreads responses out in time to avoid a simultaneous burst on the shared half-duplex channel.
3. Every node overhearing *any* `RNSBIND` response also records the responder, so a single discovery round passively populates every peer table on the channel.
4. Once peers are known, a quiet `RNSBIND` heartbeat goes out every `BIND_HEARTBEAT_S` (default: 1 hour) — no response is solicited.

The capability suffix (`R` = router, `E` = edge) tells peers at discovery time whether a node has upstream connectivity worth routing transit traffic through. It's recorded and logged but doesn't gate per-packet routing decisions — the interface's live route map is built from observed packet flow, and a path that has demonstrably worked (including through an edge node to reach a downstream client) is used regardless of the advertised capability.

### RNS header parsing

The interface inspects the RNS header byte to distinguish packet types (`DATA`, `ANNOUNCE`, `LINKREQUEST`, `PROOF`) and destination types (`SINGLE`, `GROUP`, `PLAIN`, `LINK`), and locally derives the destination hash for established Links (whose destination field becomes an ephemeral Link ID after handshake) so that direct-message routing continues to work for the life of the Link.

### Delivery confirmation

A MeshCore `MSG_SENT` result only confirms the local radio queued the frame — it isn't end-to-end delivery confirmation. For direct sends, the interface waits on the firmware's follow-up `ACK` event (matched via the `expected_ack` tag from `MSG_SENT`), bounded by `direct_ack_timeout` and a hard ceiling `direct_ack_timeout_max` so that a flood-mode peer with a long firmware-suggested timeout can't stall every other fragment behind it in the shared outgoing queue. A failed or unacknowledged direct send falls back to a channel broadcast.

## Transports

| Transport | Config keys |
|---|---|
| Serial (default) | `port`, `baudrate` |
| TCP | `host`, `tcp_port` |
| BLE | `ble_name` (blank = connect to first device found) |

## Tuning reference

| Key | Default | Purpose |
|---|---|---|
| `payload_size` | `64` | Fragment payload size in bytes; see [Payload size](#payload-size) |
| `fragment_delay` | `2.5` | Seconds between channel-mode fragments |
| `direct_frag_delay` | `0.5` | Seconds between direct-message fragments |
| `fragment_timeout` | `300` | Reassembly window for incomplete multi-fragment packets |
| `direct_ack_timeout` | `4.0` | Minimum wait for a direct-send delivery ACK |
| `direct_ack_timeout_max` | `8.0` | Hard ceiling on the ACK wait regardless of firmware suggestion |
| `outgoing_announce_rate` | `600` | Minimum seconds between announces per destination (`0` disables) |
| `outgoing_path_req_rate` | `1800` | Minimum seconds between path requests per destination (`0` disables) |
| `rate_limit` | `0` | Optional hard bandwidth cap in bits/second (`0` disables) |
| `allow_direct` | `yes` | Use unicast direct messages when a route to the peer is known |
| `peer_ttl` | `86400` | Seconds before a silent peer is dropped from the peer table |
| `can_route` | `yes` | Whether this node can carry transit traffic |
| `debug_level` | `info` | `info` or `debug` |

## Raw transport (`MeshCore_Raw_Interface.py`)

A second interface, `Interface/MeshCore_Raw_Interface.py`, carries the tunnel as **binary MeshCore payloads** instead of text messages. It keeps the peer-discovery, routing and rate-limiting design above but changes what goes on the air:

| | Text tunnel (`MeshCore_Dynamic_Interface`) | Raw tunnel (`MeshCore_Raw_Interface`) |
|---|---|---|
| Broadcast (announces, path requests, discovery) | Channel **text** message, base64, `"RNS:"` prefix, firmware adds `"name: "` | Channel **datagram** (`PAYLOAD_TYPE_GRP_DATA`, `CMD_SEND_CHANNEL_DATA`), binary, channel-encrypted, flood-routed |
| Unicast to a known peer | Direct **text** message, per-contact encryption, ACK wait | **Raw custom packet** (`PAYLOAD_TYPE_RAW_CUSTOM`, `CMD_SEND_RAW_DATA`) on an explicit repeater path; no MeshCore encryption or ACK — RNS already provides both |
| Fragment payload | 64 B (≈128-char text limit) | 140 B raw / 148 B channel |
| 500-byte RNS packet | 8 fragments | 4 fragments |
| Dependencies | `meshcore` library | none beyond `rns` (+ `pyserial` for serial, `bleak` for BLE) |

The two formats do **not** interoperate: every node on a tunnel must run the same interface.

### Why two primitives

MeshCore firmware only sends raw-custom packets on a *direct* route: `CMD_SEND_RAW_DATA` with no path returns `ERR_CODE_UNSUPPORTED_CMD` for flood, receivers drop raw packets that arrive by flood, and repeaters never re-broadcast them. Anything that has to reach every peer therefore goes as a channel datagram, which repeaters flood like any group message. Raw packets *are* forwarded by repeaters along an explicit path, which is what unicast uses once a path is known.

### Wire format

Every datagram, on either primitive, starts with a 14-byte header:

```
off size field
0   1    magic       0x52 ('R')
1   1    type/flags  low nibble: 0 = RNS fragment, 1 = BIND_REQ, 2 = BIND;  bit 4 = can route
2   4    src         first 4 bytes of the sender's MeshCore public key
6   4    dst         first 4 bytes of the target's key, or 00000000 = broadcast
10  2    pkt_id      big-endian, per-sender rolling
12  1    frag_idx
13  1    frag_total
14  ...  payload     RNS fragment, or the sender's full 32-byte key for BIND / BIND_REQ
```

Raw packets carry no MeshCore addressing and every radio in earshot of the last hop hands them to its app, so receivers drop anything whose `dst` is neither zero nor their own prefix. Discovery is the same `BIND_REQ` / `BIND` dance as the text tunnel, in binary, and the full key it carries lets the receiver add a contact and run MeshCore **path discovery** (`CMD_SEND_PATH_DISCOVERY_REQ`) so that raw sends have a path. Until a path is known, unicast traffic falls back to channel datagrams.

### Sizes

Companion frames must fit one BLE ATT write (firmware negotiates MTU 176 → 173 bytes per frame, in both directions), so the defaults keep every command and push frame at or under 173 bytes: `raw_payload_size = 140` (cmd frame `2 + hops + 14 + 140`, fine to 17 hops) and `channel_payload_size = 148` (`162 ≤ MAX_GROUP_DATA_LENGTH = 165`). Over serial or TCP the same limits apply, since the firmware's frame buffer is 176 bytes.

**Raw paths and hash size.** `CMD_SEND_RAW_DATA` takes the repeater path plus a `path_len` byte. The **v1.17.1 release** reads that byte as a plain byte count, so it only works with 1-byte repeater hashes; firmware **`dev`** (next release) and **openHop** read MeshCore's encoded form (`hash_mode << 6 | hops`) and accept multi-byte hashes. For 1-byte-hash paths the two agree. `raw_path_hashes = auto` (default) sends the contact's native hash size and, if the radio rejects it, truncates every hop to its first byte for the rest of the session (a 1-byte hash is a prefix of the longer one, so repeaters still match). Set `native` or `1byte` to force either.

### Requirements

- Companion firmware with `CMD_SEND_RAW_DATA` (25) and `CMD_SEND_CHANNEL_DATA` (62) — **v1.17** has both. Older firmware answers `ERR_CODE_UNSUPPORTED_CMD`; the interface logs it and keeps running channel-only if at least that command works.
- **openHop** repeaters: the virtual companions (`companions[].tcp_port` in `config.yaml`) implement both commands and the matching pushes, and the repeater forwards raw packets on a direct path and floods channel datagrams. Use `transport = tcp` against the companion's port (one client per companion at a time).
- Transports: `tcp` (any Python), `serial` (`pyserial`), `ble` (`bleak`).

### Configuration

```ini
[[MeshCore Raw]]
  type = MeshCore_Raw_Interface
  interface_enabled = yes
  mode = access_point

  transport = tcp            # tcp | serial | ble
  host = 127.0.0.1           # tcp: companion firmware over WiFi, or an openHop virtual companion
  tcp_port = 5000
  # port = /dev/ttyUSB0      # serial
  # baudrate = 115200
  # ble_name =               # ble: substring of the advertised name, or
  # ble_address =            #      a MAC / UUID; blank = first MeshCore found
  # ble_pin =                # optional pairing PIN

  channel_idx = 0
  channel_name = RNSTunnel
  channel_secret = <32 hex chars>   # openssl rand -hex 16
  data_type = 0xFFFF         # GRP_DATA data_type; 0xFFFF is MeshCore's app namespace

  # Flood scope - confines this interface's flood sends (self adverts, BIND
  # broadcasts, channel datagrams) to one named MeshCore region instead of the
  # public unscoped mesh. A repeater configured for a different region (or none)
  # won't relay them - this is the same mechanism as a repeater's own
  # mesh.default_region (openHop) / named region (firmware), applied to what a
  # companion transmits rather than what a repeater relays by default.
  # Leave both unset for today's behaviour (unscoped).
  flood_scope = sco          # public region name; key is sha256("#" + name)[:16],
                              # byte-identical to openhop_core get_auto_key_for()
  # flood_scope_key = <32 hex chars>   # overrides the derived key - required for
                              # a private "$region" whose key the name can't
                              # reproduce; takes precedence over flood_scope if both are set

  raw_payload_size = 140
  channel_payload_size = 148
  fragment_delay = 2.5
  direct_frag_delay = 0.5
  fragment_timeout = 300
  outgoing_announce_rate = 600
  outgoing_path_req_rate = 1800
  rate_limit = 0
  allow_direct = yes
  path_discovery_rate = 600      # min seconds between path discoveries per peer
  path_discovery_timeout = 20
  advert_on_start = yes          # one flood self-advert so peers get a contact for us
  can_route = yes
  peer_ttl = 86400
  debug_level = info
```

### Using it from rnsd, MeshChatX and Sideband

- **rnsd / any Reticulum ≥ 1.x**: copy the file to `~/.reticulum/interfaces/` and add the block above.
- **MeshChatX**: *Settings → Interfaces* can install a custom interface module; upload `MeshCore_Raw_Interface.py`, then add an interface of type `MeshCore_Raw_Interface` with the keys above (or import the config block). MeshChatX ships `pyserial` and `bleak`, so TCP, serial and BLE all work.
- **Sideband**: desktop Sideband uses `~/.reticulum`, so the rnsd route works. To avoid config files entirely — and on **Android**, where there is no `~/.reticulum` to edit — use the service plugin in `sideband/meshcore_raw_service.py`: copy it together with `MeshCore_Raw_Interface.py` into the Sideband plugins directory, edit the `CONFIG` block at the top, enable *Service plugins*, restart. The Android build has neither `pyserial` nor `bleak`, so on a phone only `transport = tcp` works (an openHop virtual companion on the LAN, for example).

### Testing without hardware

```bash
pip install rns pytest pytest-timeout
pytest tests/
```

`tests/fake_companion.py` is a fake companion mesh speaking the real frame protocol over TCP; the loopback test brings up two interfaces against it and checks discovery, a channel-carried announce, a raw-carried unicast after path discovery, and that no frame exceeds the BLE budget.

### Raw-tunnel limits

- No delivery ACK on raw sends: a stale repeater path silently loses fragments until the next (rate-limited) path discovery. RNS links retry; single datagrams do not.
- Raw packets are not MeshCore-encrypted; the 14-byte header is visible on air. The RNS packet inside is encrypted end-to-end as always.
- Multi-hop *flood* of raw packets is a firmware limitation ("don't flood route these (yet)").

## Limitations

- MeshCore's channel-message character limit varies by firmware build and must be accounted for when choosing `payload_size` (see [Payload size](#payload-size)).
- `access_point` mode suppresses announce re-broadcasting but not `DATA`+`PLAIN` path requests; a node that flaps offline can still generate path-request traffic on the LoRa channel from remote nodes searching for it. Use `outgoing_path_req_rate` to bound this.
- This interface is built and tested against a specific `meshcore` library API surface; firmware/library version drift may require updates to event/attribute names.

Yes, I absolutely had help from Claude on this. I'm not a software person, I'm just stubborn enough to think I can beat my head against something until it works. PLEASE feel free to offer improvements and corrections.
