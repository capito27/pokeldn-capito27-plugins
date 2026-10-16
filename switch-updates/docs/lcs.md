# Match Version With Local Users (nn::lcs)

**Match Version With Local Users** lets nearby consoles form a group for one game and bring everyone
up to the newest version of it in the group, and to the system version that version needs, without
the internet. It is per game: on the HOME Menu, highlight the game, press + for its options, then
**Software Update → Match Version With Local Users → Next**. That screen offers *Create Group* and
*Join Group*, and promises "everyone's software will be updated to match the most recent version
in the group."

This is Nintendo's **Local Content Sharing**, `nn::lcs`. On the Switch it lives inside **qlaunch**
(`0100000000001000`, the HOME applet), not in a separate system module, and drives `ns` and `nim`
for the actual transfers. It rides on the same LDN local wireless layer this project already speaks
([the wireless layer](https://github.com/Decryptu/pokeldn/blob/main/docs/ldn.md)). This page covers the Switch; the Switch 2 differences are noted
under [The LDN layer](#the-ldn-layer).

## Sources and confidence

Three kinds of source feed this page, ranked:

1. **Live captures** of pokeldn joining a Switch's group, taken 2026-10-13
   ([Testing against a console](#testing-against-a-console)). They outrank everything below.
2. **Our own reverse engineering** of a retail **firmware 20.5.0** dump (qlaunch, `ns` and `nim`
   program NCAs; see [reverse-engineering a Switch title](https://github.com/Decryptu/pokeldn/blob/main/docs/switch_re.md) for the extraction
   method). Addresses are file offsets into the decompressed `main` of the named title at 20.5.0 and
   will differ on other firmware.
3. **Public documentation:** switchbrew's
   [NS services](https://switchbrew.org/wiki/NS_services),
   [NIM services](https://switchbrew.org/wiki/NIM_services),
   [System Settings](https://switchbrew.org/wiki/System_Settings) and
   [Error codes](https://switchbrew.org/wiki/Error_codes) pages, and libnx's
   [`ns.h`](https://github.com/switchbrew/libnx/blob/master/nx/include/switch/services/ns.h). Taken
   as **high confidence**: it agrees with our own reading everywhere the two overlap, and where it
   was spot-checked against 20.5.0 it still held.

Public documentation covers `ns`, `nim`, the delivery infos and the **55556 content channel**. It
says nothing about the **55555 control channel** or the LDN parameters; those rest on our own
reading alone.

| Area | Source | Confidence |
|---|---|---|
| LDN parameters | own | high — read from qlaunch's `ldn:s` calls |
| LDN protocol (NX, `1`) | switchbrew, own | high — qlaunch makes no `SetProtocol` call, and `ldn`'s initialization selects NX |
| Advertise data | own | proven — qlaunch's builder and the guest's parser, run under unicorn, agree with `switchlcs.advertise` |
| 55555 framing and dispatch tables | own | high — read directly |
| 55555 message layouts | own | proven — every qlaunch sender, run under unicorn, emits the bytes `switchlcs.control` builds |
| 55555 message meanings and directions | own | high for the transfer commands (`ns` command IDs), medium elsewhere — see the per-row notes |
| 55555 session flow | own | medium — the handlers and the host's system and game-update orchestration read from qlaunch; the planner's choice of sender not read; pokeldn's guest has run against a console, its host only against pokeldn's guest |
| Delivery-info layouts and field meanings | switchbrew, libnx, own | high — sizes and offsets match `ns` |
| Delivery-info MAC: HMAC-SHA256 under two firmware-static keys | own, switchbrew | proven — 20.5.0 `ns`'s MAC routine, run under unicorn, returns HMAC-SHA256 |
| Join-gate checks and their settings | own, switchbrew | proven — `ns`'s validators, run under unicorn, agree with `switchlcs.delivery` on every case |
| Sender selection ("newest wins") | switchbrew | high |
| 55556 roles, framing and messages | switchbrew, own | high — header builders, request set, reply sizes and the `0x3`/`0x4` bodies read in 20.5.0 `nim` |
| pokeldn's 55556 client and server | own | tested against each other on the Pokémon Violet update, Let's Go's over pokeldn's own TCP, and 20.5.0's system update as installed by Ryujinx; against a console, the client received Let's Go's update and 23.0.1's system update whole, and the console installed what the server sent |

## Goals

pokeldn's lcs client lets people use their own console's update sharing from a PC:

1. **Back up their own system updates for emulation.** pokeldn joins a group as the
   *older* member, so the console sends it the system update; the received NCAs are the firmware
   an emulator installs.
2. **Back up their own game updates** the same way, by advertising an older version of an
   application the console has. lcs moves game **updates** (patches) only, never base games or
   DLC, and the update's ticket travels with it.
3. **Serve a backed-up game update back to their own console.** A speedrunner whose category
   depends on a game version Nintendo has since replaced can factory-reset the console, reinstall
   the game from its cartridge, and take the older update from pokeldn instead of the current one
   from the eShop.

The first two make pokeldn the **receiver** of a transfer; the third makes it the **sender**. When
pokeldn **hosts** the group, it picks the direction itself: the host names the sender and receiver in
each transfer command, and a guest carries out the command without comparing versions
([Session flow](#session-flow)). The console's `ns` still applies its own checks to what it installs.
When pokeldn **joins** a console's group, the "newest version wins" rule decides instead, and pokeldn
steers it through the version it advertises (see [Which side sends](#which-side-sends)).
`tools/lcs_host.py` is the host, for development: `--backup-system`, `--backup-app` and `--serve` are the
three goals. `lcs_match.py`, the plugin's **Match Version** tool, joins a console's group, shows its game, then
backs up the console's update (`--pull`), sends it a newer one from the library (`--offer NSP`) or backs up its
system update (`--system`); run without them, it lists what the console can take and asks.

## The LDN layer

qlaunch forms the group through `ldn:s` (`ISystemLocalCommunicationService`) with these parameters
(`CreateNetwork` call at `0x42eeb0`):

- Communication ID `0x0100000000001000` (qlaunch's own program ID), scene `1`, channel `0` (`ldn`
  chooses), up to 8 nodes.
- `localCommunicationVersion` `1`: the high nibble of the lcs version byte `0x13`, which also opens
  every join and the advertise data.
- Security mode `1` with a 16-byte passphrase `2d30885a658ab4e4d85092ed525a994c`.
- Node user names `LcsHost` for the host and `LcsClient` for a guest.
- **LDN protocol `1` (NX)**: qlaunch never calls `SetProtocol`, and switchbrew documents that `ldn`'s
  initialization selects NX. The advertisement is therefore AES-CTR under `master_key_00`, as Sword's
  Mystery Gift screen's is ([the wireless layer](https://github.com/Decryptu/pokeldn/blob/main/docs/ldn.md#discovery)).

The host calls `CreateNetwork`, or `CreateNetworkPrivate` to resume a group after a reboot; a guest
uses `ConnectPrivate`. `switchlcs/advertise.py` holds these parameters.

### The advertise data

The host publishes 0x100 bytes with `SetAdvertiseData`: built by `0x432fd0`, then updated in place as
members join and the share progresses (setters `0x433158`–`0x433190`). A guest reads them back with
`0x4331f0`, which drops a group whose counts fail its checks (more than one application, a maximum
outside 1–8, or a member count of 0 or above the maximum):

```
offset  size   field
0x00    1      lcs version, 0x13
0x01    1      state: 1 when built, 2 for a resumed group
0x02    1      member count, the host included (1 when built)
0x03    1      maximum members, 1–8
0x04    1      application count, 0 or 1
0x05    1      set later by 0x4331d4; not identified
0x06    1      set later by 0x433184; not identified
0x08    8      two u32 set later by 0x4331cc; not identified
0x17    0x81   the host's user name, NUL-terminated
0x98    0x40   8 × {u8, u8, 2 zero, BE u32}, filled by 0x433190; the block 0x1c carries
0xd8    0x28   the application:
                 u8 4, 3 zero
                 BE u32  the NACP's attribute flags (application info +0x8)
                 BE u64  application ID
                 BE u64  the installed update's size: 0 when built, then set from the host's
                         application record (0x433160); 0 with no update
                 16      display version (application info +0x18)
```

The application fields come from the same 0x80-byte application info a join carries, built by
qlaunch's `0x432ad0`: the ID, the NACP's attribute flags (NACP `+0x3028`), `ns`'s
`EstimateRequiredSize` over the content metas `ListContentMetaKeyToDeliverApplication` names (`+0x10`),
and the NACP's display version (`+0x18`). **There is no internal version in it**: a console names
its installed update only by size and display version until its delivery info arrives in the `0x09`
after the join. A console with Let's Go, Pikachu! 1.0.2 (v131072) installed advertised attribute
flags 0, an update size of 39,822,848 bytes and `1.0.2`. A game without an update, a Shield
cartridge or an archived Let's Go, is advertised with a size of 0 and an empty display version,
not the base game's.
`switchlcs/advertise.py` builds and parses it. `tools/lcs_qlaunch_check.py` runs qlaunch's
builder on chosen settings, comparing the bytes, and qlaunch's guest parser on pokeldn's bytes,
comparing what it reads out.

**Ethernet is not an escape hatch.** Tested on a live docked console (2026-10-12): the wired
Ethernet IP stops answering ping the moment the console creates or joins a group. The radio is
committed to LDN for the duration, so *all* lcs traffic — both the control channel and the bulk
content transfer below — has to travel over LDN. There is no path that moves the heavy transfer
onto the LAN.

**Switch 2** moves lcs out of qlaunch into its own `lcs` service (firmware 20.1.0+), and runs it on
LDN protocol 4, whose keys are Switch 2–only. Per switchbrew, those keys are used when a Switch 2
hosts an update of a Switch 2–only game, or of a Switch 1 game that has a Switch 2 Edition. The
parameters above are the Switch's.

## The control channel — TCP 55555

*Own reverse engineering only; no public documentation exists.*

The host `listen()`s on TCP port 55555. Each guest binds its own local port 55555 and connects to
the host's LDN IP. On the host object the accepted guest socket fd is kept at `+0xb0`; on the guest
object the host's IP is at `+0xb8`.

### Framing

Every message is an 8-byte header followed by a payload:

```
offset  size  field
0       1     0x10         constant
1       1     type         message type
2       2     0x0000       reserved / zero
4       4     length       payload length, big-endian u32
```

Integers that qlaunch writes into payloads itself are **big-endian** (it calls `htonl`/`htons` on
them). Lists are serialised as fixed-size entries — 0x10-byte records for key lists, 0x100-byte blobs
for delivery infos. The delivery-info blobs are `ns` structures carried as opaque bytes, so they keep
`ns`'s little-endian layout (their MAC covers the raw bytes). The receive wrapper (qlaunch `0x434680`)
uses `MSG_PEEK` to read the header, waits until the whole message is buffered, and only then
consumes it; sends loop on `poll(POLLOUT)` under a mutex. This means a reader can treat the stream as
cleanly message-framed.

### Dispatch

The host dispatches received types `0x01`–`0x1b` through a jump table (`0xf237e5`, based at
`0x429ba4`) and handles `0x01`, `0x03`, `0x05`, `0x06`, `0x0d`, `0x0f`, `0x11`, `0x13`, `0x15`, `0x17`,
`0x18`, `0x19`, `0x1a` and `0x1b`. The guest dispatches `0x07`–`0x1c` (`0xf237b1`, based at
`0x423088`) and handles `0x07`–`0x0c`, `0x0e`, `0x10`, `0x12`, `0x14`, `0x16` and `0x1c`. Every other
type is consumed and ignored. Both roles are the *same* qlaunch binary.

### Message catalog

Direction is H→G (host to guest) or G→H. Every layout below is proven: qlaunch's own senders, run
under unicorn by `tools/lcs_qlaunch_check.py`, emit exactly the bytes `switchlcs/control.py`
builds. The exception is `0x01` / `0x03`, which have no sender; their layout is what the host reads.
"Conf." is the confidence in the *meaning*.

| Type | Dir | Conf. | Payload and meaning |
|---|---|---|---|
| `0x01` / `0x03` | G→H | high | **Control-data query**, `{BE u64 application ID}` (read by the host at `0x429c78` / `0x429cf8`). The host fetches `ns`'s `GetApplicationControlData` for that game (`0x432c80`) and answers `0x02` to `0x01`, `0x04` to `0x03` (`0x433330`). The dispatch has no join-state check, so it is answered before a `0x05` too. Any `ns` error aborts qlaunch (`0x433404`), so ask only for the game the group advertises. **No sender in qlaunch.** |
| `0x02` | H→G | high | `{BE u64 application ID, BE u32 size}`: the size of the control data. The guest does not handle it. |
| `0x04` | H→G | high | The `0x02` layout followed by `size` bytes of control data: the 0x4000-byte NACP (the title name and publisher per language at `0`, the display version at `0x3060`), then the icon, a JPEG. The guest does not handle it. |
| `0x05` | G→H | high | **Join**, layout below. |
| `0x06` | G→H | high | **Leave**, `{u8 kind, 3 zero}`. Kind `1` means the guest will return (a reboot), and the host keeps its node; any other kind drops the node. |
| `0x07` | H→G | high | **Accept**, `{BE u32 node ID}`. The guest checks only the length. A console gave itself `0x4016b8e8` and pokeldn `0x4016b8e9`: not small integers. |
| `0x08` | H→G | high | **Reject**, `{u8 reason, 3 zero}`; see [Reject reasons](#reject-reasons). |
| `0x09` | H→G | high | **Snapshot**: `{u8 application count, u8 node count (at most 8), 6 zero}`, the application records (as in the join), then per node `{BE u32 node ID, 7 zero, 0x81-byte name}`. Sent to every member when one joins or leaves. Each game's record is the host's own, from `GetApplicationDeliveryInfo`, so its delivery info carries the host's `RequiredApplicationVersion`. A member's record replaces it only when `HasAllContentsToDeliver` passes on it on the host and `CompareApplicationDeliveryInfo` ranks it newer (`0x4307b0`): with Let's Go archived on the console, the first `0x09` after pokeldn's join at v131072 carried pokeldn's own delivery info, byte for byte (seen live). The console's own version is then not in the snapshot. |
| `0x0a` | H→G | high | **Start share**, empty. The guest answers with a `0x18` refresh and enters state 4; its worker thread acts on transfer commands only in that state. |
| `0x0b` | H→G | med | A 0x580-byte block, stored for the share. |
| `0x0c` | H→G | high | **Suspend**, `{u8 kind, 3 zero}`, sent to a member before it receives a system update. Kind `1` before the share's first one (`0x42a080`): the guest answers `0x0d` with `0` and enters state 6, suspended, unless a flag of its own (`+0xab`) is set, when it answers `2`. Kind `2` on later passes (`0x42a2b0`): the guest answers `2` and stays as it is. A guest already suspended first answers `0`; any other kind gets no answer (`0x42568c`). |
| `0x0d` | G→H | high | `{u8 result, 3 zero, 0x100 bytes}`. Result `0` marks the node ready; `1` makes the host reject that node with reason 6; `2` leaves its state as it is (`0x42d580`). |
| `0x0e` | H→G | high | **Send your system update to the peer**: `{u8 kind 1, u8 0x14, u8 flag, 0, BE u32 peer IP, BE u32 peer node ID, 4 zero, 0x100 zero}`. The guest replies `0x0f` at once, then calls `ns`'s `RequestSendSystemUpdate(peer IP, 55556, its own SystemDeliveryInfo)`, which listens on 55556 for the peer. The flag is `1`: qlaunch sends `0x0e` only to have one member send to another. |
| `0x0f` | G→H | high | `{u8 2, 3 zero, the guest's own SystemDeliveryInfo}`. |
| `0x10` | H→G | high | **Receive the system update from the peer**: the `0x0e` layout with kind `2` and the sender's `SystemDeliveryInfo`. The guest replies `0x11` with kind `2` at once, then calls `RequestReceiveSystemUpdate(peer IP, 55556, that info)`, which connects to the peer. The flag is `0` when the peer is the host itself and `1` when it is another member, as in `0x14` and `0x16`. The guest stores it with the transfer; where it is read was not found. |
| `0x11` | G→H | med | `{u8 kind, 3 zero, 0x100 bytes}`. The host treats kind `0` as done. |
| `0x12` | H→G | high | **Prepare an application**, `{u8 4, 3 zero, BE u64 application ID}`. The guest answers `0x13` with `2` when it can proceed; when it cannot (presumably the game is running), it answers `0`, enters state 6 and sends `0x1a` once it can. |
| `0x13` | G→H | high | `{u8 result, 7 zero}`. |
| `0x14` | H→G | high | **Send this application's update to the peer**: `{u8 kind 1, 04, 14, u8 flag, u8 0, 3 zero, BE u32 peer IP, BE u32 peer node ID, BE u64 application ID}`. The guest answers `0x15` with what it can deliver, then calls `RequestSendApplication`, which listens on 55556. |
| `0x15` | G→H | high | `{u8 2, u8 count, 6 zero}` + count × 0x10-byte content-meta keys (little-endian: u64 ID, u32 version, u8 type, u8 install type, 2 padding). Kind `0` means nothing to send. |
| `0x16` | H→G | high | **Receive these content metas from the peer**: the `0x14` layout with kind `2` and the key count, then the keys (at most 0x12, all Patch). The guest answers `0x17`, calls `RequestReceiveApplication`, which connects to the peer, and once installed sends a `0x18` refresh with its new delivery infos. |
| `0x17` | G→H | med | `{u8 result, 7 zero}`: `2` when the guest goes ahead, `1` when it cannot. |
| `0x18` | G→H | high | **Join refresh**: the `0x05` layout with byte 2 set by the caller (builder `0x434b30`). After installing a game update, the member's refresh must name the new version, in a delivery info with attribute bit 28 set as a console's own are (`0x50000002`). `CanDeliverApplication` lets a sender at an equal version deliver to a receiver without bit 28, so a console host otherwise sends the update again, without end (seen live). |
| `0x19` | G→H | low | 8-byte body; the host marks the node done. **No sender in qlaunch.** |
| `0x1a` | G→H | med | Empty: the guest is ready again (after a `0x13` of `0`, or once a suspended transfer is over). The host marks the node ready and re-sends snapshots. |
| `0x1b` | G→H | low | The host runs the join validator again and marks the node ready, like a rejoin. **No sender in qlaunch.** |
| `0x1c` | H→G | high | **Share completed**, a 0x40-byte block (the advertise data's `+0x98`). A 20.5.0 guest requires the block, stores it and moves to state 7; qlaunch sends the empty form only to guests whose join version is `0x10` or `0x11`. |

The transfer directions follow from the `ns` interfaces the guest calls: `ISystemUpdateControl`'s
`RequestReceiveSystemUpdate` from the `0x10` handler (`0x42595c`), `RequestSendSystemUpdate` from the
`0x0e` path; the host itself calls `RequestSendSystemUpdate` (command 17) when it is the sender. The
port is never on the wire: both sides use 55556.

### The join (`0x05`)

Built by the guest at qlaunch `0x4349a0` and parsed by the host at `0x42da40`. The header's length is
0x188 plus the application records:

```
offset  size   field
0x00    1      version, 0x13
0x01    1      application record count; the host refuses more than 1
0x02    1      0 (set in a 0x18 refresh)
0x03    0x81   user name, NUL-terminated
0x84    4      zero
0x88    0x100  the guest's SystemDeliveryInfo
0x188          per application record:
        1        N, the number of ApplicationDeliveryInfos, at most 0x10
        7        zero
        0x80     ns's application info: the application ID (+0x0, little-endian), the version
                 (+0x8) and the display version (+0x18)
        N×0x100  ApplicationDeliveryInfos
```

### Reject reasons

The reason in `0x08` indexes a table (`0xf23884`) of the `2211-xxxx` codes the guest displays. The
host sends the reason whose code its join validator returned:

| Reason | Code | Sent when |
|---|---|---|
| `1` | `2211-0232` | the validator returns `2211-0232` or `2211-0235` |
| `2` | `2211-0260` | the group is not taking members, or the validator returns `2211-0260`–`0263` |
| `3`–`8` | `2211-0256` | the validator returns `2211-0256`–`0287` (3); a member answers `0x0d` with `1` (6) |
| `9` | `2211-0233` | the validator returns it |
| `10` | `2211-0234` | the validator returns it |

### Session flow

**Nodes.** The host enters each LDN station into an 8-entry node table (`0x42fab0`) with its IP and
MAC, and numbers the nodes from 1. Its accept loop (`0x429a5c`) takes a 55555 connection only from an
IP in that table and closes any other. The node ID travels in `0x07`, `0x09` and the transfer
commands; it is not the IP.

**Joining.** The guest connects and sends `0x05`. The host validates it (`0x42d2e8`), answers `0x07`
with the guest's node ID, and sends every member a new `0x09`.

**Starting.** The host sends `0x0a`; each guest answers `0x18` and enters state 4.

The host's share loop (`0x429f60`) runs the system update before the game update. Each step takes
one receiver and one sender from a planner (`0x42b5a0` for the system update, `0x42bed0` for the game
update), whose choice was not read.

**System update** (`0x42b6e0`). The host suspends the receiving member with `0x0c` and waits for its
`0x0d`. When the host is the sender, it starts its own `RequestSendSystemUpdate` toward the receiver
and sends it `0x10` naming itself, flag `0`. When another member is the sender, the host sends it
`0x0e` naming the receiver (flag `1`), and once that member's `0x0f` arrives with its
`SystemDeliveryInfo`, sends the receiver `0x10` naming the sender with that info (flag `1`). The host
never receives a system update itself: that case ends in qlaunch's abort routine (`0x42bbc0`).

**Game update** (`0x42c040`). When the host is the sender, it sends the receiver `0x12`, waits for its
`0x13` (or the `0x1a` that follows a `0`), starts its own `RequestSendApplication` toward it and sends
`0x16` naming itself, flag `0`. When the host receives, it sends the sending member `0x14` naming
itself, flag `0`, with no `0x12` first, and pulls the keys the `0x15` lists. Between two members it
sends the receiver `0x12`, the sender `0x14` naming the receiver (flag `1`), then the receiver `0x16`
naming the sender (flag `1`).

**Completing.** The host sends `0x1c` to every member (`0x42ca50`).

The guest's states, in order, are `1` initialized, `2` opened, `3` joined, `4` transferring, `5`
failed, `6` suspended and `7` completed (setter `0x4212d0`, getter `0x432404`; a failure reason is
stored at ctx `+0x446a0`). The control flow through these values is clear; the *names* are from SDK
recollection. The lcs result module is `0xd3` (211), so errors surface as `2211-xxxx`.

`switchlcs/session.py` implements both roles on top of `control.py` and `content.py`. `Host` admits
a guest (validating its delivery infos), starts the share, and runs the three goals:
`pull_system_update` (`0x0e` naming pokeldn, then a 55556 pull), `pull_application` (`0x14`, the
`0x15` keys, then a pull) and `push_application` (listen on 55556, `0x12`, `0x16`, serve, wait for
the `0x18`); `finish` sends `0x1c`. Each transfer command names pokeldn with flag `0`, as qlaunch's
host names itself. `pull_system_update` has no qlaunch counterpart, since a console host never
receives a system update. `push_system_update` is a console host sending its own system update, as
qlaunch's does: `0x0c` of kind `1` suspends the member until its `0x0d`, then, with the host listening
on 55556, `0x10` names the host; a `0x11` of kind `0` declines. It serves from `content.DirSource`, a folder of
installed NCAs (a library's `System update <version>.zip`, which `tools/lcs_host.py` unpacks, or Ryujinx's
`bis/system/Contents/registered`,
where each `<content id>.nca` is a folder of parts), whose Meta NCAs it finds by their header. A guest
replies before its `nim` task listens, so a refused
55556 connect is retried for 10 seconds. `Guest` answers as qlaunch's guest does and stands in for a
console in `tests/test_lcs_session.py`, which runs them against each other over pokeldn's userspace TCP,
and runs `tools/lcs_host.py` end to end across two simulated ESP32 boards: the guest scans for the lcs
group, joins with the lcs passphrase, and has its system update pulled.

**pokeldn joining a console's group.** A guest can learn what the console offers before it commits
to anything, and then choose the direction:

1. The scan's advertisement names the group, the game (application ID), the installed update's
   size and display version (not its internal version), and the member count ([The advertise data](#the-advertise-data)).
2. After the LDN connect, a 55555 connection and a `0x03` for the advertised game return its NACP
   and icon (`session.query_control`): the title in every language, the publisher and the display
   version.
3. pokeldn then builds its `0x05` from the user's choice, since the direction of each transfer follows
   from the delivery infos in it ([Which side sends](#which-side-sends)): an application version below
   the console's to pull its update, the backed-up version above it to offer that one.
   `Guest.run` continues on the queried connection.

The console's own system version is not visible to a guest; it arrives only in a `0x10`, when the
console sends its system update. The system update version pokeldn claims steers that transfer too:
a console sends its system update first to a member that is to receive its game update and is below
the system version that update requires (seen live). A console host never receives a system update
([Session flow](#session-flow)), so a claim above the console's has no transfer to lead to. The
choice is made with the join; after a system update, the `0x18` refresh that names the game at the
console's version makes the console end the share without sending its game update (seen live).
`lcs_match.py` is the joining side. `tools/lcs_host.py --console NSP` stands in for a console host:
it advertises the game installed from the NSPs (its highest Patch version, and the newest NSP's
display version), answers `0x03` from a Control NCA (`content.nsp_control_data`, or `--control-from`)
and lets the newer side send if `ns`'s `CanDeliverApplication` allows it (`Host.match_application`;
`--required-version` sets the newest version the stand-in has run). With `--system DIR` it also has a system update installed: the group claims its version,
and a member on an older one is sent it first (`Host.push_system_update`).
`tools/lcs_simulate.py pull|offer|system` runs the two against each other: `pull` gives the
console the update and has pokeldn take it, `offer` gives the console the base game and has pokeldn
send the update, and `system` gives the console a system update (Ryujinx's installed 20.5.0, 356 MB
in 235 NCAs) and has pokeldn join claiming `0.0.0`, as the tool's system backup does. It
then compares every received file with its source: the update NSP's entries, the NSP pokeldn packed,
or the installed NCAs: pokeldn saves the update as one NSP at its library's top and the system update as
`System update 20.5.0.zip`. `--capture` records both sides
([Recording a session](#recording-a-session)). Both tools take
`--loopback`, which replaces LDN with the OS's TCP between `127.0.0.1` and `127.0.0.2`
(`switchlcs/loopback.py`; the host serves its advertise data on port 45554 in place of the scan, and
the two protocols run on 45555 and 45556, below the ports Windows reserves for Hyper-V and WSL).
That is the simulator's default transport and moves a 5.2 GB Violet update in about 17 seconds.
`--transport boards` runs the same flow through two simulated ESP32 boards, LDN and pokeldn's
userspace TCP included, at about 1.6 MB/s, so it takes updates up to 256 MiB (LGPE's 34 MB update
takes 26 seconds); `--allow-large` lifts the limit, and `--loss PERCENT` drops that share of the data
frames between the boards at random.

## DeliveryInfo and the join gate

This is the part that decides whether a non-Nintendo client can participate.

### Layout

Both delivery infos are 0x100 bytes: 0xE0 bytes of little-endian data and a 0x20-byte HMAC-SHA256
over them. A console produces its own with `ns`'s `GetSystemDeliveryInfo` /
`GetApplicationDeliveryInfo`. Field meanings and the settings they come from are switchbrew's.

**`SystemDeliveryInfo`**

| Offset | Type | Field |
|---|---|---|
| `0x00` | u32 | system delivery protocol version — setting `contents_delivery!system_delivery_protocol_version` (1) |
| `0x04` | u32 | application delivery protocol version — setting `contents_delivery!application_delivery_protocol_version` (1) |
| `0x08` | u8 | has exFAT (3 reserved bytes follow) |
| `0x0C` | u32 | system update version |
| `0x10` | u64 | old system update ID — from 20.0.0 always the Switch's, `0x0100000000000816` (setting `contents_delivery!old_system_update_id`) |
| `0x18` | u8 | firmware variation ID — setting `ns.systemupdate!firmware_variation` |
| `0x19` | u8 | updatable firmware group ID — setting `ns.systemupdate!updatable_firmware_group_id` |
| `0x1A` | u8 | platform region: `0` global, `1` China |
| `0x1B` | u8 | platform (20.0.0+) — setting `ns.systemupdate!system_delivery_info_platform` |
| `0x1C` | u8 | system update ID flag (20.0.0+): when set, `0x20` is used instead of `0x10`; `GetSystemDeliveryInfo` always sets it (3 padding bytes follow) |
| `0x20` | u64 | system update ID (20.0.0+): the installed system update's ID |
| `0x28` | 0xB8 | reserved |
| `0xE0` | 0x20 | HMAC-SHA256 over `0x00`–`0xDF`, key at `ns` `0x2c3340` |

**`ApplicationDeliveryInfo`**

| Offset | Type | Field |
|---|---|---|
| `0x00` | u32 | application delivery protocol version (4 padding bytes follow) — must lie between settings `contents_delivery!acceptable_application_delivery_protocol_version` (0) and `contents_delivery!application_delivery_protocol_version` (1) |
| `0x08` | u64 | application ID |
| `0x10` | u32 | application version (cleared when the installed content is compacted) |
| `0x14` | u32 | required application version |
| `0x18` | u32 | required system version |
| `0x1C` | u32 | attributes (`ApplicationDeliveryAttributeTag`): the caller's bit 1, plus bits 28 and 30 set by `ns` depending on the content-meta type (Patch, etc.) |
| `0x20` | u8 | content-meta platform (20.0.0+) |
| `0x21` | u8 | proper program exists (20.0.0+) |
| `0x22` | 0xBE | reserved (`0x22` is used on Switch 2) |
| `0xE0` | 0x20 | HMAC-SHA256 over `0x00`–`0xDF`, key at `ns` `0x2c3360` |

### The MAC keys

The two infos are signed under **different keys**, both 0x20-byte constants in `ns` read-only data
and both fed to the same MAC primitive (`ns` `0x31a80`) over 0xE0 bytes:

| Key | Bytes | Generate | Verify |
|---|---|---|---|
| `SystemDeliveryInfo` | `0x2c3340`: `5680121bb673e042…a2fa598f32eccb` | `0x13f45c` | `0x13fab8` |
| `ApplicationDeliveryInfo` | `0x2c3360`: `1ea1fe6a41e2438b…ae5f97c4` | `0x13fe78` | `0x141304` |

The primitive is **pure software** — built from SHA block functions, with no `svc`/`smc`/`mrs` or
keyslot access — and each key is passed to it as a plain pointer. The keys are therefore the same on
every console and extractable from the `ns` image; they are **not** console-unique and do not
involve the security processor. Switchbrew and libnx name the construction HMAC-SHA256, and running
`0x31a80` under unicorn on random inputs gives exactly Python's HMAC-SHA256 under the same key.

`switchlcs/delivery.py` builds, parses and checks both infos. `tools/lcs_ns_check.py` runs
20.5.0 `ns`'s own MAC and validators (`0x13fa5c`, `0x141304`, `0x1412c0`) under unicorn, with the
settings readers patched to the retail values, and compares every verdict with the module's. The
reference blobs in `tests/test_lcs_delivery.py` are ones `ns` accepted.

### The checks on join

When a guest joins, its `SystemDeliveryInfo` arrives inside the `0x05` payload. The host validator
(qlaunch `0x42da40`) copies it out and hands it to `ns`, which runs three checks (`ns` `0x13fa5c`;
this matches switchbrew's description of `ns`'s `VerifyDeliveryProtocolVersion`):

1. **The HMAC** over the first 0xE0 bytes, under the system key.
2. **The protocol versions**, against this console's own settings
   (`contents_delivery!system_delivery_protocol_version` and its application counterpart, read
   through accessors `0x9780c` / `0x97850` / `0x97894`) — not against the host peer.
3. **A system-version floor:** the system update version at `+0xc` must be at least the setting
   `contents_delivery!required_system_version_to_deliver_application` (context `+0x40`). The
   setting defaults to **0**, so on a retail console this check never rejects.

Failures return `2016-0931` (bad HMAC or system update ID), `2016-0801` / `2016-0802` (system
protocol version below / above the setting), `2016-0811` / `2016-0812` (application protocol version
below / above it) or `2016-1110` (below the version floor); the host then sends an `0x08` reject
whose reason maps to the `2211-xxxx` code the UI displays. An `ApplicationDeliveryInfo` is checked
the same way (`0x141304` HMAC, failing with `2016-0930`; `0x1412c0` protocol version).

### Building a valid `SystemDeliveryInfo`

The gate is a MAC under a firmware-static key over a known layout, so pokeldn can build the infos it
advertises. On 20.0.0 and later, `ns` additionally requires (switchbrew):

- **The system update ID** selected by the flag at `0x1C` must be one of the setting
  `contents_delivery!acceptable_system_update_ids_string`
  (`0x0400000000000816,0x0100000000000816`). For an actual system-update transfer it must equal the
  ID of the system update the console has installed.
- **Protocol versions** `1` and `1`.
- **For sender selection** (`SelectLatestSystemDeliveryInfo`), a candidate info is skipped unless:
  its platform region matches the selecting console's; it has exFAT when the selecting console does;
  its updatable firmware group is not `0xFF` and is a valid index into the setting
  `contents_delivery!updatable_firmware_group_string` (`1,3,4,8,23,127,2047,2048,6144` from 20.0.0);
  and that entry has the bit for the selecting console's firmware variation set (which must not be
  `0xFF`).

Copying these fields from a console's own info (captured from its `0x05` join) and changing only the
version is the safe way to build one.

### Which side sends

The "newest wins" decision is `ns`'s, not qlaunch's own logic (switchbrew):

- **System updates:** `SelectLatestSystemDeliveryInfo` takes the members' system infos and their
  application infos. It works out the highest required system version among the application infos,
  drops any system info that fails the checks above, and picks the newest of the rest.
  `CompareSystemDeliveryInfo` compares two system update versions.
- **Game updates:** `CompareApplicationDeliveryInfo` compares two application versions;
  `CanDeliverApplication` decides whether one side can deliver to the other. It refuses when either
  side's required application version is above the sender's version, and otherwise delivers when the
  sender's version is at least the receiver's (strictly higher when the receiver's attribute bit 28
  is set).
- **A receiving console refuses a system update it does not need** (`RequestReceiveSystemUpdate`
  checks before starting), and the transferred game content is always of type Patch.

qlaunch's calls into these have not been located yet. This matters only when pokeldn **joins** a
console's group; as the host it names the sender itself ([Session flow](#session-flow)). As a guest,
the direction of a transfer follows from what pokeldn advertises:

- To **receive** (back up), advertise a lower system update version, or a lower application
  version, than the console has.
- To **send** (serve a backed-up update), advertise the backed-up application version, which must
  be higher than what the console has installed. A sender's update is only deliverable when the
  receiver's system version meets the update's required system version (`ns`'s
  `NeedsSystemUpdateToDeliverApplication`); an older update needs an older system version, so a
  console that is newer than the update is fine.

## The content channel — TCP 55556

*Documented by switchbrew's NIM services page ("Contents Delivery"); the header and request set
confirmed in 20.5.0 `nim`.*

Once a transfer starts, the heavy lifting is done by `ns` and `nim`, not by qlaunch.
`ns`'s `RequestSendSystemUpdate` / `RequestReceiveSystemUpdate` and `RequestSendApplication` /
`RequestReceiveApplication` create `nim` `LocalCommunication` tasks, and qlaunch passes them port
**55556**. The peer IP comes from the `0x0e`/`0x10`/`0x14`/`0x16` command on 55555 (the BE u32 field).

### Roles

- **The sender is the server.** Its `nim` task binds `INADDR_ANY:55556`, listens with a backlog of 1,
  and accepts connections until one comes from the IP it was given; others are closed.
- **The receiver is the client.** It connects to the sender's IP and port, with a 5-second connect
  timeout.
- **The receiver drives the transfer.** The sender only answers requests, in any order, until it
  receives message `0x0` or an error.

### Framing

Every message — request or reply — starts with a 16-byte little-endian header, followed by the data:

```
offset  size  field
0x0     4     magic        0x7152444c ("LDRq") on requests, 0x7352444c ("LDRs") on replies
0x4     1     id           message ID; a reply carries its request's ID
0x5     1     padding
0x6     2     meta_size    at most 0x1000; always 0 when sent, ignored when received
0x8     8     data_size    s64, must not be negative and must match the message's expected size
```

In 20.5.0 `nim` the request header is built at `0x114cf0` and the reply header at `0x114d10`, each
as the magic with the ID in byte 4.

### Messages

| ID | Request data | Reply data | Purpose |
|---|---|---|---|
| `0x0` | none | no reply | Ends the session. |
| `0x1` | 0x10-byte content-meta key | 0x38-byte packaged content info (hash and content info) of that title's **meta** content | Find a title's metadata NCA. |
| `0x2` | 0x18 bytes: 0x10-byte content ID, u8 flag, 7 padding | the whole content, as stored on the sender | Fetch one NCA. The flag set to `1` keeps the transfer out of the progress count; the system-update client sets it only for the system update's own meta content. |
| `0x3` | the 0x10-byte rights ID | u32 ticket size, u32 certificate size, the common ticket, its certificate chain | Fetch an NCA's **common ticket**, which the receiver imports with `es` `ImportTicket`. |
| `0x4` | s64 total size | a header with data size 0 | Tells the sender the transfer's total size, for its progress bar. |

The `0x3` request comes from `ncm`'s install task (`InstallTicket`, `nim` `0x114080`), once per
rights ID, and only for Application and Patch content metas. The sender stores the `0x4` total and
replies with a bare header, which the client waits for; `0x0` is the only request without a reply.

The 20.5.0 `nim` client sends exactly these five requests (IDs `0x0` at `0x114b88`, `0x1` at
`0x114570`, `0x2` at `0x1149b4`, `0x3` at `0x1140b8` and `0x4` at `0x114888`), with data sizes 0,
0x10, 0x18, 0x10 and 8, and expects a 0x38-byte reply to `0x1`.

The sender's checks:

- **System update:** it serves only from built-in system storage. A `0x1` key must be the system
  update's own, or a title listed in the system update's metadata with install type Full.
- **Application:** a `0x1` key must be one of the keys the send task was given (the 55555 `0x16`
  list), and a `0x2` content ID must belong to one of them.
- **Ticket:** from 10.1.0 the sender also checks the ticket's info before serving `0x3`.

### What a receiver gets

The receiver writes each `0x2` reply into an `ncm` placeholder, so the bytes on the wire are the NCAs
exactly as stored on the sender, and the ticket arrives via `0x3`. A received transfer is therefore
complete: the system update's NCAs need only `prod.keys`; a game update's NCAs also need the title
key, which its common ticket carries.

A content meta lists **DeltaFragment** contents (`ncm` content type 6) that an update NSP does not
carry and an installed update does not keep; a receiver skips them. The Violet update v786432's meta
lists 4 NCAs and 5 delta fragments.

The order of requests does not matter to either side: the sender answers any order, and a receiver
chooses its own. `switchlcs/content.py` pulls a content meta as `0x1` and `0x2` for each content
meta (a system update's, then each one it lists), `0x4` with the total, `0x2` for each content with
a `0x3` after the first NCA of each rights ID, and `0x0`. Its `serve()` answers from NSP backups
(`NspSource`). Pulling the Violet update this way over localhost returned all seven files byte for
byte.

## What a pokeldn client needs

| Piece | State |
|---|---|
| TCP over LDN | **Done for the ESP32 board** (`switchlcs/tcp.py` on pokeldn's userspace stack, below); the `nl80211` path uses the kernel's TCP |
| `SystemDeliveryInfo` / `ApplicationDeliveryInfo` builder | **Done** (`switchlcs/delivery.py`), checked against `ns` under unicorn |
| The 55556 client (goals 1 and 2) | **Done** (`switchlcs/content.py` `receive`): writes the NCAs, ticket and certificate to disk, checking each NCA's size and SHA-256 |
| The 55556 server (goal 3) | **Done** (`content.serve` with `NspSource`): answers from NSP backups |
| The 55555 messages | **Done** (`switchlcs/control.py`), byte-identical to qlaunch's senders under unicorn |
| The 55555 host and guest | **Done** (`switchlcs/session.py`); the guest has run against a console, the host only against the guest |
| Game details for a joining guest | **Done** (`session.query_control`: `0x03` → NACP and icon), checked against qlaunch's answer under unicorn |
| The advertise data | **Done** (`switchlcs/advertise.py`), checked against qlaunch's builder and guest parser under unicorn |
| An lcs LDN group | **Done** for hosting (`tools/lcs_host.py`) and joining (`lcs_match.py`), both run end to end over loopback and on simulated ESP32 boards (`tools/lcs_simulate.py`); joining also against a console |
| The app | **Done**: the plugin's Match Version tool runs `lcs_match.py` ([the README](../README.md)), and checks an update before it offers one ([below](#checking-an-update-before-offering-it)) |

Against a console, both downloads complete. An upload installs on the console, but the console has
not yet ended that share ([Testing against a console](#testing-against-a-console)). pokeldn hosting
a console has not been tried.

## TCP over LDN

The whole lcs protocol (55555 *and* 55556) is TCP, and all of it rides on LDN (Ethernet is cut).
Two radios can carry it:

- **The Linux `nl80211` path** (a supported USB Wi-Fi adapter on a Linux host or Raspberry Pi) brings
  the LDN link up as a kernel network interface, so the **kernel's own TCP stack** terminates 55555 /
  55556 and `tcpdump` on that interface captures them as ordinary pcap. A Pi's **built-in Wi-Fi cannot
  host LDN** (its Broadcom `brcmfmac` chip is not among the adapters that work; it sits with the cards
  that fail), so the adapter is an external USB one: the proven choice is the TP-Link Archer T3U
  (`2357:012d`, `rtw88_8822bu`), with the ALFA AWUS036ACHM or an MT7601U plus the custom DKMS driver
  as alternatives (see [Adapters](https://github.com/Decryptu/pokeldn/blob/main/docs/hardware_adapters.md) and
  [Raspberry Pi host](https://github.com/Decryptu/pokeldn/blob/main/docs/hardware_raspberry_pi.md)).
- **The ESP32 board path** has no kernel interface. pokeldn's userspace stack (`pokeldn/ldn/userspace_ip.py`,
  IPv4, UDP and ARP for the games) hands any other IP protocol to a handler a plugin registers
  (`Network.add_protocol`); the plugin's TCP, `switchlcs/tcp.py`, takes protocol 6 there
  (`switchlcs/net.py`). The board's firmware forwards every received frame to the host and
  runs no TCP of its own, so no firmware change is needed.

`switchlcs/tcp.py` has active and passive open, cumulative ACKs with a 64 KiB window, out-of-order
segments held until the hole fills, Reno congestion control with fast retransmit and NewReno partial
ACKs, the RFC 6298 retransmit timer (capped at 2 s, so a stalled radio link recovers quickly),
zero-window probes, FIN and RST. It takes window scaling and timestamps when the peer offers them,
and offers both on its own connects; SACK is left out. A console's SYN offers all three. Its
receive buffer starts at 4 KiB, and its BSD stack grows the buffer only on a connection with
timestamps. Without them, an upload over the board ran with a 2920-byte window, two segments per
round trip (about 70 KB/s live). Sockets block and have `sendall` / `recv`, so
`switchlcs.content` runs on them unchanged.

The board's USB link sets the upload's pace: a 1.5 KB frame takes about 3 ms to write, so an upload
runs at about 0.5 MB/s, whatever the Wi-Fi data rate. The host keeps at most 8 KiB written to the
board beyond what the board has credited, and the board credits every 1024 bytes it reads. Up to
pokeldn 0.29.0 the host refused a credit that arrived while it was still writing the frame it
counted, and waited for the board's idle credit about 20 ms later every few frames: an upload ran at
about 0.3 MB/s. pokeldn 0.29.1 counts that frame
([Decryptu/pokeldn#25](https://github.com/Decryptu/pokeldn/pull/25)).

`tests/test_tcp.py` joins two stacks with a simulated link that drops, duplicates, delays
and reorders frames, and runs bulk transfers and a whole 55556 transfer over it. In-process, it
moves about 20 MB/s on a clean link and 1.5 MB/s at 3% loss, more than the board's USB link carries.

No existing package fit. PyTCP, the one maintained pure-Python stack, needs Python 3.14 and a Linux
TAP device, and is built on Linux-only `eventfd`, so it runs neither on the Windows desktop build
nor on a link without a kernel interface. No lwIP or smoltcp binding is published.

Throughput matters only for the 55556 bulk transfer; the 55555 control channel is tiny. The board
moves about 880 KB/s on a native-USB ESP32-S3 and 92–149 KB/s on a classic ESP32 behind a CP2102, so
a 1 GB update takes about 20 minutes on an S3 and two to three hours on a classic board.

**Decrypting and compressing on the board does not shorten transfers.** NCAs travel encrypted and
encrypted data does not compress, so the idea was for the board to decrypt each NCA (the keys are
derivable: the common ticket's title key under `prod.keys`' `titlekek`, or the NCA's key area),
compress it for the USB link, and have the PC decompress and re-encrypt it byte for byte. Measured on
the Pokémon Violet update v786432 (5.24 GB, almost all of it the Program NCA's patch RomFS), the
decrypted content barely compresses:

| Codec | Saves |
|---|---|
| LZ4, 64 KiB window | 1.0% |
| LZ4 HC-9, 64 KiB window | 1.7% |
| zstd-1, 128 KiB window | 2.1% |
| deflate-1, 32 KiB window | 2.8% |
| zstd-3, 1 MiB window | 5.4% |

Only a fifth of 64 KiB blocks shrink at all: the game's assets are already compressed. At best this
saves about 5 of the roughly 99 minutes the update takes over an S3, so the board passes NCAs
through unmodified. Transfer time depends only on link throughput, which is where the `nl80211`
adapter path, with no USB link in between, has the edge for multi-gigabyte updates.

## Capturing live traffic

A capture is now mainly about the **55555 session flow**, the part read from control flow rather than
proven by running qlaunch, and about a **real `SystemDeliveryInfo`** to check the builder against. A
55556 capture confirms switchbrew's description rather than discovering it.

1. **Scan.** `tools/ldn/ldn_scan.py` lists any nearby LDN group's advertisement from `prod.keys`
   alone, with no association, on an `nl80211` adapter or the ESP32 board. A console on the Create
   Group screen should show `local_communication_id = 0100000000001000`, scene 1, protocol 1 and
   advertise data that `switchlcs.advertise.Advertisement.parse` reads.
2. **pokeldn hosts, a real console joins.** `tools/lcs_host.py --log-join join.bin` hosts the group,
   writes the console's `0x05` (its *real* `SystemDeliveryInfo` inside) and stops without answering,
   so nothing reaches the console.
3. **A real transfer into pokeldn.** `tools/lcs_host.py --backup-system DIR` or `--backup-app ID --out
   DIR` runs the whole host side: accept, snapshot, start, the transfer command and the 55556 pull
   (goals 1 and 2).
4. **pokeldn joins a real host**, which shows the host→guest half as qlaunch sends it (`0x09`, `0x0b`,
   `0x0a`, the transfer commands, `0x1c`). Its first and safest step is the `0x03` query alone, which
   changes nothing on the console: `lcs_match.py` without `--pull`, `--offer` or `--system` shows the
   game and stops at its choice, and *Leave the group* joins nothing.

Steps 1 and 4 have run against a console ([Testing against a console](#testing-against-a-console));
steps 2 and 3, with pokeldn hosting, have not.

**Passive sniffing does not work**, for reasons deeper than "the sender isn't written yet":

- **TCP only flows to an endpoint that handshakes and keeps ACKing.** The host transmits 55555 /
  55556 bytes only to a peer that completed the connection and acknowledges its segments; there is no
  broadcast to overhear, and a silent participant receives nothing (and without ACKs the sender stalls
  after a few segments and resets). Receiving *requires* transmitting ACKs — there is no receive-only
  TCP — which is exactly why a real endpoint is unavoidable and a "listen without sending" capture is
  impossible.
- **A third node cannot overhear two real consoles.** LDN unicast frames between a console and the
  host are CCMP-encrypted under a per-pair key and addressed to that node, so a third associated node
  is never handed them in the clear and cannot decrypt them. (The monitor sniffer `tools/ldn/sniff.py`
  confirms the limit from the other side: it sees frame presence and cadence but cannot read the
  encrypted body.)

Bring up the **receiver** side first: receiving changes nothing on the console, whereas a transfer
*into* a console writes to its storage. Sending (goal 3) comes once the receive side works against
a real console.

### Recording a session

`lcs_match.py` and `tools/lcs_host.py` take `--capture FILE`. `switchlcs/record.py` wraps the session's network, so every
connection is recorded as it passes through unchanged. Each JSON line carries `t` (seconds since
the run started), `port`, `peer` and either an `event` (`connect`, `accept`, `close`) or a message:

- **55555:** `dir` (`out` sent, `in` received), `type`, `name` (the constant in
  `switchlcs/control.py`), `size` and the whole payload as `hex`. Only a `0x04`'s icon is cut, at
  64 KiB; `kept` then says how much of the payload `hex` holds.
- **55556:** `dir`, `magic` (`LDRq` or `LDRs`), `type`, `name`, `size` and the first 64 bytes as
  `hex`: a request's whole body, a meta-info reply, the start of a ticket reply. Contents stream
  past unrecorded.

Bytes that do not frame as the protocol produce one `error` line with the raw header, and nothing
more from that direction.

### Testing against a console

Everything above the LDN layer has run end to end in simulation. Over the two simulated boards,
Let's Go, Pikachu!'s 34 MB update moves both ways as the Match Version tool runs it: downloaded and packed
into an NSP whose six entries are identical to the dump's, and uploaded into a stand-in console
holding the base game. The system download, run as the tool runs it against a stand-in console
holding Ryujinx's installed 20.5.0, receives all 235 NCAs identical to the installed ones. The
stand-in sends what qlaunch's host sends in each case ([Session flow](#session-flow)). With 3% of the
frames between the boards lost, the download still completes in 45 seconds instead of 25. With 10%
lost, the upload takes nearly 7 minutes. A share that stops partway, a refused join, and a group
that is not there each end the run with a message in the console's terms, and nothing incomplete is
saved. What is left is the console's side of it.

**Live results, 2026-10-13** (a Switch hosting Let's Go, Pikachu! 1.0.2, over the ESP32 board):

- The console answers `0x03` before any join, and its advertisement names the update by size and
  display version only ([The advertise data](#the-advertise-data)).
- Downloading the game update: `0x07`, `0x09`, then `0x0a`, `0x12` and `0x16` naming the console with
  flag `0`, as qlaunch's code reads. The 34 MB arrived whole in 41 seconds. The console's delivery
  info in the `0x09` carried version 131072 and required version 131072, with a valid HMAC and zero
  reserved bytes; its attributes were `0x50000002` and its required system version `0x20100000`. pokeldn's own delivery infos now carry those attributes (`delivery.CONSOLE_ATTRIBUTES`).
- The share starts only when the console's player starts it on the console, after pokeldn joins.
- A console sends its system update only to a member that is to receive its game update and is
  below the system version that update requires (the Patch content meta's, carried as the delivery
  info's required system version: 8.1.0 for Let's Go 1.0.2). Joining at `0.0.0` with the game
  already at the console's version, the console completed the share at once with nothing sent. A
  system download therefore joins with the game at its base version.
- After a system update, a console host waits while the receiver is still in transfer state 3
  (`0x42b760`), re-checking only when a message signals it: the member's `0x18` refresh, `0x19`, `0x1a`
  or a leave. Sending nothing there leaves the console on "Waiting for other users" (seen live).
  pokeldn's guest refreshes with the console's own `SystemDeliveryInfo` from the `0x10`, which the
  join validator accepts, and for a system download names the game at the console's version too, so
  nothing is left to send and the console completes the share with `0x1c`: a 23.0.1 console answered
  that refresh with two `0x09`s and the `0x1c` within a second (seen live, Scarlet 4.0.0). Its 23.0.1
  update, 340 MB, arrived in about 7 minutes and passes `verify.check_system`: 121 content metas and
  117 distinct contents. The host then marks the
  node as returning (`+0x1258`), which a guest's `0x1a` clears; it holds the share only while some
  game update is still to send.
- With pokeldn's refresh naming the installed version in a delivery info with the console's
  attributes, the console ended the share with `0x1c` after one transfer (44 seconds). The saved NSP
  passes `check_update`, and its NCAs and ticket are byte-identical to a dump of the same update. Its
  `.cert` holds the same two certificates as the dump's, CA00000003 first: the console sends that
  order, where the dumping tool wrote XS00000020 first.
- Downloading the system update from a console on 23.0.1: the first `0x0c` was of kind `2`, not the
  `1` that 20.5.0's code sends first; pokeldn answered `2` and the console went on. `0x10` named the
  console with flag `0` and carried its `SystemDeliveryInfo` for 23.0.1 (`0x5C010014`), whose MAC
  verifies with pokeldn's key. The node IDs in it are large values such as `0x4016b8e8`, not small
  integers.
- Before any content, the receiver reads every content meta's Meta NCA, one round trip each: 121 for
  23.0.1 (the SystemUpdate meta and the 120 it lists), about 14 seconds over the board with no bytes
  counted toward the total. The page shows that phase as "Reading the update's list of contents".
- Uploading Let's Go 1.0.2 to the console, with the game archived there: the console sent `0x14`
  naming itself with flag `0`, pulled the update's four contents and kept the update, which its Data
  Management lists. It then sent two `0x09`s and stayed on "Please wait" (seen twice; once it sent
  `0x08` with reason 4 after 25 seconds). A console that receives marks the sender as still
  transferring (`0x4303b0`, state 3) and waits (`0x42c138`) until the sender's `0x18` moves it on, as
  after a system update. qlaunch's guest keeps that refresh pending once its send task is done
  (`+0x210`) and sends it on the next `0x09` (`0x425138`). pokeldn's guest now does the same and
  repeats it on later `0x09`s, at most once a second, until the host moves on.
- The system version pokeldn claims does not hold a share up: a game update download that claimed
  20.5.0 against the 23.0.1 console completed with `0x1c`.
- Upload speed over the board: 70 KB/s at first, held to two segments per round trip
  ([TCP over LDN](#tcp-over-ldn)); 0.37 MB/s with timestamps and scaling, where the console's
  window grew to about 117 KB and the host's writes to the board set the pace
  ([The ESP32 board](https://github.com/Decryptu/pokeldn/blob/main/docs/hardware_esp32.md)).

**Before the session:**

- A Switch 1. The static analysis is of firmware 20.5.0, so a console on or near it.
- The ESP32 board with pokeldn's radio firmware, which answers HELLO with its version.
- The console offline, so that it takes nothing from the internet before or after a test. A
  download needs the console's game to have an update installed. An upload needs the console below
  the version served, and not below one it has run: deleting the update (System Settings → Data
  Management) and uploading that same version is enough
  ([Serving an older game update](#serving-an-older-game-update)).
- `prod.keys` in Settings, with captures and the board trace turned on.

**The order,** from changing nothing on the console to writing to it. Each step goes through the
console's path: HOME Menu → the game → + → Software Update → Match Version With Local Users → Next →
Create Group.

1. **Scan.** `tools/ldn/ldn_scan.py` with the console on the group screen. It shows
   `local_communication_id = 0100000000001000`, scene 1, protocol 1, and advertise data that
   `Advertisement.parse` reads, naming the game and its version.
2. **Start, then Leave.** The page joins the LDN network, sends `0x03` and shows the game; Leave
   closes the connection before any `0x05`. The capture holds only the `0x03` and its `0x04`. This
   answers whether a console takes the query before the join.
3. **Download the game update.** A small update first, such as Let's Go's. pokeldn joins at the
   base version, and the console sends. The capture should hold `0x07`, `0x09`, `0x0b` and `0x0a`,
   then `0x12`, and `0x16` naming the console with flag `0`, then `0x1c`. The saved card passes the
   page's signature check. This shows whether the console's planner picks itself as the sender from
   pokeldn's join.
4. **Download the system update.** pokeldn claims `0.0.0`. The capture should hold `0x0c` (kind
   `2` from a 23.0.1 console), then `0x10` naming the console with flag `0` and the console's real `SystemDeliveryInfo`. The
   folder holds every NCA the SystemUpdate meta lists.
5. **Upload** last: the only step that writes to the console. The console should send `0x14` naming
   itself with flag `0` and no `0x12`, pull the keys pokeldn's `0x15` lists, install them, and end
   the share with `0x1c` once pokeldn's `0x18` answers its next `0x09`. With the game archived, the first `0x09` carries pokeldn's own delivery info,
   not the console's: whether the console takes the update is known only once the share runs.

Keep each run's capture and board trace: they are the live evidence that
[Sources and confidence](#sources-and-confidence) ranks first.

## Serving an older game update

Goal 3 relies on lcs moving a console *up* to the newest version in the group, so the console must
start below the version pokeldn serves:

- A factory reset erases installed updates, and a release-day cartridge brings the game back at its
  first version, below any update; a later print may carry a newer version. A digital copy
  redownloaded from the eShop would come with the current update, so this path is for cartridges.
- The console must not take the current update from the internet before pokeldn serves the older
  one, and has to keep declining it afterwards.
- The console keeps the newest version of the game it has run, and deleting the update does not
  clear it. `ns`'s `GetApplicationDeliveryInfo` fills the receiver's `RequiredApplicationVersion` from
  `avm`'s `GetLaunchRequiredVersion`, and `CanDeliverApplication` refuses any sender below it
  (switchbrew). `avm` has `PushLaunchVersion` and `UpgradeLaunchRequiredVersion`, which only raises
  it, and no command that lowers it, so only a factory reset does. After deleting an update, the
  same version can be served again, but no older one.
- The system version is not downgraded. That is fine for an older game update, whose required
  system version is lower than the console's.
- pokeldn can only serve genuine content it received from a console: the console checks Nintendo's
  signatures on what it installs.

## Checking an update before offering it

`switchlcs/verify.py` `check_update` refuses an NSP that the console would not take, before the
console sees it. The Match Version tool runs it on the update it sends, every content hashed, before it
joins; *Import an update* runs it on what goes into the library and *Check saved updates* on what is there
([the README](../README.md)).

The NSP must be:

- **one update.** It has exactly one content meta, of type Patch. Its ID is the game's ID with
  `0x800` set, the Meta NCA's title ID is that ID, and the extended header names the game.
- **for the console's game.** The game ID matches the one the console advertised.
- **newer.** Its internal version is above the console's installed one. A console moves only up.
  The newest version the console has run is not in its advertisement, so an update newer than the
  installed one but older than that passes here. The console's own delivery info arrives in the
  `0x09` after the join, carrying that version as its `RequiredApplicationVersion`; when it is above
  the offered update, pokeldn sends a `0x06` and leaves before the share, and the tool says why. A
  console that completes the share without pulling is reported too
  ([Serving an older game update](#serving-an-older-game-update)).
- **complete.** Every content the meta lists, except delta fragments, is in the NSP at the listed
  size. An NCZ is refused: it is a compressed dump, not what the console installs.
- **signed by Nintendo, end to end:**
  - Every NCA header carries an RSA-2048 PSS signature (SHA-256, 32-byte salt) over header bytes
    `0x200`–`0x400`, under the fixed header key of key generation 0 (byte `0x221`). Every retail
    NCA uses it. That signed range holds the SHA-256 of each FS header.
  - The Meta NCA's FS header holds the PFS0's master hash. That hash covers the hash table, and the
    table's block hashes cover the `.cnmt`.
  - The `.cnmt` lists the SHA-256 of every other content, so each content's hash is checked against
    it.
  - Content NCAs carry the game's ID, not the update's; only the Meta NCA carries the update ID.
- **ticketed with a common ticket.** Each rights ID has a `.tik` and a `.cert`. The ticket is
  common (key type 0, not tied to an account). It is RSA-2048 signed (signature type `0x10004`,
  stored little-endian) over `0x140` to the end by its issuer's XS certificate. That XS certificate
  is signed with PKCS#1 v1.5, SHA-256, by CA00000003, whose key is pinned. The `.cert` holds XS
  first, then the CA, so certificates are looked up by name.
- **readable.** Its Control NCA opens with the ticket's title key, which gives the name, the display
  version and the icon the tool shows.

The two keys are public, and pokeldn ships them as moduli: the NCA header key and the CA00000003
key. The title keys come from the player's `prod.keys` (`titlekek`) and never leave the computer.

Update dumps carry Nintendo's own common ticket, so an untouched one passes. Hashing every byte
of Violet's 5.2 GB update takes about 4 s from an SSD. An NSP that a tool changed after Nintendo
signed it is refused: its NCA header signature or a content hash fails. A "standard crypto"
conversion is the common case: it zeroes the Program NCA's rights ID, writes the title key into the
key area and drops the ticket. Only the header changes, so putting the rights ID back (the update's
ID, seven zero bytes, the key generation) and zeroing the key area gives Nintendo's bytes again:
the signature verifies and the NCA hashes to its content ID. The ticket cannot be rebuilt, though.
Its signature is Nintendo's, so a whole copy has to come from a console that has the update, through
pokeldn's game update download. Base game and DLC dumps
carry tickets that the dump tool forged (the signature is `0xFF` filler), and a console has no reason
to take those over lcs anyway.

## Open questions and missing details

- **`0x01`, `0x03`, `0x19` and `0x1b`** are *handled* by the host but no *sender* for any of them was
  found in qlaunch, even though the guest role is the same binary. `0x01` / `0x03` are understood (the
  control-data query); `0x1b` re-runs the join validator, which fits a guest resuming after the
  reboot a system update needs. The senders may sit in another component or an older client.
- **Whether a console takes the direction from a `0x18` sent after `0x0a`**, before any transfer.
  After a system update it does: the refresh that names the game at the console's version ends the
  share (seen live).
- **The 0x40-byte block** at the advertise data's `+0x98`, also carried by `0x1c`: eight
  `{u8, u8, 2 zero, BE u32}` entries copied from a host table (`+0x4f910`); the u32 is byte-swapped
  like an IP address. pokeldn sends zeros. Likewise the advertise data's `+0x05`, `+0x06`, `+0x08`
  and `+0x0c`, and the 0x580-byte `0x0b` block.
- **Whether a guest sends its system update to the host.** qlaunch's host never receives one, so
  pokeldn's `0x0e` naming itself (`--backup-system`) is an exchange no console host makes; whether
  the guest's `0x0e` handler treats a host peer differently was not read.
- **What the transfer flag does on the guest.** The `0x10`, `0x14` and `0x16` handlers store it with
  the transfer; where it is read was not found.
- **Whether `nim`'s sender requires the peer IP to match** the connecting address beyond what
  switchbrew documents; pokeldn always connects from the IP it named.
- **The host's choice of sender and receiver.** The planners (`0x42b5a0`, `0x42bed0`) and their
  calls into `ns`'s `SelectLatestSystemDeliveryInfo` / `Compare…DeliveryInfo` /
  `CanDeliverApplication` have not been read. pokeldn as host does not need them; as a guest it relies
  on the console choosing the newer side, as the stand-in does.
- **Why a console does not end an upload's share.** It installs the update, then stays on "Please
  wait", once ending it with reason `4`. pokeldn's guest now repeats its `0x18` refresh on the
  console's `0x09`s as qlaunch's guest does; that has not run against a console yet
  ([Testing against a console](#testing-against-a-console)).
- **A console joining pokeldn's group.** `tools/lcs_host.py` has run only against pokeldn's own
  guest; `--log-join` is the first step.
