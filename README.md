# Thread Tree

Thread Tree shows a Thread network (Matter-over-Thread, IKEA DIRIGERA, …) as a tree of **leader → routers → end
devices**, with roles, all IPv6 addresses per device, router links and their quality, and a diagnosis of what goes
wrong. It runs standalone on a small computer such as a Raspberry Pi, needs no Home Assistant and changes nothing in
your network. It works with one or two nRF52840 USB sticks:

- a **sniffer** listens passively and turns the decrypted traffic into the tree, statistics and the behaviour of every
  device;
- a **diagnostic node** (optional) joins the network as an end device and *asks* the routers what they know: Thread
  versions, MAC addresses of all children, the signal and error rate of every link, manufacturer and model.

The UI is in English and German, with a legend for every abbreviation. No Python dependencies; the sniffer needs
`tshark` from Wireshark.

![Tree view with the detail panel of a router](docs/screenshots/tree.png)

**Status: v0.1.** Running on a real network (Raspberry Pi 2, IKEA DIRIGERA): the passive tree from the sniffer, and
the active diagnostics with the diagnostic node alone. Newer parts are tested with recorded and simulated data only;
see [Verification status](#verification-status).

## Contents

- [Features](#features)
- [Hardware](#hardware)
- [Quick start](#quick-start)
- [Using the UI](#using-the-ui)
- [Diagnosis and findings](#diagnosis-and-findings)
- [Guided tests](#guided-tests)
- [Active diagnostics](#active-diagnostics)
- [Raspberry Pi setup](#raspberry-pi-setup)
- [Security](#security)
- [How it works](#how-it-works)
- [Verification status](#verification-status)
- [Planned tests](#planned-tests)
- [Development](#development)
- [License](#license)

## Features

- **Views:** tree, mesh of the routers (link quality as colour and number), table (searchable, accepts MAC and IPv6
  addresses as Home Assistant shows them), diagnosis, tests.
- **Every device:** role (leader, router, full/minimal/sleepy end device), short address (RLOC16), MAC address
  (EUI-64), all IPv6 addresses (link-local, mesh-local, RLOC, OMR, …), parent or children, online state, your name for it.
- **Diagnosis:** findings with an explanation and what to do; per device signal and traffic statistics, 24 h charts,
  timing, links, history; CSV and JSON export.
- **Behaviour of sleepy devices:** poll rhythm, gaps longer than the child timeout, searches for a new parent — what
  happens when a battery device "stops working" for a while.
- **Active diagnostics:** what the routers measure themselves, also for devices the sniffer cannot hear.
- **Guided tests:** router, leader or border router outage, partition and merge, router upgrade, router coming back,
  re-attach after a battery change, commissioning — you do the physical part, the program records what the network does.
- **Persistent:** nodes, names, statistics and history survive restarts (SQLite, light on an SD card).
- **Demo mode** with a simulated network, including active diagnostics and guided tests.

## Hardware

Both jobs use an nRF52840 USB stick (Nordic nRF52840 Dongle, Ebyte E104-BT5040U, …), but with **different firmware**.
One stick does one job; for both you need two sticks. Either one is enough to start.

| Job | Firmware | Where to get it | Start option |
|---|---|---|---|
| **Sniffer** (passive: traffic, signal, behaviour) | Nordic's *nRF Sniffer for 802.15.4*, shows up as USB `1915:154b` | [firmware/nordic-sniffer/](firmware/nordic-sniffer/) (Nordic's license, not GPL) | `--source nrf:/dev/ttyACM…` |
| **Diagnostic node** (active: asks the routers) | OpenThread CLI with `meshdiag`, built by this project's [workflow](.github/workflows/firmware-diag.yml), shows up as `OpenThread Device` | [release `firmware-diag-2026-10-03`](https://github.com/thomasjanker/thread-tree/releases/tag/firmware-diag-2026-10-03), steps in [docs/diagnostics.md](docs/diagnostics.md) | `--diag-port /dev/serial/by-id/…` |

An ESP32-C6/H2 can also serve as sniffer through a bridge that writes pcap to stdout (`--source cmd:…`, untested).

## Quick start

Try it without hardware:

```sh
python3 -m thread_tree demo            # simulated network: http://127.0.0.1:8787
```

With hardware, then open `http://<host>:8787` → **Settings** → enter the Thread dataset:

```sh
python3 -m thread_tree run --source nrf:/dev/ttyACM0                       # sniffer only
python3 -m thread_tree run --source nrf:/dev/ttyACM0 \
    --diag-port /dev/serial/by-id/usb-Nordic_Semiconductor_nRF528xx_OpenThread_Device_…-if00   # both sticks
python3 -m thread_tree run --source "cmd:sleep 1000000" --diag-port /dev/serial/by-id/…      # diagnostic node only
```

Other sources: `--source pcap:capture.pcapng` (replay), `iface:<interface>`, `cmd:<command writing pcap>`. Useful
options: `--channel 17` (instead of the dataset's), `--diag-interval 600` (seconds between rounds, default 300),
`--db <file>` (default `./thread-tree.sqlite`), `--host`/`--port` (default `0.0.0.0:8787`), `--local-config-only`.
`python3 -m thread_tree diag-probe --list-ports` lists the serial devices; `python3 -m thread_tree dataset` decodes a
dataset without printing secrets.

**The Thread dataset** provides the network key (to decrypt), the channel, the PAN ID and the mesh-local prefix. Copy it
from your border router (IKEA app: Hub settings → Thread network → More options → copy dataset; or
`ot-ctl dataset active -x`) and enter it under Settings. It is stored in `<db>.dataset` (mode 600) and never returned by
the API. Alternatively pass it as `THREAD_TREE_DATASET` (then the form is read-only).

**Start with the computer** (systemd, adapt user, folder and ports):

```sh
sudo tee /etc/systemd/system/thread-tree.service >/dev/null <<'EOF'
[Unit]
Description=Thread Tree
After=network-online.target
Wants=network-online.target

[Service]
User=pi
WorkingDirectory=/home/pi/thread-tree
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 -m thread_tree run --source nrf:/dev/ttyACM0 --diag-port /dev/serial/by-id/…
Restart=on-failure
RestartSec=10
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now thread-tree
journalctl -u thread-tree -f          # log; after an update: git pull && sudo systemctl restart thread-tree
```

## Using the UI

| | |
|---|---|
| ![Mesh view](docs/screenshots/mesh.png) | ![Diagnosis overview](docs/screenshots/diagnosis.png) |

- **Tree / Mesh / Table:** click a device for its detail panel. A dotted circle marks a device the sniffer never heard
  directly; a coloured dot a warning or critical finding.
- **Names:** type a name in the detail panel. It is bound to the device's MAC address, so it stays when the device
  changes its parent. A device known only by its short address can be named too, with a warning.
- **Matching with Home Assistant:** paste what HA shows under "Matter info" into the table's filter: a MAC address (8
  bytes = Thread EUI-64, 6 bytes = Ethernet/Wi-Fi) or IPv6 address in any notation. A Matter bridge that HA reaches over
  Ethernet (e.g. DIRIGERA) shows its Ethernet MAC there, which is not its Thread address.
- **Rebuild tree** (header) forgets what was learned and learns it again; names and the dataset stay.
- **Active diagnostics: on / off** (header, with a diagnostic node): off, the stick stays in the network but asks
  nothing; kept across restarts.
- **Diagnosis** and **Tests**: see below. Data is saved every 30 s and on shutdown; devices unseen for 30 days are
  removed.

## Diagnosis and findings

![Device page of a router](docs/screenshots/device.png)

The **Diagnosis** tab has an overview (devices online, routers of at most 32, partitions, border routers, links,
capture, active diagnostics), all findings, and a sortable table with frames per hour, retransmissions, RSSI,
advertisement or poll interval, children and Thread version (CSV export). A **device page** shows its findings with
what to do, signal and traffic at the sniffer with 24 h charts, timing, the behaviour of a sleepy device, router links
(with active diagnostics also the signal and loss the routers measure), parent or children, its history (30 days) and
addresses (JSON download).

Values without the mark "active" are measured **at the sniffer**: a device far from it looks weak and quiet without
being so. Findings are hints, not proof. Thresholds are constants at the top of `thread_tree/diagnose.py`.

| Finding | Severity | When |
|---|---|---|
| Offline | critical (leader, router with children) / warning | no frame for longer than usual for its role (routers 15 min, sleepy devices 6 h) |
| Critical router | warning | its failure splits the known router mesh |
| Router with a single link | warning | only one two-way link, at least 3 routers |
| All links weak / uneven link | warning / note | all links LQ 1 / in and out differ by 2 or more |
| Changes parent often; router changes address or role often | warning | 3 or more in 24 h |
| Many retransmissions | warning | 15 % or more of at least 50 frames (24 h) |
| Very frequent advertisements | warning | more than 360 per hour (stable: about 110) |
| Weak signal at the sniffer | note | average below -85 dBm |
| Gaps in its polling | note / warning | a sleepy device skipped its polls for 4 usual intervals while the sniffer heard others; warning beyond its child timeout or 3 times in 24 h |
| Searches for a parent | note / warning | MLE Parent Requests; warning from 3 searches in 24 h |
| Polls barely within its timeout; silent right now | warning | poll interval 90 % of the child timeout or more; no poll for a gap's length now |
| Parent offline / unknown, not heard directly, MAC unknown | warning / notes | |
| Active: router loses frames to a neighbour | warning | 25 % of its frames (or 5 % of its messages) not delivered |
| Active: poor link to its parent | note / warning | -90 dBm or weaker, or 25 % frames lost (5 % of messages: warning) |
| Active: parent has not heard it for long; router does not answer detail queries; confirmed by diagnostics; diagnostics not working | notes / warning | |
| Network: sniffer silent, decryption failing | critical | |
| Network: partitions, leader changes, many offline, router limit | warning | |
| Network: no / single border router, near the router limit | note | |

## Guided tests

The **Tests** tab: pick a test and a device, start it, then do the physical part. The report updates live, with times
counted from the start. One test at a time; it ends by itself after 30 minutes; the last 20 reports are kept. In the demo
the simulator plays your part.

| Test | You | It shows |
|---|---|---|
| Router outage | cut a router's power | when it fell silent, whether the mesh dropped its links, where and after how long each of its devices attached elsewhere |
| Leader outage | cut the leader's power | time until a new leader (after the network ID timeout, 120 s by default), new partition ID, Network Data version |
| Border router outage | cut a border router's power | when it leaves the Network Data, which border routers are left |
| Partition and merge | cut the router that connects two parts, then power it on | whether a second partition forms, and when the parts merge again |
| Router upgrade | cut a router's power | whether a router-eligible end device becomes a router (below 16 routers by default) |
| Router comes back | power a router on (or off and on) | when it is heard and advertises again, same router ID or not, devices attached to it |
| Re-attach after a battery change | battery out and back in | silence, parent search, Parent Requests, chosen parent, time until it is back |
| Commissioning | pair a new device | every new device with Discovery Request, parent search, attach (the DTLS joining itself is encrypted) |

With the sniffer the times are accurate to the second; with the diagnostic node alone, changes show at its next round.

## Active diagnostics

A diagnostic node joins your network as an **end device** (router role disabled: no router ID, no influence on routing)
and runs a round of questions every `--diag-interval` seconds: `meshdiag topology` (routers, links in both directions,
addresses, children), per router its child and neighbour tables, Network Data, and manufacturer / model of a few devices
per round. It fills in what the sniffer cannot hear and shows weak links by what the routers lost. The stick shows up as
a device (tag *diagnostic node*) and keeps the dataset in its flash. Routers with an older Thread stack (1.3) do not answer
the detail queries; they get a note and are asked again after 6 hours. Details, flashing and limits:
[docs/diagnostics.md](docs/diagnostics.md).

## Raspberry Pi setup

What worked in testing for the sniffer (a Raspberry Pi 2 is enough):

1. Flash the sniffer firmware: [firmware/nordic-sniffer/](firmware/nordic-sniffer/) (hex for the nRF52840 Dongle, checksum,
   steps); other boards: [NordicSemiconductor/nRF-Sniffer-for-802.15.4](https://github.com/NordicSemiconductor/nRF-Sniffer-for-802.15.4).
2. `sudo apt install tshark python3-serial git`; add your user to `dialout` and `wireshark`; log in again.
3. Install Nordic's extcap script as your user: clone the repository above, copy `nrf802154_sniffer.py` to
   `~/.config/wireshark/extcap/` and `chmod +x` it. Use the script of the same version as the firmware.
4. The channel comes from the dataset. Without it, capture a few seconds per channel 11–26 and compare; a Zigbee channel
   (DIRIGERA's Zigbee is often on 11) shows `zbee_nwk` in `tshark -q -z io,phs`, Thread shows 6LoWPAN/MLE.
5. Wireshark's default Thread settings fit; without the key the UI shows a warning.

Use `/dev/serial/by-id/…` names when two sticks are plugged in: `ttyACM0` and `ttyACM1` can swap.

## Security

The web server listens on all interfaces (`--host 0.0.0.0`) and has **no authentication**: anyone on the network can
view the topology and, by default, enter or remove the dataset, name devices, rebuild the tree, switch the active
diagnostics and start tests. The key is never sent back, but travels unencrypted over HTTP when entered (the UI warns).
`--local-config-only` restricts all changes to the machine itself (use an SSH tunnel: `ssh -L 8787:localhost:8787 pi@host`).
Changing requests need `Content-Type: application/json` and a matching `Origin`; with `--local-config-only` also a local
`Host` name (against DNS rebinding). Known limitation: tshark gets the key on its command line, visible to other local
users in the process list.

## How it works

| Shown | Source |
|---|---|
| Routers, leader, partition | MLE advertisements (Leader Data) |
| Router links and quality | Route64 TLV; with active diagnostics both directions measured by the routers |
| Parent of an end device | its RLOC16 (`rloc16 >> 10` = parent router ID) |
| Device type (FED / MED / SED) | Mode TLV; data polls mark sleepy devices |
| Border routers | Network Data |
| MAC address | frame addresses; the attach response binds a short address to a MAC address; the routers' child tables |
| Direct / indirect | whether the sniffer received a frame sent by the device itself |
| Link-local, RLOC, ALOC | derived from MAC address, RLOC16 and mesh-local prefix |
| ML-EID, OMR | address registrations and notifications; the routers' address lists |
| Poll rhythm, parent searches, child timeout | MAC data requests, MLE Parent / Child ID Requests, Timeout TLV |
| Thread version, manufacturer, link signal and loss | active diagnostics only |

Limits of passive capture: only what the sniffer hears; sleepy devices appear slowly; a REED cannot be told from a FED;
a router link needs that router's advertisement at the sniffer. While a network re-forms, two partitions can briefly use
the same router ID; and if a short address is reused unnoticed, frames carrying only it are attributed to the old
device (the detail panel warns when a named device has been heard only by its short address for an hour).

## Verification status

**On real hardware:** the nRF sniffer piping into tshark on a Raspberry Pi 2 with decryption; the tree from a real
network; the diagnostic firmware, `diag-probe` and the active diagnostics with the diagnostic node alone (5 routers,
IKEA DIRIGERA, ESP32-C6 routers): joining, rounds, findings, manufacturer answers, the UI in a browser.

**Tested with recorded or simulated data only:**
- signal statistics from the sniffer's TAP fields (`wpan-tap.rss`, `wpan-tap.lqi`, `wpan.seq_no`, …);
- behaviour of sleepy devices (also the field `mle.tlv.timeout`) and the guided tests on a real network
  (`mle.tlv.leader_data.data_version`, MLE Discovery Request);
- sniffer and diagnostic node running together;
- the ESP32 pcap bridge.

Wireshark field names come from its reference and are checked against `tshark -G fields` at startup; a missing field
disables only its feature, with a warning in the log.

## Planned tests

Ideas from the Thread specification, not implemented yet. **S** sniffer, **D** diagnostic node (its firmware has `ping`,
`scan`, `counters`, `eidcache`). Suggested order: 15, 9, 8, 10. (Guided tests 1–7 are implemented, see above.)

Continuous checks against the standard (passive):

8. Parent selection (S): routers answer a search with link margin and connectivity; did the device pick the best one?
9. Reboot detection (S): frame counters only grow per sender; a counter that jumps back means a restart or reset.
10. Child supervision (S): since Thread 1.2 the parent must contact a silent child within the supervision interval.
11. Network Data versions (S): a router whose advertised data version keeps lagging does not receive Network Data.
12. Advertisement timing (S): Trickle runs between 1 s and 32 s; gaps are not conform either.
13. Full routers (S): a router that rejects attaches because its child table is full.
14. Battery estimate (S): rough radio-on time from poll rhythm and traffic.

Active tests with the diagnostic node:

15. Reachability series (D): e.g. 20 pings to a sleepy device's ML-EID: success rate and round trip (about its poll
    interval), optionally every few minutes.
16. Census by multicast (D): ping to all Thread nodes (`ff03::1`): who answers, who is listed but silent.
17. Address resolution after a parent change (D, S): how long a device is unreachable by its ML-EID.
18. Channel check (D): `scan energy` on all channels (Wi-Fi overlap) and the stick's MAC counters.

## Development

```sh
python3 -m unittest discover -s tests       # about 400 tests; the JS helpers need gjs (skipped without it)
python3 -m thread_tree demo --port 8788     # UI with simulated data
```

```
thread_tree/engine.py     observations -> persistent node model, history events
thread_tree/topology.py   snapshot and tree (leader root, best-quality router paths)
thread_tree/diagnose.py   findings, network summary, device page, CSV
thread_tree/behavior.py   poll rhythm, gaps, parent searches
thread_tree/scenario.py   guided tests
thread_tree/stats.py      per-device counters, RSSI, intervals, 10-minute buckets
thread_tree/presence.py   online / offline rules
thread_tree/addresses.py  EUI-64 / RLOC16 / IPv6 classification
thread_tree/ek.py         tshark EK output -> engine calls
thread_tree/capture.py    nrf / pcap / interface / command sources
thread_tree/collector.py  active diagnostics: join as end device, rounds of questions
thread_tree/otcli.py      serial client for the OpenThread CLI
thread_tree/otdiag.py     parsers for meshdiag / netdata output (tested on a real transcript)
thread_tree/diagprobe.py  diag-probe: what can the stick ask (transcript without secrets)
thread_tree/simulate.py   demo network, simulated diagnostics and tests
thread_tree/store.py      SQLite persistence
thread_tree/runtime.py    capture, diagnostics and tests lifecycle; dataset and settings files
thread_tree/server.py     HTTP: JSON API and the static UI
thread_tree/web/          UI (vanilla JS, no build step; en/de)
firmware/nordic-sniffer/  Nordic's sniffer firmware, unmodified (own license)
```

**API** (JSON; changing requests need `Content-Type: application/json`): `GET /api/topology`, `/api/status`,
`/api/config`, `/api/diagnostics`, `/api/nodes/<id>/diagnostics`, `/api/export/nodes.csv`, `/api/tests`;
`POST /api/config/dataset` `{"dataset": "<hex>"}`, `DELETE /api/config/dataset`, `PUT /api/nodes/<id>/name`
`{"name": "…"}`, `POST /api/topology/reset`, `/api/diagnostics/run`, `/api/diagnostics/enabled` `{"enabled": true}`,
`/api/tests/start` `{"kind": "router_outage", "target": "<id>"}`, `/api/tests/stop`.

Matter support is planned as a later extension; the graph model is transport-agnostic.

## License

Copyright (C) 2026 Thomas Janker. Licensed under the GNU General Public License, version 3 or (at your option) any later
version. See [LICENSE](LICENSE). Exception: `firmware/nordic-sniffer/` contains Nordic Semiconductor's firmware under
Nordic's license (see the `LICENSE` file there).
