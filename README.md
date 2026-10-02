# Thread Tree

Standalone, passive visualizer for Thread networks (Matter-over-Thread, IKEA DIRIGERA, …).
A single 802.15.4 sniffer (nRF52840 or ESP32-C6/H2) listens on the Thread channel; Thread Tree
turns the decrypted traffic into a tree of **leader → routers → end devices** with roles,
all IPv6 addresses per node (a border router shows several), and router link quality.
No Home Assistant, no changes to your network. UI in English and German, with a legend for every abbreviation.

**Status: v0.1, engine and UI are implemented and unit-tested with synthetic data. The tshark
adapter has not yet been run against a real capture (see "Verification status").**

## Quick start

```sh
python3 -m thread_tree demo            # simulated network, no hardware; http://127.0.0.1:8787
python3 -m unittest discover -s tests  # tests
```

With hardware (needs `tshark` from Wireshark; nothing else, no Python dependencies):

```sh
python3 -m thread_tree run --source nrf:/dev/ttyACM0     # then open the UI -> Settings -> enter the dataset
python3 -m thread_tree run --source nrf:/dev/ttyACM0 --channel 17
python3 -m thread_tree run --source iface:<nrf-sniffer-interface>
python3 -m thread_tree run --source pcap:capture.pcapng   # replay
python3 -m thread_tree run --source cmd:"your-esp32-sniffer-bridge --port /dev/ttyACM0"  # writes pcap to stdout
python3 -m thread_tree dataset                            # decode a dataset (prints no secrets)
```

**Thread dataset.** It provides the network key (needed to decrypt), the channel (used by `nrf:`), the PAN ID filter
and the mesh-local prefix. Enter it in the UI under **Settings** (e.g. copy it in the IKEA app: Hub settings -> Thread
network -> More options -> copy dataset; or `ot-ctl dataset active -x`). Saving validates it, stores it in
`<db>.dataset` (mode 600) and restarts the capture with the new key and channel; learned nodes are kept. Alternatively
give it on startup via `THREAD_TREE_DATASET` (preferred over `--dataset`, keeps it out of shell history); then the form
is read-only. The key is never returned by the API. Without a key only MAC-level data is visible; the UI says so.

Security notes: the server binds to localhost without authentication. Entering a key in the UI is only allowed on a
loopback bind (use an SSH tunnel: `ssh -L 8787:localhost:8787 pi@host`), unless `--allow-remote-config` is given.
Config requests need `Content-Type: application/json`, a local `Host` and a matching `Origin` (guards against other
web pages and DNS rebinding). Known limitation: the key is passed to tshark on its command line, so other local users
of the same machine can see it in the process list.

State is stored in SQLite (`--db`, default `./thread-tree.sqlite`) every 10 s and on SIGTERM/Ctrl+C,
so nodes, roles and addresses survive restarts (nodes unseen for 30 days are pruned).

## Raspberry Pi + Nordic nRF 802.15.4 sniffer (setup that worked in testing)

1. `sudo apt install tshark python3-serial git`; add your user to `dialout` and `wireshark`; log in again.
2. Install Nordic's extcap script (run as your user, not root, the extcap folder is per user):
   `git clone https://github.com/NordicSemiconductor/nRF-Sniffer-for-802.15.4`, copy `nrf802154_sniffer.py` to
   `~/.config/wireshark/extcap/` and `chmod +x` it. `lsusb` shows the dongle as "nRF 802154 Sniffer" (1915:154b).
3. Find the channel: the dataset has it (`python3 -m thread_tree dataset`). Without the dataset, scan channels 11-26
   with `--capture ... --channel N --fifo /tmp/chN.pcap` and compare. Zigbee networks look similar (Dirigera's Zigbee is
   often on channel 11): a Zigbee channel shows `zbee_nwk` in `tshark -r ... -q -z io,phs`, Thread shows 6LoWPAN/MLE.
4. Thread encrypts MLE with a key derived from the network key; Wireshark's defaults (`thread.thr_use_pan_id_in_key: FALSE`,
   `thread.thr_auto_acq_thr_seq_ctr: TRUE`) already fit. Without the key the UI shows a warning.

## How the tree is derived (all passive)

| Shown | Source |
|---|---|
| Routers, leader | MLE advertisements (Source Address, Leader Data TLVs) |
| Router links + quality | Route64 TLV (link quality in/out, cost) |
| Parent of an end device | RLOC16: parent router ID = `rloc16 >> 10` (recomputed, never stored) |
| MED / SED / FED | Mode TLV in Parent/Child ID/Child Update Requests; MAC data polls mark sleepy |
| Border router flag | Network Data (Border Router / Has Route RLOC16s) |
| Reception: direct / indirect | direct = the sniffer received a frame transmitted by that node itself; indirect = known only from others' traffic (out of range) |
| Link-local, RLOC, ALOC | derived from EUI-64 / RLOC16 / mesh-local prefix (marked "derived") |
| ML-EID, OMR/GUA | Address Registration of children, Address Notification (marked "observed") |

Limits: only what the sniffer hears; sleepy devices appear slowly; a REED cannot be told from a FED;
router-to-router links need that router's advertisement to reach the sniffer.

## Verification status (honest)

Verified here: engine, topology, persistence, dataset parser, address math, EK adapter logic
(on synthetic EK input), CLI, server endpoints, graceful SIGTERM flush.
**Not verified (no hardware / tshark / browser in the dev environment):**
1. Real tshark output: field names come from the Wireshark field reference and are resolved against
   `tshark -G fields` at startup (missing ones disable a feature and log a warning), but EK key naming
   and Route64 entry alignment are untested on real traffic.
2. Decryption option `uat:ieee802154_keys:"<key>","1","Thread hash"` in `capture.py`.
3. The web UI has only been read through, not rendered in a browser.
4. The ESP32-C6 pcap bridge (`cmd:` source). The nRF extcap piping (`--fifo /dev/stdout` into `tshark -r -`) was confirmed
   on a Raspberry Pi 2: frames, Thread PAN, RLOC16s and link-local addresses decode as expected.

First hardware step: capture a few minutes with the sniffer, run `tshark -r cap.pcapng -T ek` by hand
next to `thread-tree run --source pcap:cap.pcapng`, and compare.

## Layout

```
thread_tree/addresses.py  EUI-64 / RLOC16 / IPv6 classification
thread_tree/engine.py     observations -> persistent node model
thread_tree/topology.py   snapshot + spanning tree (leader root, best-LQ router paths)
thread_tree/ek.py         tshark EK -> engine calls (field table)
thread_tree/capture.py    pcap / interface / command / EK sources
thread_tree/store.py      SQLite persistence
thread_tree/runtime.py    capture lifecycle + dataset (UI/CLI), private dataset file
thread_tree/server.py     stdlib HTTP: /api/topology, /api/status, static UI
thread_tree/web/          vanilla JS UI (tree, mesh, table views, legend, en/de)
```

Matter support is planned as a later extension; the graph model is transport-agnostic.

## License

Copyright (C) 2026 Thomas Janker. Licensed under the GNU General Public License, version 3 or (at your
option) any later version. See [LICENSE](LICENSE).
