# Active diagnostics

Passive sniffing only sees what reaches the antenna. A second nRF52840 running OpenThread's CLI firmware joins the
network as an **end device** (router role disabled, so it takes no router ID and changes no routing) and *asks* the
network what the routers themselves know: every router with its Thread version, MAC address and IPv6 addresses, both
directions of every link, the signal and error rates the routers measure, the children of every router with their MAC
and IPv6 addresses and the parent's view of each link, Network Data, and (as far as devices answer) manufacturer and
model. The sniffer keeps providing activity ("who transmits, when").

It is optional. Without `--diag-port` nothing changes.

## What you need and how to start

1. A second nRF52840 stick with the diagnostic firmware (below), plugged in next to the sniffer.
2. The Thread dataset entered in the UI (Settings) or given on the command line: the node needs it to join.
3. Start with the stick's serial device (use `/dev/serial/by-id/...`, `ttyACM0` and `ttyACM1` can swap after a reboot):

```sh
python3 -m thread_tree diag-probe --list-ports        # shows both sticks: the sniffer and the CLI node
python3 -m thread_tree run --source nrf:/dev/serial/by-id/<sniffer> --diag-port /dev/serial/by-id/<CLI node>
python3 -m thread_tree run ... --diag-port ... --diag-interval 600     # seconds between rounds (default 300)
```

The **Diagnosis** tab then has an "Active diagnostics" card (state, last round, "Ask now") and the values below.
`POST /api/diagnostics/run` (JSON body `{}`, same access rule as naming a device) starts a round at once; it answers
`409` without `--diag-port` or while switched off. The card's **Switch off** button (`POST /api/diagnostics/enabled`
with `{"enabled": false}`) stops the background queries: the stick stays in the network, asks nothing, and the active
values grow old; the setting is kept in `<db>.settings.json` across restarts. A new dataset in the Settings makes the node join the new network; a node that is attached
to another network than the dataset describes (name, channel, PAN ID, extended PAN ID or key differs) is moved to ours.

The demo (`python3 -m thread_tree demo`) simulates all of it, including a router that does not answer.

## What is asked, how often

One round every `--diag-interval` seconds (default 300, at least 10), one request at a time:

| Request | Gives |
|---|---|
| `leaderdata` | partition ID |
| `meshdiag topology ip6-addrs children` (up to 90 s) | every router that answers: RLOC16, MAC address, Thread version, leader / border-router flags, its neighbours by link quality (so both directions of every link), its IPv6 addresses, its children with mode and link quality |
| per router `meshdiag childtable`, `childip6`, `routerneighbortable` (30 s each) | children: MAC address, version, timeout, age, supervision, queued messages, signal, link margin, frame and message error rates, time attached; their IPv6 addresses; the router's neighbours with signal, margin, error rates, time attached |
| `netdata show` | border routers, 6LoWPAN contexts |
| `networkdiagnostic get <router address> 25 26 27 28` (3 per round, routers first, then always-listening children) | manufacturer, model, software version, Thread stack version; asked again after 6 h if a device did not answer |

A router that does not answer the detail queries is not asked again for 6 hours; routers without children are not asked
for a child table. The first round also pays the timeouts of routers that never answer (up to 30 s each), later rounds
skip them.

## Where it shows

- **Overview:** the card, a *Thread* column (version) in the device table, the findings below.
- **Device page:** Thread version, manufacturer / model (software), "confirmed by diagnostics"; for a router the table of
  links gets signal, link margin, frames lost, messages lost and time attached (measured by the router named under
  "Reported by"), and its children are listed with signal, losses and age; for an end device the section "Link to its
  parent (as the parent measures it)": signal, margin, frames and messages lost, last heard by the parent, child timeout,
  time attached, waiting messages, supervision. The diagnostic node itself carries the tag *diagnostic node*.
- **Online state:** a device that was never heard by the sniffer but is listed by the routers counts as *online*, no
  longer only as "online (indirect)". Without new answers it falls back to the old rule after 15 min (routers) to 6 h.
- **Banner:** if the collector reports an error (stick missing, did not attach ...) it is shown on every view.
- **API:** `GET /api/diagnostics` has `summary.active` (state, last round, devices that did not answer), `GET /api/status`
  has `diagnostics` and `diagnostics_error`, `POST /api/diagnostics/run` asks now.
- **CSV / JSON:** columns `thread_version`, `last_diag`, `vendor`, `model`, `firmware`, `parent_rssi`, `parent_margin`,
  `parent_frame_err`; the device JSON has `version`, `vendor`, `link`, per-link `metrics` and per-child `link`.

| Finding | Severity | When |
|---|---|---|
| Router loses frames to a neighbour | warning | the router could not deliver 25 % or more of its frames to a neighbour (no acknowledgement), or 5 % of its messages; names the worst link |
| Poor link to its parent | note, warning if messages are lost | its parent hears it at -90 dBm or weaker, or loses 25 % of the frames to it, or 5 % of the messages |
| Parent has not heard it for a long time | note | 80 % of the child timeout without anything from it |
| Router does not answer detail queries | note | usually an older Thread stack; its children and links are known only from other routers |
| Not heard directly, confirmed by diagnostics | note | replaces "Not heard directly" while the routers vouch for the device |
| Active diagnostics not working | warning | the collector reports an error (stick missing, did not attach, firmware without `meshdiag`) |

Measurements older than an hour are not used for findings (the collector stopped). The link margin is shown but not used
for findings: it is the signal above the noise floor *as the measuring chip assumes it*. In the first real network the
border router assumed -100 dBm and two other routers -120 dBm, so margins of different devices are not comparable.
"Frames lost" is the share of the frames **the measuring device sent** to that neighbour that were not acknowledged (a
moving average over the most recent frames; OpenThread's `AddFrameTxStatus`), "messages lost" the share of IPv6 messages
that failed although every frame was repeated.

## Firmware: why a custom build

The commands needed (`meshdiag`, `networkdiagnostic`) are compiled in only on border routers
(`OPENTHREAD_CONFIG_MESH_DIAG_ENABLE` and `OPENTHREAD_CONFIG_TMF_NETDIAG_CLIENT_ENABLE` default to
`OPENTHREAD_CONFIG_BORDER_ROUTING_ENABLE`; ot-nrf528xx does not switch them on). Checked on the prebuilt
`ot-cli-ftd-USB.hex` of ArthFink/nrf52840-OpenThread (release 2026-09, `OPENTHREAD/c34311f`): the binary contains
`routereligible`, `neighbor`, `netdata`, `dataset` but neither `meshdiag` nor `networkdiagnostic`.

**Ready to flash:** the pre-release
[`firmware-diag-2026-10-03`](https://github.com/thomasjanker/thread-tree/releases/tag/firmware-diag-2026-10-03)
(hex file, checksum, build info and `NOTICES.txt` with the component licenses; read them: Nordic's license restricts use to
Nordic chips). It ran on an Ebyte E104-BT5040U in the first real test (`diag-probe`, below).

To build a newer one **in the cloud**, no local toolchain: GitHub Actions workflow
[`firmware-diag.yml`](../.github/workflows/firmware-diag.yml) (Actions tab -> "Firmware (nRF52840 diagnostic node)"
-> Run workflow). It builds `ot-cli-ftd` with `-DOT_BOOTLOADER=USB -DOT_MESH_DIAG=ON -DOT_NETDIAG_CLIENT=ON`, fails
if the command names are missing in the binary, and uploads `ot-cli-ftd-diag-USB.hex` with the source commits and a
checksum.

## Flash the stick

0. Download `ot-cli-ftd-diag-USB.hex` from the release above (`sha256sum -c SHA256SUMS`).
1. Open the case: the Ebyte E104-BT5040U has a reset button inside.
2. Plug it in, press reset: the LED pulses red, USB id `1915:521f` (bootloader).
3. nRF Connect for Desktop -> Programmer -> select the device -> add `ot-cli-ftd-diag-USB.hex` -> Write.
4. Replug. The stick appears as a USB serial device. To flash again, press reset again.

## How the node joins

On start (and after a new dataset) the collector checks the stick: if it is not an attached end device with the router
role disabled, or is attached to another network, it runs `thread stop`, `ifconfig down`, `routereligible disable`,
`dataset set active <dataset>`, `ifconfig up`, `thread start` and waits up to two minutes for the state `child`. A node
that attaches as router or leader is stopped again (error shown). A stick that is already joined is not disturbed, also
not across restarts. The dataset reaches the stick over USB serial only; it never appears in logs, status or error
messages (the command is shown as `<command with a secret>`). If the stick is unplugged or silent the collector reports it
(finding "Active diagnostics not working") and retries with a growing delay up to 5 minutes.

The sniffer hears the stick like any other device: it appears as a full end device (FED) with the tag *diagnostic node*,
child of whatever router it chose.

## Test the stick first: diag-probe

```sh
python3 -m thread_tree diag-probe --list-ports
python3 -m thread_tree diag-probe --port /dev/serial/by-id/<CLI node> --db ~/thread-tree.sqlite
```

It reads the dataset from `<db>.dataset` (entered in the UI), joins as end device, waits for the state `child`, and runs:
identity and local view (`state`, `rloc16`, `ipaddr`, `parent`, `router table`, `neighbor table`, `netdata show`), then
`meshdiag topology` (also with `ip6-addrs children`) and per router `childtable`, `childip6`, `routerneighbortable`; with
`networkdiagnostic` it queries each router's RLOC address. It aborts and stops the stack if the node attaches as router.

The transcript (`diag-probe-<time>.txt`, mode 600) never contains the dataset or the network key: the command is
shown as `<dataset>` and every hex run of 32+ digits is masked. An anonymized transcript of the first real run is the
test fixture of the parsers (`tests/fixtures/probe_real.txt`).

## What the first real network showed

(5 routers, 6 children, DIRIGERA as border router; anonymized in the fixture.)

- `meshdiag` works from an end device. All five routers answered `meshdiag topology`.
- The two routers with Thread version 1.3 (`ver:4`) timed out (error 28, `ResponseTimeout`) on `childtable`, `childip6` and
  `routerneighbortable`; the 1.4 routers answered. Hence the "does not answer detail queries" note and the 6 h pause.
- Weak links were visible only through the routers' own error rates (up to 54 % of frames not acknowledged on some
  router-to-router links, 25 % to some sleepy children); the sniffer alone shows none of that.
- The OMR address that Home Assistant shows for a Thread device appeared in that router's `ip6-addrs`.

## Not verified yet

- The whole loop on hardware (`run --diag-port` with the sniffer running at the same time). The pieces are tested: the
  parsers and one collection round against the recorded real output, the join and the rounds against a simulated stick
  behind a pseudo terminal, findings and UI against it and against the demo.
- The output of `networkdiagnostic get <addr> 25 26 27 28`: its format was taken from OpenThread's source, no real answer
  has been recorded (the first real run could not ask for vendor data). Run `diag-probe` again after a while and send the
  transcript if the vendor column stays empty.
- Output formats can change between OpenThread versions: the parsers read by keyword and ignore what they do not know;
  pin the firmware version.

## Notes

- The network key is stored in the stick's flash after joining; `factoryreset` removes it.
- Sleepy devices are not asked for vendor data (they are asleep almost all the time); only routers and always-listening
  children are. A device that does not answer is not asked again for 6 h.
- Run only one program on the stick's port at a time (this application or `diag-probe`, not both).
