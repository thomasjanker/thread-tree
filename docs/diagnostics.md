# Active diagnostics (plan and Phase 0)

Passive sniffing only sees what reaches the antenna. A second nRF52840 running OpenThread's CLI firmware joins
the network as an **end device** (router role disabled, so it takes no router ID and changes no routing) and
*asks* the network: every router, its neighbours, its children with MAC addresses and IPv6 addresses, vendor and
model, Network Data. The sniffer keeps providing activity ("who transmits, when").

Decisions: firmware on the nRF (variant C: no border-router stack and nothing to install on the Pi), joined as end
device, second stick next to the sniffer.

## Firmware: why a custom build

The commands needed (`meshdiag`, `networkdiagnostic`) are compiled in only on border routers
(`OPENTHREAD_CONFIG_MESH_DIAG_ENABLE` and `OPENTHREAD_CONFIG_TMF_NETDIAG_CLIENT_ENABLE` default to
`OPENTHREAD_CONFIG_BORDER_ROUTING_ENABLE`; ot-nrf528xx does not switch them on). Checked on the prebuilt
`ot-cli-ftd-USB.hex` of ArthFink/nrf52840-OpenThread (release 2026-09, `OPENTHREAD/c34311f`): the binary contains
`routereligible`, `neighbor`, `netdata`, `dataset` but neither `meshdiag` nor `networkdiagnostic`.

**Ready to flash:** the pre-release
[`firmware-diag-2026-10-03`](https://github.com/thomasjanker/thread-tree/releases/tag/firmware-diag-2026-10-03)
(hex file, checksum, build info and `NOTICES.txt` with the component licenses; read them: Nordic's license restricts use to
Nordic chips). Not verified on hardware yet.

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

## Phase 0: what can this node ask?

```sh
python3 -m thread_tree diag-probe --list-ports        # two sticks: sniffer and CLI node
python3 -m thread_tree diag-probe --port /dev/serial/by-id/<the CLI node> --db ~/thread-tree.sqlite
```

It reads the dataset from `<db>.dataset` (entered in the UI), joins as end device (`routereligible disable`, `dataset
set active`, `thread start`), waits for the state `child`, and runs: identity and local view (`state`, `rloc16`,
`ipaddr`, `parent`, `router table`, `neighbor table`, `netdata show`), then `meshdiag topology` (also with
`ip6-addrs children`) and per router `childtable`, `childip6`, `routerneighbortable`; with `networkdiagnostic` only,
it queries each router's RLOC address. It aborts and stops the stack if the node attaches as router.

The transcript (`diag-probe-<time>.txt`, mode 600) never contains the dataset or the network key: the command is
shown as `<dataset>` and every hex run of 32+ digits is masked. Send it to get the parsers written against real
output.

## Roadmap

1. Connection, join as end device, `meshdiag topology` -> routers, links, leader, border routers, Thread versions.
2. Children: tree with all children, their MAC and OMR addresses (replaces most guessing for sleepy devices).
3. Vendor/model, Network Data and prefixes in the UI, source of every value ("diagnostic" / "overheard"), status
   panel, "query now" button.
4. Robustness: schedule (one round about every 5 minutes, one request at a time, sleepy devices rarely), retries,
   reconnect, tests against recorded transcripts.

## Open questions (Phase 0 answers them)

- Does `meshdiag` work from an end device? The API documentation only requires an attached FTD node.
- What do the DIRIGERA and the other routers answer? Child MAC, child addresses, neighbour table and vendor data
  need newer Thread versions.
- Sleepy devices answer late or not at all within the response timeout.
- Output formats can change between OpenThread versions: pin the firmware version and test against transcripts.

## Notes

- The network key is stored in the stick's flash after joining; `factoryreset` removes it.
- Use `/dev/serial/by-id/...`: `ttyACM0`/`ttyACM1` can swap after a reboot.
