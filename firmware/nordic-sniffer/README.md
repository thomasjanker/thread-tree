# Nordic nRF Sniffer for 802.15.4: firmware for the sniffer stick

`nrf802154_sniffer_nrf52840dongle.hex` is Nordic Semiconductor's unmodified firmware for the **nRF52840 Dongle**
(PCA10059 layout, USB bootloader), copied from
[NordicSemiconductor/nRF-Sniffer-for-802.15.4](https://github.com/NordicSemiconductor/nRF-Sniffer-for-802.15.4)
at commit `b69293680ac92aeddc10807314d564e4c929dcd3` (tag v0.8.0, 2026-08-04), path `nrf802154_sniffer/`.
Git blob `4ff27389b31f3b047de5c6902ceac9180ce2515d` (identical upstream), SHA-256 in `SHA256SUMS`
(`sha256sum -c SHA256SUMS`). After flashing, the stick shows up as USB `1915:154b` "nRF 802154 Sniffer".

**License:** not GPL. These files are under Nordic's own license (`LICENSE` in this folder): redistribution is allowed
if the notice is kept, the binary stays unmodified, and the software is only used with a Nordic Semiconductor
integrated circuit. It is only stored here for convenience, as a separate work next to the GPL code of Thread Tree.
Other boards (nRF52840 DK, nRF5340 DK, nRF54LM20 Dongle) and newer versions: take the file from the upstream repository.

The firmware and the extcap script `nrf802154_sniffer.py` come as a pair: use the script from the same upstream
version (see the Raspberry Pi section of the main README).

## Flash

1. Put the stick into bootloader mode: press its reset button (on the Nordic dongle the small button at the side; the
   Ebyte E104-BT5040U has one inside its case). The LED pulses red, the USB id is `1915:521f`.
2. nRF Connect for Desktop -> Programmer -> select the device -> add the hex file -> Write.
3. Replug. `lsusb | grep 154b` shows the sniffer; it appears as `/dev/ttyACM*`.

Not verified here: which Nordic build fits boards other than the dongle.
