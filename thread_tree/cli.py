from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from pathlib import Path

from .capture import DEFAULT_EXTCAP_SCRIPT
from .dataset import normalize_hex, parse_dataset
from .engine import Engine
from .runtime import Controller
from .server import is_loopback, make_server
from .simulate import Simulator, populate
from .store import Persister, Store


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="thread-tree", description="Thread network tree from a passive 802.15.4 sniffer")
    sub = p.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--host", default="0.0.0.0",
                        help="bind address (default: 0.0.0.0 = all IPv4 interfaces; '::' for IPv6, "
                             "127.0.0.1 for this machine only)")
    common.add_argument("--port", type=int, default=8787)
    common.add_argument("--db", default="thread-tree.sqlite", help="persistence file")
    run = sub.add_parser("run", parents=[common], help="capture and serve")
    run.add_argument("--source", required=True,
                     help="nrf:PORT | pcap:FILE | iface:NAME | cmd:COMMAND | ek:FILE")
    run.add_argument("--channel", type=int, help="802.15.4 channel 11-26 for nrf: (default: from the dataset)")
    run.add_argument("--extcap-script", default=DEFAULT_EXTCAP_SCRIPT, help="Nordic nrf802154_sniffer.py")
    run.add_argument("--dataset", help="active dataset TLVs as hex; locks the UI form (prefer env THREAD_TREE_DATASET)")
    run.add_argument("--key", help="network key as 32 hex chars (prefer env THREAD_TREE_KEY)")
    run.add_argument("--local-config-only", action="store_true",
                     help="only accept the dataset from this machine (e.g. through an SSH tunnel); by default "
                          "any machine that can reach the UI may enter it, and the key travels unencrypted over HTTP")
    run.add_argument("--diag-port",
                     help="serial device of a second nRF52840 with OpenThread CLI firmware (see docs/diagnostics.md), "
                          "best /dev/serial/by-id/usb-...: it joins the network as an end device and asks the routers "
                          "(active diagnostics)")
    run.add_argument("--diag-interval", type=float, default=300.0,
                     help="seconds between two rounds of questions (default 300, from 10 to 3600)")
    run.add_argument("--tshark", default="tshark")
    run.add_argument("--tshark-arg", action="append", default=[], help="extra tshark argument (repeatable)")
    sub.add_parser("demo", parents=[common], help="serve a simulated network (no hardware)")
    dec = sub.add_parser("dataset", help="decode a dataset and print what it contains (no secrets)")
    dec.add_argument("tlvs", nargs="?", help="hex; default: env THREAD_TREE_DATASET")
    probe = sub.add_parser("diag-probe", help="test an nRF52840 with OpenThread CLI firmware as diagnostic node")
    probe.add_argument("--port", help="serial device, best /dev/serial/by-id/usb-... (see --list-ports)")
    probe.add_argument("--list-ports", action="store_true", help="show serial devices and exit")
    probe.add_argument("--db", default="thread-tree.sqlite",
                       help="database whose <db>.dataset file holds the dataset to join with")
    probe.add_argument("--dataset-file", help="file with the dataset hex (default: <db>.dataset or env THREAD_TREE_DATASET)")
    probe.add_argument("--no-join", action="store_true", help="do not (re)join: probe a node that is already attached")
    probe.add_argument("--stop", action="store_true", help="stop the Thread stack on the node afterwards")
    probe.add_argument("--out", help="transcript file (default: diag-probe-<time>.txt)")
    return p


def _diag_probe(args: argparse.Namespace) -> int:
    from .diagprobe import list_ports, run_probe
    from .otcli import OtCli

    if args.list_ports:
        rows = list_ports()
        for by_id, tty in rows:
            print(f"{by_id} -> {tty}")
        if not rows:
            print("no serial devices found")
        return 0
    if not args.port:
        print("--port is required (see --list-ports)", file=sys.stderr)
        return 2
    dataset_hex = None
    if not args.no_join:
        path = Path(args.dataset_file or args.db + ".dataset")
        raw = os.environ.get("THREAD_TREE_DATASET") or (path.read_text().strip() if path.is_file() else None)
        if not raw:
            print(f"no dataset: enter it in the UI first ({path} is missing) or set THREAD_TREE_DATASET",
                  file=sys.stderr)
            return 2
        try:
            parse_dataset(raw)
        except ValueError as exc:
            print(f"invalid dataset: {exc}", file=sys.stderr)
            return 2
        dataset_hex = normalize_hex(raw)
    out = Path(args.out or time.strftime("diag-probe-%Y%m%d-%H%M%S.txt"))
    try:
        cli = OtCli(args.port).open()
    except OSError as exc:
        print(f"cannot open {args.port}: {exc}", file=sys.stderr)
        return 2
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as sink, cli:
        def emit(text: str) -> None:
            print(text)
            sink.write(text + "\n")
            sink.flush()

        summary = run_probe(cli, dataset_hex, join=not args.no_join, emit=emit, stop_after=args.stop)
    print(f"\nTranscript written to {out} (it contains no network key).")
    return 0 if summary["joined"] else 1


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if args.cmd == "diag-probe":
        return _diag_probe(args)

    if args.cmd == "dataset":
        try:
            ds = parse_dataset(args.tlvs or os.environ.get("THREAD_TREE_DATASET", ""))
        except ValueError as exc:
            print(f"invalid dataset: {exc}", file=sys.stderr)
            return 2
        print(f"network name:      {ds.network_name}\nchannel:           {ds.channel}\n"
              f"PAN ID:            {None if ds.pan_id is None else hex(ds.pan_id)}\n"
              f"extended PAN ID:   {ds.ext_pan_id}\nmesh-local prefix: {ds.mesh_local_prefix_str}\n"
              f"network key:       {'present' if ds.network_key else 'missing'}")
        return 0

    engine = Engine()
    store = Store(args.db)
    engine.load_state(store.load())

    if args.cmd == "demo":
        populate(engine, history=True, active=True)
        controller = Controller(engine, "demo", editable=False, locked_reason="demo", allow_remote_config=True)
    else:
        if args.channel is not None and not 11 <= args.channel <= 26:
            print(f"invalid channel {args.channel}: Thread uses 11-26", file=sys.stderr)
            return 2
        try:
            controller = Controller(
                engine, "run", args.source, args.channel,
                dataset_path=Path(args.db + ".dataset"),
                cli_dataset=args.dataset or os.environ.get("THREAD_TREE_DATASET"),
                cli_key=args.key or os.environ.get("THREAD_TREE_KEY"),
                tshark=args.tshark, extra=args.tshark_arg, extcap_script=args.extcap_script,
                allow_remote_config=not args.local_config_only,
                diag_port=args.diag_port, diag_interval=args.diag_interval)
        except ValueError as exc:
            print(f"invalid dataset: {exc}", file=sys.stderr)
            return 2
        if not controller.key:
            logging.warning("no network key yet: enter the dataset in the UI (Settings) or start with --dataset")

    persister = Persister(engine, store)
    persister.start()
    sim = None
    if args.cmd == "demo":
        sim = Simulator(engine)
        sim.start()
    else:
        controller.start_capture()
        if args.diag_port:
            logging.info("active diagnostics through %s every %.0f s", args.diag_port,
                         min(3600.0, max(10.0, args.diag_interval)))
            controller.start_diagnostics()

    def _terminate(*_):  # SIGTERM (systemd, docker stop) -> same clean shutdown as Ctrl+C
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _terminate)
    server = make_server(engine, args.host, args.port, controller)
    logging.info("UI: http://%s:%d/ (no authentication: keep it on a trusted network)", args.host, args.port)
    if not is_loopback(args.host):
        if controller.allow_remote_config:
            logging.warning("listening on %s: anyone on the network can view the topology AND set the Thread "
                            "dataset (the key is sent unencrypted); use --local-config-only to prevent that", args.host)
        else:
            logging.warning("listening on %s: anyone on the network can view the topology; "
                            "the dataset can only be entered from this machine", args.host)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        controller.stop_diagnostics()
        controller.stop_capture()
        if sim:
            sim.stop()
        persister.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
