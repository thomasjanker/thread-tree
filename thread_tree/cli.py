from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
from pathlib import Path

from .capture import DEFAULT_EXTCAP_SCRIPT
from .dataset import parse_dataset
from .engine import Engine
from .runtime import Controller
from .server import is_loopback, make_server
from .simulate import Simulator, populate
from .store import Persister, Store


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="thread-tree", description="Thread network tree from a passive 802.15.4 sniffer")
    sub = p.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--host", default="127.0.0.1", help="bind address (default: localhost only)")
    common.add_argument("--port", type=int, default=8787)
    common.add_argument("--db", default="thread-tree.sqlite", help="persistence file")
    run = sub.add_parser("run", parents=[common], help="capture and serve")
    run.add_argument("--source", required=True,
                     help="nrf:PORT | pcap:FILE | iface:NAME | cmd:COMMAND | ek:FILE")
    run.add_argument("--channel", type=int, help="802.15.4 channel 11-26 for nrf: (default: from the dataset)")
    run.add_argument("--extcap-script", default=DEFAULT_EXTCAP_SCRIPT, help="Nordic nrf802154_sniffer.py")
    run.add_argument("--dataset", help="active dataset TLVs as hex; locks the UI form (prefer env THREAD_TREE_DATASET)")
    run.add_argument("--key", help="network key as 32 hex chars (prefer env THREAD_TREE_KEY)")
    run.add_argument("--allow-remote-config", action="store_true",
                     help="allow entering the dataset in the UI although the server is not bound to localhost "
                          "(the key then travels unencrypted over HTTP!)")
    run.add_argument("--tshark", default="tshark")
    run.add_argument("--tshark-arg", action="append", default=[], help="extra tshark argument (repeatable)")
    sub.add_parser("demo", parents=[common], help="serve a simulated network (no hardware)")
    dec = sub.add_parser("dataset", help="decode a dataset and print what it contains (no secrets)")
    dec.add_argument("tlvs", nargs="?", help="hex; default: env THREAD_TREE_DATASET")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

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
        populate(engine)
        controller = Controller(engine, "demo", editable=False, locked_reason="demo")
    else:
        if args.channel is not None and not 11 <= args.channel <= 26:
            print(f"invalid channel {args.channel}: Thread uses 11-26", file=sys.stderr)
            return 2
        editable = is_loopback(args.host) or args.allow_remote_config
        try:
            controller = Controller(
                engine, "run", args.source, args.channel,
                dataset_path=Path(args.db + ".dataset"),
                cli_dataset=args.dataset or os.environ.get("THREAD_TREE_DATASET"),
                cli_key=args.key or os.environ.get("THREAD_TREE_KEY"),
                tshark=args.tshark, extra=args.tshark_arg, extcap_script=args.extcap_script,
                editable=editable, locked_reason=None if editable else "remote")
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

    def _terminate(*_):  # SIGTERM (systemd, docker stop) -> same clean shutdown as Ctrl+C
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _terminate)
    server = make_server(engine, args.host, args.port, controller)
    logging.info("UI: http://%s:%d/ (no authentication: keep it on a trusted network)", args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop_capture()
        if sim:
            sim.stop()
        persister.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
