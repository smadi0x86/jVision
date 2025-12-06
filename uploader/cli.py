from __future__ import annotations

import argparse
from pathlib import Path

from .core import UploaderConfig, Uploader
from .plugins import nmap, fscan


def main():
    parser = argparse.ArgumentParser(description="Lightweight uploader for jVision")
    parser.add_argument("target", help="Target IP/hostname/subnet passed to nmap")
    parser.add_argument("--server", default="localhost", help="jVision server host")
    parser.add_argument("--port", type=int, default=7777, help="jVision server port")
    parser.add_argument("--subnet", dest="subnet", default=None, help="Subnet label to attach to hosts")
    parser.add_argument("--xml", type=Path, help="Existing Nmap XML (skip running nmap)")
    parser.add_argument("--timing", default="3", help="Nmap timing template (default T3)")
    parser.add_argument("--top-ports", type=int, default=200, help="Limit to top ports for gentler scans")
    parser.add_argument("--verify-ssl", action="store_true")
    parser.add_argument("--plugin", choices=["nmap", "fscan"], default="nmap", help="Scanner plugin to use")
    args = parser.parse_args()

    # Select plugin based on argument
    if args.plugin == "fscan":
        plugin = fscan
    else:
        plugin = nmap

    cfg = UploaderConfig(
        server_url=f"http://{args.server}:{args.port}",
        verify_ssl=args.verify_ssl,
        batch_size=25,
        timeout=20,
        max_retries=3,
        backoff_seconds=2.0,
        rate_limit_delay=0.5,
    )
    uploader = Uploader(cfg)
    if args.xml:
        # Use nmap parser for XML files
        boxes = nmap.parse_nmap_xml(args.xml, subnet=args.subnet or args.target)
    else:
        # Call the appropriate plugin's collect function
        if args.plugin == "fscan":
            boxes = plugin.collect(args.target, subnet=args.subnet)
        else:  # nmap
            boxes = plugin.collect(args.target, args.subnet, args.timing, args.top_ports)
    uploader.send_boxes(boxes)


if __name__ == "__main__":
    main()
