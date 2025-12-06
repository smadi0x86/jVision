#!/usr/bin/env python3
"""
Multi-stage scanner: runs fscan for fast discovery, then nmap for detailed enumeration.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from uploader.core import UploaderConfig, Uploader
from uploader.plugins import fscan, nmap


def main():
    parser = argparse.ArgumentParser(
        description="Multi-stage scan: fscan (fast) → nmap (detailed)"
    )
    parser.add_argument("target", help="Target IP/hostname/subnet")
    parser.add_argument("--server", default="localhost", help="jVision server host")
    parser.add_argument("--port", type=int, default=7777, help="jVision server port")
    parser.add_argument("--subnet", default=None, help="Subnet label")
    parser.add_argument("--timing", default="3", help="Nmap timing template")
    parser.add_argument("--top-ports", type=int, default=200, help="Nmap top ports")
    parser.add_argument("--verify-ssl", action="store_true")
    parser.add_argument("--skip-fscan", action="store_true", help="Skip fscan stage")
    parser.add_argument("--skip-nmap", action="store_true", help="Skip nmap stage")
    args = parser.parse_args()

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

    # Stage 1: fscan (fast reconnaissance)
    if not args.skip_fscan:
        print("[*] Stage 1: Running fscan for fast discovery...")
        try:
            fscan_boxes = fscan.collect(args.target, subnet=args.subnet)
            uploader.send_boxes(fscan_boxes)
            print("[+] fscan results uploaded")
        except Exception as e:
            print(f"[!] fscan failed: {e}")

    # Stage 2: nmap (detailed enumeration)
    if not args.skip_nmap:
        print("[*] Stage 2: Running nmap for detailed enumeration...")
        try:
            nmap_boxes = nmap.collect(
                args.target, args.subnet, args.timing, args.top_ports
            )
            uploader.send_boxes(nmap_boxes)
            print("[+] nmap results uploaded")
        except Exception as e:
            print(f"[!] nmap failed: {e}")

    print("[✓] Multi-stage scan complete")


if __name__ == "__main__":
    main()
