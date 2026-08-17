from __future__ import annotations

from __future__ import annotations

import argparse
import sys
import socket
import time

from port_scanner.core.ports_data import COMMON_PORTS
from port_scanner.core.tcp_scan import tcp_connect_scan, PortResult
from port_scanner.customization.output_customize import print_result, print_progress, enrich_service_info


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="Port Scanner",
        description="A simple TCP/SYN scanner with service indentification"
        epilog="If you have any questions or suggestions, feel free to let me know!"
        )

    parser.add_argument(
        "target",
        help="Target IP address or hostname")

    parser.add_argument(
        "-p", "--ports",
        help="Comma-separated list of ports to scan (e.g., 22,80,443) or a range of ports to scan (e.g., 1 - 1024). Default: top common ports.")

    parser.add_argument(
        "-t", "--type",
        choices=["tcp", "syn"],
        default="tcp",
        help="Scan technique. 'tcp' = full connect scan (no privileged needed). 'syn' = half-open scan via scapy (needs root privilege). Default: tcp "
    )

    parser.add_argument(
        "--timeout"
        type=float,
        default=1.0,
        help="Per-port timeout in seconds. Default: 1.0"
    )

    parser.add_argument(
        "-a", "--all",
        action="store_true",
        help="Show scan report for both closed and filtered ports. Default: only show open port"
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=200,
        help="Max concurrent scan. Default: 200"
    )
    
    return parser

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = parser.parse_args(argv)