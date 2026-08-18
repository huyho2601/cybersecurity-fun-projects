from __future__ import annotations
import re
import argparse
import sys
import socket
import time

from port_scanner.core.ports_data import COMMON_PORTS
from port_scanner.core.tcp_scan import tcp_connect_scan, PortResult
from port_scanner.customization.output_customize import print_result, print_progress, enrich_service_info
from port_scanner.core.syn_scan import ScapyNotAvailableError, InsufficientPrivilegesError, syn_scan


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
        help="Comma-separated list of ports to scan (e.g., 22,80,443) or a range of ports to scan (e.g., 1 - 1024) or 'common' for a list of top common ports or combination of comma-separated values and ranges (e.g., 22,80-443). Default: top common ports.",
        default="common")

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

def parse_ports(ports_str: str | None) -> list[int]:
    ports_int_complete = []

    # Default case: common ports
    if ports_str is None or ports_str.lower() == "common":
        ports_list = list(COMMON_PORTS.keys())
        ports_int_complete = [int(port) for port in ports_list]
        return ports_int_complete

    # Invalid input: characters or symbols
    if re.fullmatch(r"[\d,\-\s]+", ports_str):
        raise ValueError("Invalid ports input. The port(s) must be a number")

    # Case: "80", "80,443", "1-1024", "22, 80, 1-1024"
    ports_int_complete = []
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            ports_int_complete.extend(range_helper(part))
        else:
            if not part.isdigit():
                raise ValueError(f"Invalid port: {part}. The port must be a number.")
            port_int = int(part)
            if not (1 <= port_int <= 65535):
                raise ValueError(f"Invalid port: {part}. Ports must be in the range 1-65535.")
            ports_int_complete.append(port_int)
    return ports_int_complete


def range_helper(part: str) -> range:
    bounds = part.split("-")
    if len(bounds) != 2 or not all(b.strip().isdigit() for b in bounds):
        raise ValueError(f"Invalid port range: {part}.")
    start_port, end_port = (int(b.strip()) for b in bounds)
    if start_port > end_port:
        raise ValueError("Invalid port range. Start port must be <= end port.")
    if start_port < 1 or end_port > 65535:
        raise ValueError("Invalid port range. Ports must be in the range 1-65535.")
    return range(start_port, end_port + 1)

def resolve_target(target: str) -> str:
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Could not resolve the host '{target}'", file=sys.stderr)
        sys.exit(1)



def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = parser.parse_args(argv)

    # Parse user's inputs
    try:
        ports = parse_ports(argv.ports)
    except (ValueError, TypeError) as e:
        print(f"Error parsing ports: {e}")
        return 1

    if not ports:
        parser.error("No valid ports to scan")

    ip = resolve_target(argv.target)
    display_target = argv.target if argv.target == ip else f"{argv.target} - {ip}"

    print(f"Start scanning {display_target} - {len(ports)} ports, mode = {argv.type}")
    start = time.time()

    # Starting the scan
    if argv.type == "tcp":
        results = tcp_connect_scan(
            ip,
            ports,
            timeout = argv.timeout,
            max_threads = argv.threads,
            progress_cb=print_progress,
        )
    else:
        try:
            results = syn_scan(
                target = ip,
                ports = ports,
                timeout = argv.timeout
                max_threads = min(argv.threads,50),
                progress_cb=print_progress,
            )
        except (ScapyNotAvailableError, InsufficientPrivilegesError) as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    enrich_service_info(results)
    elapsed = time.time() - start

    # Print the results
    print_result(display_target, results, argv.all)
    print(f"\nScan completed in {elapsed:.2f}s")


if __name__ == "__main__":
    sys.exit(main())