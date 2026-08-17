from __future__ import annotations

from __future__ import annotations

import argparse
import sys
import socket
import time

from port_scanner.core.ports_data import COMMON_PORTS
from port_scanner.core.tcp_scan import tcp_connect_scan, PortResult
from port_scanner.formatting.output_format import print_result, print_progress, enrich_service_info

def help_message():
    return """
Usage: python port_scanner.py [OPTIONS] TARGET

Options:
  -h, --help \t Show this help message and exit
  -p, --ports \t Specify the ports to scan (comma-separated)
  -a, --all \t Show all ports (open, filtered, closed)
  -c, --closed \t Show only closed ports
  -f, --filtered \t Show only filtered ports
  -common, --common \t Scan only the top 1000 common ports
"""