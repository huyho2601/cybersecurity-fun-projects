import csv
import io
import json
import sys
from dataclasses import asdict

from port_scanner.core.tcp_scan import PortResult
from port_scanner.core.ports_data import lookup_service
import colors as clr 

def _coloring(text: str, color: str) -> str:
  if not clr.enabled():
    return text
  return f"{color}{text}{clr.RESET}"


def enrich_service_info(results: list[PortResult]):
  for r in results:
    service, description = lookup_service(r.port)
    r.service = service
    r.description = description

def print_progress(done: int, total: int):
  bar_length = 30
  filled = int(bar_length * done / total) if total else bar_length
  bar = "#" * filled + "-" * (bar_length - filled)
  sys.stderr.write(f"\rScanning [{bar}] {done}/{total}")
  sys.stderr.flush()
  if done == total:
    sys.stderr.write("\n")

# TODO: Add a logical way to handle the case when the user wants to see closed/filtered ports in the output
# TODO: Idea -a (all) flag to show all ports, or -c (closed) to show closed ports, or -f (filtered) to show filtered ports
def print_result(target: str, results: list[PortResult], show_command: bool = False):
  open_ports = [r for r in results if r.state == "open"]
  filtered_ports = [r for r in results if r.state == "filtered"]
  closed_ports = [r for r in results if r.state == "closed"]

  print()
  print(_coloring(f"Scan report for {target}", clr.BOLD))
  print(f"=> Open ports: {len(open_ports)}")
  print(f"=> Filtered ports: {len(filtered_ports)}")
  print(f"=> Closed ports: {len(closed_ports)}")

  if open_ports:
    header = f"{'PORT':<15}{'STATE':<15}{'SERVICE':<25}{'DESCRIPTION':<30}"
    print(_coloring(header, clr.CYAN))
    print(_coloring("-" * len(header), clr.CYAN))

    for r in open_ports:
      info = r.banner if r.banner else r.service
      print(f"{r.port:<15}{_coloring(r.state, clr.GREEN):<15}{r.service:<25}{info:<30}")

    print()

  if show_command and filtered_ports:
    pass

  if show_command and closed_ports:
    pass