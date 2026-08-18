"""
SYN Scan: Half-Open scan

Scanner send SYN packet to the target port and trick the target to response with SYN-ACK:

  SYN-ACK back -> port is open
  RST back -> port is closed
  No response -> port is filtered
"""

from __future__ import annotations

import random
import concurrent.futures
from typing import Callable, List, Optional

from .tcp_scan import PortResult

try:
  from scapy.all import IP, TCP, sr1, send
  SCAPY_AVAILABLE = True
except ImportError:
  SCAPY_AVAILABLE = False


class ScapyNotAvailableError(RuntimeError):
  """Raised when Scapy is not available for SYN scan"""
  pass

class InsufficientPrivilegesError(RuntimeError):
  """Raised when the user does not have sufficient privileges to perform SYN scan"""
  pass


def _check_syn_port(target:str, port:int, timeout:float) -> PortResult:
  """
  Syn scan will only focus on scanning the top 1000 common ports, as it is a stealthy scan and can be easily detected 
  """
  src_port = random.randint(1024, 65535)

  #Send craft query packet
  syn_packet = IP(dst=target)/TCP(sport=src_port, dport=port, flags="S")

  # Send and receive the packet with sr1()
  response = sr1(syn_packet, timeout=timeout, verbose=0)

  if response is None:
    return PortResult(port=port, state="filtered", banner="")

  if response.haslayer(TCP):
    flags = response.getlayer(TCP).flags
    if flags == 0x12:  # SYN-ACK
      # Send RST to close the connection
      rst_packet = IP(dst=target)/TCP(sport=src_port, dport=port, flags="R")
      send(rst_packet, verbose=0)
      return PortResult(port=port, state="open", banner="")
    elif flags == 0x14:  # RST
      return PortResult(port=port, state="closed", banner="")

  return PortResult(port=port, state="filtered", banner="")

def syn_scan(
    target: str,
    ports: list[int],
    timeout: float = 1.0,
    max_workers: int = 50,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> list[PortResult]:

  if not SCAPY_AVAILABLE:
    raise ScapyNotAvailableError("Scapy is not available. Please install scapy to use SYN scan: pip install scapy")

  import os
  if hasattr(os, "geteuid") and os.geteuid() != 0:
    raise InsufficientPrivilegesError("SYN scan requires root privileges. Please run the script as root or with sudo.")

  results: List[PortResult] = []
  total = len(ports)
  done = 0

  with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
    futures = {executor.submit(_check_syn_port, target, p, timeout): p for p in ports}

    for ft in concurrent.futures.as_completed(futures):
      results.append(ft.result())
      done += 1
      if progress_cb:
        progress_cb(done, total)

  results.sort(key=lambda x: x.port)
  return results