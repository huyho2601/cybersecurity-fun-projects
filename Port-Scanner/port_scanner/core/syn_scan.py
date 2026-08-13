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
from typing import Callable, Optional

from .tcp_scan import PortResult

try:
  from scapy.all import IP, TCP, sr1, send
  SCAPY_AVAILABLE = True
except ImportError:
  SCAPY_AVAILABLE = False


class ScapyNotAvailableError(Exception):
  """Raised when Scapy is not available for SYN scan"""
  pass

class InsufficientPrivilegesError(Exception):
  """Raised when the user does not have sufficient privileges to perform SYN scan"""
  pass


def _check_syn_port(target:str, port:int, timeout:float) -> PortResult: