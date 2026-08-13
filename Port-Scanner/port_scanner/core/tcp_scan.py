"""
TCP Connect Scan Module
"""

from __future__ import annotations

import socket
import concurrent.futures
from dataclasses import dataclass
from typing import Callable, Optional

@dataclass
class PortResult:
  port: int
  state: str # {"open", "closed", "filtered"}
  banner: str = ""
  service: str = ""
  description: str = ""

def _check_port(target:str, port:int, timeout:float) -> PortResult:
    """
    Check if a port is open on a target using TCP connect"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
      result = sock.connect_ex((target,port))
      if result == 0:
        return PortResult(port=port, state="open")
      return PortResult(port=port, state="closed")
    except socket.timeout:
      return PortResult(port=port, state="filtered")
    except OSError:
      return PortResult(port=port, state="filtered")
    finally:
      sock.close()

# TODO: Add more robust banner grabbing logic for different protocols (HTTP, FTP, SMTP, etc.)
def grab_banner(target:str, port:int, timeout = 1.5) ->str:
    """
    Attempt to grab a banner from a service running on a target port"""
    try:
      with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((target, port))
        banner = ""
        try:
          data = sock.recv(1024)
          banner = data.decode(errors="ignore").strip()
        except socket.timeout:
          pass

        if not banner:
          try:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(1024)
            banner = data.decode(errors="ignore").strip()
          except (socket.timeout, OSError):
            pass

        return banner.splitlines()[0] if banner else ""

    except OSError:
      return ""

def tcp_connect_scan(
      target: str,
      ports: list[int],
      timeout: float = 1.0,
      max_threads: int = 100,
      grab_banner: bool = True,
      progress_cb: Optional[Callable[[int, int], None]] = None,
  ) -> list[PortResult]:
      """
      Scan ports on target using TCP connect attemps
      """
      results: list[PortResult] = []
      total = len(ports)
      done = 0

      # Use ThreadPoolExecutor to scan ports concurrently
      with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(_check_port, target, p, timeout):p for p in ports}

        for future in concurrent.futures.as_completed(futures):
          res = future.result()
          results.append(res)
          done += 1
          if progress_cb:
            progress_cb(done, total)

      # Filter out open ports for banner grabbing
      open_results = [r for r in results if r.state == "open"]

      # Identify banners for open ports
      if grab_banner and open_results:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, len(open_results))) as executor:
          banner_future ={
            executor.submit(grab_banner, target, r.port, timeout + 0.5): r for r in open_results
          }
          for future in concurrent.futures.as_completed(banner_future):
            r = banner_future[future]
            r.banner = future.result()

      results.sort(key=lambda x: x.port)
      return results
