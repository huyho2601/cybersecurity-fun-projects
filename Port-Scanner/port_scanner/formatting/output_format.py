import csv
import io
import json
import sys
from dataclasses import asdict

from port_scanner.core.tcp_scan import PortResult
from port_scanner.core.ports_data import lookup_service

