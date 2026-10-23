"""
High-Speed Native Route Tracer using Win32 ICMP TTL Variation.
Traces network hops, measures hop-by-hop latency and jitter,
and classifies network segments without relying on external tracert/pathping.
"""

import time
import socket
import ipaddress
import threading
from typing import List, Dict, Any, Optional, Callable
from core.win32_icmp import Win32ICMPEngine


def is_private_or_cgnat(ip_str: str) -> bool:
    """Check if an IP is LAN private (192.168/10/172.16) or Carrier-Grade NAT (100.64.0.0/10)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip in ipaddress.ip_network("100.64.0.0/10")
    except Exception:
        return False


class RouteTracer:
    """Executes high-speed hop-by-hop route discovery."""

    def __init__(self, icmp_engine: Optional[Win32ICMPEngine] = None):
        self.icmp = icmp_engine or Win32ICMPEngine()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def trace(
        self,
        target_ip: str,
        max_hops: int = 25,
        queries_per_hop: int = 3,
        timeout_ms: int = 1000,
        resolve_hostnames: bool = True,
        on_hop: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        on_complete: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
    ):
        """Asynchronous trace run."""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._worker,
            args=(
                target_ip,
                max_hops,
                queries_per_hop,
                timeout_ms,
                resolve_hostnames,
                on_hop,
                on_progress,
                on_complete,
            ),
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _worker(
        self,
        target_ip: str,
        max_hops: int,
        queries_per_hop: int,
        timeout_ms: int,
        resolve_hostnames: bool,
        on_hop: Optional[Callable[[Dict[str, Any]], None]],
        on_progress: Optional[Callable[[int, int], None]],
        on_complete: Optional[Callable[[List[Dict[str, Any]]], None]],
    ):
        target_resolved = self.icmp.resolve_ip(target_ip)
        if not target_resolved:
            if on_complete:
                on_complete([])
            return

        hops_result: List[Dict[str, Any]] = []
        reached_destination = False

        for ttl in range(1, max_hops + 1):
            if self._stop_event.is_set():
                break

            hop_rtts: List[float] = []
            hop_ip: Optional[str] = None
            losses = 0

            for q in range(queries_per_hop):
                if self._stop_event.is_set():
                    break

                res = self.icmp.ping(target_resolved, timeout_ms=timeout_ms, ttl=ttl)
                
                # Check status: 0 is destination reached, 11013 is TTL expired in transit (intermediate router)
                if res["status"] in (0, 11013):
                    if res["from_ip"]:
                        hop_ip = res["from_ip"]
                    if res["rtt_ms"] is not None:
                        hop_rtts.append(res["rtt_ms"])
                else:
                    losses += 1

            if self._stop_event.is_set():
                break

            # Reverse DNS resolution
            hostname = ""
            if hop_ip and resolve_hostnames:
                try:
                    hostname = socket.gethostbyaddr(hop_ip)[0]
                except Exception:
                    hostname = ""

            # Hop statistics
            received_count = len(hop_rtts)
            avg_rtt = round(sum(hop_rtts) / received_count, 2) if received_count > 0 else None
            min_rtt = round(min(hop_rtts), 2) if received_count > 0 else None
            max_rtt = round(max(hop_rtts), 2) if received_count > 0 else None
            jitter = round(max_rtt - min_rtt, 2) if (min_rtt and max_rtt) else 0.0
            loss_pct = round((losses / queries_per_hop) * 100.0, 1)

            hop_data = {
                "hop": ttl,
                "ip": hop_ip or "*",
                "hostname": hostname,
                "avg_rtt": avg_rtt,
                "min_rtt": min_rtt,
                "max_rtt": max_rtt,
                "jitter": jitter,
                "loss_pct": loss_pct,
                "is_private": is_private_or_cgnat(hop_ip) if hop_ip else False,
                "is_destination": (hop_ip == target_resolved),
            }

            hops_result.append(hop_data)

            if on_hop:
                try:
                    on_hop(hop_data)
                except Exception:
                    pass

            if on_progress:
                try:
                    on_progress(ttl, max_hops)
                except Exception:
                    pass

            if hop_ip == target_resolved:
                reached_destination = True
                break

        if on_complete:
            try:
                on_complete(hops_result)
            except Exception:
                pass
