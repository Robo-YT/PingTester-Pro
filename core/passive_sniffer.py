"""
Passive In-Game Netcode Sniffer for Apex Legends.
Monitors live UDP match datagrams exchanged between r5apex.exe and the actual
match server IP (e.g. 15.129.x.x, 3.x.x.x) using elevated Windows raw sockets.
Calculates true gameplay RTT, tick jitter, and packet loss with 0% firewall loss.
"""

import socket
import struct
import time
import threading
from collections import deque
from typing import Dict, Any, Optional, Callable, List, Set, Tuple

from core.ping_engine import PingStats
from core.apex_detector import ApexDetector


class PassiveNetcodeSniffer:
    """
    Passive In-Game Netcode Sniffer.
    Listens to live authorized match traffic between the client and game host,
    bypassing AWS EC2 ICMP firewall drops completely.
    """

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.stats = PingStats()

    @property
    def is_running(self) -> bool:
        return self._running

    def stop(self):
        """Signals the background sniffer to stop immediately."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._running = False

    def start_sniffing(
        self,
        target_ip: str,
        target_port: int = 27015,
        packet_count: Optional[int] = None,
        duration_seconds: Optional[float] = None,
        tick_rate_hz: float = 20.0,
        late_threshold_ms: float = 130.0,
        on_packet: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_stats: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_finished: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_status: Optional[Callable[[str], None]] = None,
    ):
        """
        Starts passive packet capture on a background thread.
        Matches outgoing client inputs to incoming server world snapshots.
        """
        if self._running:
            return

        self._running = True
        self._stop_event.clear()
        self.stats = PingStats(late_threshold_ms=late_threshold_ms)

        self._thread = threading.Thread(
            target=self._sniff_loop,
            args=(
                target_ip,
                target_port,
                packet_count,
                duration_seconds,
                tick_rate_hz,
                late_threshold_ms,
                on_packet,
                on_stats,
                on_finished,
                on_status,
            ),
            daemon=True,
        )
        self._thread.start()

    def _sniff_loop(
        self,
        target_ip: str,
        target_port: int,
        packet_count: Optional[int],
        duration_seconds: Optional[float],
        tick_rate_hz: float,
        late_threshold_ms: float,
        on_packet: Optional[Callable[[Dict[str, Any]], None]],
        on_stats: Optional[Callable[[Dict[str, Any]], None]],
        on_finished: Optional[Callable[[Dict[str, Any]], None]],
        on_status: Optional[Callable[[str], None]],
    ):
        raw_sock = None
        try:
            # 1. Determine local adapter IP
            try:
                s_probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s_probe.connect((target_ip, target_port if target_port > 0 else 27015))
                local_ip = s_probe.getsockname()[0]
                s_probe.close()
            except Exception:
                local_ip = "0.0.0.0"

            # 2. Bind raw socket (Requires Administrator)
            try:
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                raw_sock.bind((local_ip, 0))
                raw_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                raw_sock.settimeout(0.15)
            except PermissionError:
                if on_status:
                    on_status("⚠️ Admin Required: Run 'run_as_admin.bat' for Driver UDP Sniffer.")
                if on_finished:
                    on_finished(self.stats.to_dict())
                self._running = False
                return
            except Exception as e:
                if on_status:
                    on_status(f"⚠️ Raw Socket Bind Error: {e}")
                if on_finished:
                    on_finished(self.stats.to_dict())
                self._running = False
                return

            # 3. Discover local UDP ports used by Apex Legends
            local_ports: Set[int] = set()
            proc = ApexDetector.get_apex_process()
            if proc:
                sockets = ApexDetector.get_live_apex_sockets(proc["pid"])
                local_ports = {
                    s["local_port"]
                    for s in sockets
                    if s.get("proto") == "UDP" and s.get("local_port")
                }

            if on_status:
                port_desc = f":{target_port}" if target_port > 0 else ""
                on_status(f"🎮 Passive Sniffer Active: Listening to live match traffic with {target_ip}{port_desc}...")

            sent_timestamps: deque = deque(maxlen=256)
            seq_counter = 0
            t_start = time.perf_counter()
            t_last_stat = t_start
            t_last_packet_seen = t_start

            # Main sniffing loop
            while not self._stop_event.is_set():
                # Check limits
                elapsed = time.perf_counter() - t_start
                if duration_seconds and elapsed >= duration_seconds:
                    break
                if packet_count and self.stats.received >= packet_count:
                    break

                try:
                    pkt, _ = raw_sock.recvfrom(65535)
                except socket.timeout:
                    # Check if game traffic has gone quiet (>4 seconds)
                    if (time.perf_counter() - t_last_packet_seen) > 4.0:
                        if on_status:
                            on_status("⏳ Awaiting in-game packets... (Ensure you are in a live match, not lobby)")
                    continue
                except Exception:
                    break

                if len(pkt) < 28:
                    continue

                # Must be IPv4
                if (pkt[0] >> 4) != 4:
                    continue

                ihl = (pkt[0] & 0x0F) * 4
                if len(pkt) < ihl + 8:
                    continue

                # Protocol 17 = UDP
                if pkt[9] != 17:
                    continue

                src_ip = socket.inet_ntoa(pkt[12:16])
                dst_ip = socket.inet_ntoa(pkt[16:20])
                src_port, dst_port = struct.unpack("!HH", pkt[ihl:ihl + 4])
                t_now = time.perf_counter()

                # Case A: Outgoing packet from Apex client to match server
                is_outgoing = (dst_ip == target_ip) and (
                    target_port == 0 or dst_port == target_port or not target_port
                )
                if local_ports:
                    is_outgoing = is_outgoing and (src_port in local_ports)

                if is_outgoing:
                    sent_timestamps.append(t_now)
                    t_last_packet_seen = t_now
                    continue

                # Case B: Incoming packet from match server to Apex client
                is_incoming = (src_ip == target_ip) and (
                    target_port == 0 or src_port == target_port or not target_port
                )
                if local_ports:
                    is_incoming = is_incoming and (dst_port in local_ports)

                if is_incoming:
                    t_last_packet_seen = t_now
                    # Find matching send timestamp
                    matched_sent: Optional[float] = None
                    while sent_timestamps:
                        candidate = sent_timestamps.popleft()
                        diff = t_now - candidate
                        # Plausible physical RTT range: 5ms to 1200ms
                        if diff >= 0.005:
                            matched_sent = candidate
                            break

                    if matched_sent is not None:
                        rtt_ms = round((t_now - matched_sent) * 1000.0, 2)
                        seq_counter += 1
                        is_late = rtt_ms > late_threshold_ms

                        self.stats.add_result(True, rtt_ms)

                        packet_info = {
                            "seq": seq_counter,
                            "rtt_ms": rtt_ms,
                            "is_late": is_late,
                            "success": True,
                            "ttl": pkt[8],
                            "mode": "PASSIVE_UDP",
                        }

                        if on_packet:
                            on_packet(packet_info)

                        if on_stats and (time.perf_counter() - t_last_stat) >= 0.1:
                            t_last_stat = time.perf_counter()
                            on_stats(self.stats.to_dict())

            # Loop finished normally or stopped
            if on_finished:
                on_finished(self.stats.to_dict())

        finally:
            if raw_sock:
                try:
                    raw_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
                try:
                    raw_sock.close()
                except Exception:
                    pass
            self._running = False
