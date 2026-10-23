"""
High-Speed UDP Probing Engine for Apex Legends & Gaming Ports.
Sends real UDP game datagrams to live server ports (e.g. 27015, 37015),
measuring true UDP round-trip latency, packet loss, and jitter.
"""

import time
import socket
import threading
from typing import Dict, Any, Optional, Callable
from core.ping_engine import PingStats


class UDPEngine:
    """Direct UDP Datagram Probe Engine."""

    # Standard Steam Datagram / Source Engine query payload accepted by Apex relays
    A2S_PAYLOAD = b"\xff\xff\xff\xffTSource Engine Query\x00"

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    @property
    def is_running(self) -> bool:
        return self._running

    def ping_udp(
        self,
        target_ip: str,
        target_port: int = 27015,
        timeout_sec: float = 1.2,
        payload: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """
        Sends a single UDP probe to (target_ip, target_port)
        and waits for response.
        """
        data_to_send = payload or self.A2S_PAYLOAD
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout_sec)

        t_start = time.perf_counter()
        try:
            s.sendto(data_to_send, (target_ip, target_port))
            recv_data, addr = s.recvfrom(2048)
            t_end = time.perf_counter()
            rtt_ms = round((t_end - t_start) * 1000.0, 2)
            return {
                "success": True,
                "rtt_ms": rtt_ms,
                "status": 0,
                "status_text": "UDP_REPLY_OK",
                "from_ip": addr[0],
                "from_port": addr[1],
                "bytes_received": len(recv_data),
                "timestamp": time.time(),
            }
        except socket.timeout:
            return {
                "success": False,
                "rtt_ms": None,
                "status": 10060,
                "status_text": "UDP_REQ_TIMED_OUT",
                "from_ip": target_ip,
                "from_port": target_port,
                "bytes_received": 0,
                "timestamp": time.time(),
            }
        except Exception as e:
            return {
                "success": False,
                "rtt_ms": None,
                "status": -1,
                "status_text": f"UDP_SOCKET_ERR: {e}",
                "from_ip": target_ip,
                "from_port": target_port,
                "bytes_received": 0,
                "timestamp": time.time(),
            }
        finally:
            try:
                s.close()
            except Exception:
                pass

    def start_udp_stream(
        self,
        target_ip: str,
        target_port: int = 27015,
        packet_count: Optional[int] = 100,
        duration_seconds: Optional[float] = None,
        tick_rate_hz: float = 10.0,
        late_threshold_ms: float = 130.0,
        timeout_sec: float = 1.2,
        on_packet: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_stats: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_finished: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        """Streams UDP probes at the specified tick rate in a background thread."""
        if self._running:
            self.stop()

        self._stop_event.clear()
        self._running = True

        self._thread = threading.Thread(
            target=self._worker,
            args=(
                target_ip,
                target_port,
                packet_count,
                duration_seconds,
                tick_rate_hz,
                late_threshold_ms,
                timeout_sec,
                on_packet,
                on_stats,
                on_finished,
            ),
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._running = False

    def _worker(
        self,
        target_ip: str,
        target_port: int,
        packet_count: Optional[int],
        duration_seconds: Optional[float],
        tick_rate_hz: float,
        late_threshold_ms: float,
        timeout_sec: float,
        on_packet: Optional[Callable[[Dict[str, Any]], None]],
        on_stats: Optional[Callable[[Dict[str, Any]], None]],
        on_finished: Optional[Callable[[Dict[str, Any]], None]],
    ):
        stats = PingStats(late_threshold_ms=late_threshold_ms)
        target_interval = 1.0 / max(0.1, tick_rate_hz)
        seq = 0
        t_stream_start = time.perf_counter()

        while not self._stop_event.is_set():
            t_now = time.perf_counter()
            elapsed_sec = t_now - t_stream_start

            if duration_seconds is not None and elapsed_sec >= duration_seconds:
                break

            if packet_count is not None and seq >= packet_count:
                break

            seq += 1
            t_loop_start = time.perf_counter()

            res = self.ping_udp(target_ip, target_port=target_port, timeout_sec=timeout_sec)
            res["seq"] = seq
            is_late = res["success"] and (res["rtt_ms"] is not None) and (res["rtt_ms"] > late_threshold_ms)
            res["is_late"] = is_late

            stats.add_result(res["success"], res["rtt_ms"])

            if on_packet:
                try:
                    on_packet(res)
                except Exception:
                    pass

            if on_stats:
                try:
                    s_dict = stats.to_dict()
                    s_dict["elapsed_sec"] = round(elapsed_sec, 1)
                    s_dict["duration_seconds"] = duration_seconds
                    s_dict["remaining_sec"] = max(0.0, round(duration_seconds - elapsed_sec, 1)) if duration_seconds else None
                    on_stats(s_dict)
                except Exception:
                    pass

            t_elapsed = time.perf_counter() - t_loop_start
            sleep_time = target_interval - t_elapsed
            if sleep_time > 0 and not self._stop_event.is_set():
                end_sleep = time.perf_counter() + sleep_time
                while time.perf_counter() < end_sleep and not self._stop_event.is_set():
                    time.sleep(0.002)

        self._running = False
        final_summary = stats.to_dict()
        final_summary["elapsed_sec"] = round(time.perf_counter() - t_stream_start, 1)
        final_summary["duration_seconds"] = duration_seconds
        if on_finished:
            try:
                on_finished(final_summary)
            except Exception:
                pass
