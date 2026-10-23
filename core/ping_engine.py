"""
Stream Ping Engine for Real-Time Game Packet Timing Analysis.
Supports high tick rates (1Hz to 60Hz), late-packet thresholding,
and RFC 3550 gaming jitter calculations.
"""

import time
import math
import threading
from typing import List, Dict, Any, Optional, Callable
from collections import deque
from core.win32_icmp import Win32ICMPEngine


class PingStats:
    """Calculates comprehensive network timing statistics."""

    def __init__(self, late_threshold_ms: float = 130.0):
        self.late_threshold_ms = late_threshold_ms
        self.sent = 0
        self.received = 0
        self.lost = 0
        self.late_count = 0
        
        self.rtt_history: List[float] = []
        self.consecutive_jitter_diffs: List[float] = []
        
        self.min_rtt = float("inf")
        self.max_rtt = 0.0
        self.sum_rtt = 0.0
        
        # RFC 3550 Jitter state
        self._prev_rtt: Optional[float] = None
        self._rfc_jitter = 0.0

    def add_result(self, success: bool, rtt_ms: Optional[float]):
        self.sent += 1
        if success and rtt_ms is not None:
            self.received += 1
            self.rtt_history.append(rtt_ms)
            self.sum_rtt += rtt_ms
            
            if rtt_ms < self.min_rtt:
                self.min_rtt = rtt_ms
            if rtt_ms > self.max_rtt:
                self.max_rtt = rtt_ms

            if rtt_ms > self.late_threshold_ms:
                self.late_count += 1

            if self._prev_rtt is not None:
                diff = abs(rtt_ms - self._prev_rtt)
                self.consecutive_jitter_diffs.append(diff)
                # RFC 3550 smoothed jitter update
                self._rfc_jitter += (diff - self._rfc_jitter) / 16.0

            self._prev_rtt = rtt_ms
        else:
            self.lost += 1

    @property
    def avg_rtt(self) -> float:
        return (self.sum_rtt / self.received) if self.received > 0 else 0.0

    @property
    def loss_pct(self) -> float:
        return (self.lost / self.sent * 100.0) if self.sent > 0 else 0.0

    @property
    def late_pct(self) -> float:
        return (self.late_count / self.received * 100.0) if self.received > 0 else 0.0

    @property
    def mean_jitter(self) -> float:
        if not self.consecutive_jitter_diffs:
            return 0.0
        return sum(self.consecutive_jitter_diffs) / len(self.consecutive_jitter_diffs)

    @property
    def rfc_jitter(self) -> float:
        return self._rfc_jitter

    @property
    def std_dev(self) -> float:
        if len(self.rtt_history) < 2:
            return 0.0
        avg = self.avg_rtt
        variance = sum((x - avg) ** 2 for x in self.rtt_history) / (len(self.rtt_history) - 1)
        return math.sqrt(variance)

    def get_percentile(self, p: float) -> float:
        if not self.rtt_history:
            return 0.0
        sorted_rtts = sorted(self.rtt_history)
        k = (len(sorted_rtts) - 1) * (p / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_rtts[int(k)]
        d0 = sorted_rtts[int(f)] * (c - k)
        d1 = sorted_rtts[int(c)] * (k - f)
        return d0 + d1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sent": self.sent,
            "received": self.received,
            "lost": self.lost,
            "loss_pct": round(self.loss_pct, 2),
            "late_count": self.late_count,
            "late_pct": round(self.late_pct, 2),
            "late_threshold_ms": self.late_threshold_ms,
            "min_rtt": round(self.min_rtt, 2) if self.received > 0 else 0.0,
            "avg_rtt": round(self.avg_rtt, 2),
            "max_rtt": round(self.max_rtt, 2),
            "median_rtt": round(self.get_percentile(50), 2),
            "p95_rtt": round(self.get_percentile(95), 2),
            "p99_rtt": round(self.get_percentile(99), 2),
            "mean_jitter": round(self.mean_jitter, 2),
            "rfc_jitter": round(self.rfc_jitter, 2),
            "std_dev": round(self.std_dev, 2),
        }


class StreamPingEngine:
    """Runs a continuous or count-limited stream of ICMP packets at target tick rate."""

    def __init__(self, icmp_engine: Optional[Win32ICMPEngine] = None):
        self.icmp = icmp_engine or Win32ICMPEngine()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    @property
    def is_running(self) -> bool:
        return self._running

    def start_stream(
        self,
        target_ip: str,
        packet_count: Optional[int] = 100,
        duration_seconds: Optional[float] = None,
        tick_rate_hz: float = 10.0,
        late_threshold_ms: float = 130.0,
        timeout_ms: int = 1500,
        on_packet: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_stats: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_finished: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        """
        Starts ping streaming in a dedicated background thread.
        duration_seconds: If set, runs until time expires (e.g. 60.0 for 1 min).
        packet_count: If set, stops after N packets.
        """
        if self._running:
            self.stop()

        self._stop_event.clear()
        self._running = True

        self._thread = threading.Thread(
            target=self._worker,
            args=(
                target_ip,
                packet_count,
                duration_seconds,
                tick_rate_hz,
                late_threshold_ms,
                timeout_ms,
                on_packet,
                on_stats,
                on_finished,
            ),
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        """Signals the background worker to stop immediately."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._running = False

    def _worker(
        self,
        target_ip: str,
        packet_count: Optional[int],
        duration_seconds: Optional[float],
        tick_rate_hz: float,
        late_threshold_ms: float,
        timeout_ms: int,
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

            # Check time-based stop
            if duration_seconds is not None and elapsed_sec >= duration_seconds:
                break

            # Check packet-count stop
            if packet_count is not None and seq >= packet_count:
                break

            seq += 1
            t_loop_start = time.perf_counter()

            # Execute single ping
            res = self.icmp.ping(target_ip, timeout_ms=timeout_ms)
            res["seq"] = seq
            is_late = res["success"] and (res["rtt_ms"] is not None) and (res["rtt_ms"] > late_threshold_ms)
            res["is_late"] = is_late

            stats.add_result(res["success"], res["rtt_ms"])

            # Callbacks
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

            # Precise interval sleeping (accounting for ping duration)
            t_elapsed = time.perf_counter() - t_loop_start
            sleep_time = target_interval - t_elapsed
            if sleep_time > 0 and not self._stop_event.is_set():
                # Sleep in short increments for responsive cancellation
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
