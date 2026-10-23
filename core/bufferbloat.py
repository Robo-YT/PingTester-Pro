"""
Bufferbloat & Loaded Latency Evaluator (Waveform-Equivalent 3-Phase Bidirectional Engine).
Measures true latency under idle conditions vs sustained multi-threaded network load
across BOTH Download and Upload directions to detect router queue buildup and link saturation.
"""

import time
import urllib.request
import threading
from typing import Dict, Any, Optional, Callable, List
from core.win32_icmp import Win32ICMPEngine


class BufferbloatTester:
    """Accurately measures bidirectional latency degradation under sustained network load."""

    # High-throughput global CDN endpoints for benign download load generation
    DOWNLOAD_URLS = [
        "https://speed.cloudflare.com/__down?bytes=50000000",   # 50MB Cloudflare chunk
        "https://proof.ovh.net/files/10Mb.dat",                # OVH Speed Test CDN
        "https://speed.cloudflare.com/__down?bytes=25000000",   # 25MB Cloudflare chunk
        "https://speed.cloudflare.com/__down?bytes=10000000",   # 10MB Cloudflare chunk
    ]

    # Global upload sink endpoint for benign upload load generation
    UPLOAD_URL = "https://speed.cloudflare.com/__up"
    UPLOAD_CHUNK = b"0" * (1024 * 512)  # 512 KB payload chunk

    def __init__(self, icmp_engine: Optional[Win32ICMPEngine] = None):
        self.icmp = icmp_engine or Win32ICMPEngine()
        self._stop_event = threading.Event()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    @property
    def is_running(self) -> bool:
        return self._running

    def stop(self):
        """Immediately halts the running bufferbloat test."""
        self._stop_event.set()
        self._running = False

    def start_test_async(
        self,
        target_ip: str,
        unloaded_seconds: float = 3.5,
        download_seconds: float = 7.0,
        upload_seconds: float = 7.0,
        on_phase: Optional[Callable[..., None]] = None,
        on_ping: Optional[Callable[[Dict[str, Any], str], None]] = None,
        on_speed: Optional[Callable[..., None]] = None,
        on_complete: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        """Runs the 3-phase bufferbloat test asynchronously in a background thread."""
        if self._running:
            self.stop()

        self._stop_event.clear()
        self._running = True

        def _worker():
            try:
                res = self.run_test(
                    target_ip=target_ip,
                    unloaded_seconds=unloaded_seconds,
                    download_seconds=download_seconds,
                    upload_seconds=upload_seconds,
                    on_phase=on_phase,
                    on_ping=on_ping,
                    on_speed=on_speed,
                )
            finally:
                self._running = False
            if on_complete:
                on_complete(res)

        self._thread = threading.Thread(target=_worker, daemon=True)
        self._thread.start()

    def run_test(
        self,
        target_ip: str,
        unloaded_seconds: float = 3.5,
        download_seconds: float = 7.0,
        upload_seconds: float = 7.0,
        on_phase: Optional[Callable[..., None]] = None,
        on_ping: Optional[Callable[[Dict[str, Any], str], None]] = None,
        on_speed: Optional[Callable[..., None]] = None,
    ) -> Dict[str, Any]:
        """
        Executes a 3-Phase Waveform-equivalent bufferbloat evaluation:
        Phase 1: Idle Baseline (quiescent RTT)
        Phase 2: Multi-stream Download Saturation (download queue bloat)
        Phase 3: Multi-stream Upload Saturation (upload queue bloat - major gaming culprit)
        """
        self._stop_event.clear()
        self._running = True

        def _emit_phase(msg: str, pct: float, phase_key: str):
            if on_phase:
                try:
                    on_phase(msg, pct, phase_key)
                except TypeError:
                    on_phase(msg, pct)

        def _emit_speed(mbps: float, phase_key: str):
            if on_speed:
                try:
                    on_speed(mbps, phase_key)
                except TypeError:
                    on_speed(mbps)

        # Total test time estimate for progress calculation
        t_total_expected = unloaded_seconds + download_seconds + upload_seconds

        # =====================================================================
        # PHASE 1: IDLE BASELINE LATENCY (~3.5s)
        # =====================================================================
        _emit_phase("Phase 1/3: Measuring Idle Baseline Latency...", 0.05, "baseline")

        unloaded_rtts: List[float] = []
        t_phase1_start = time.perf_counter()

        while (time.perf_counter() - t_phase1_start) < unloaded_seconds:
            if self._stop_event.is_set():
                break

            r = self.icmp.ping(target_ip, timeout_ms=800)
            if r.get("success") and r.get("rtt_ms") is not None:
                rtt = r["rtt_ms"]
                unloaded_rtts.append(rtt)
                if on_ping:
                    on_ping(r, "unloaded")

            elapsed = time.perf_counter() - t_phase1_start
            pct = 0.02 + 0.18 * (elapsed / unloaded_seconds)
            rem = max(0.0, unloaded_seconds - elapsed)
            _emit_phase(f"Phase 1/3: Measuring Idle Baseline ({rem:.1f}s left)...", pct, "baseline")

            time.sleep(0.08)

        base_avg = sum(unloaded_rtts) / len(unloaded_rtts) if unloaded_rtts else 0.0
        base_min = min(unloaded_rtts) if unloaded_rtts else base_avg
        base_max = max(unloaded_rtts) if unloaded_rtts else base_avg
        base_jitter = (
            sum(abs(unloaded_rtts[i] - unloaded_rtts[i - 1]) for i in range(1, len(unloaded_rtts)))
            / max(1, len(unloaded_rtts) - 1)
            if len(unloaded_rtts) > 1
            else 0.0
        )

        if self._stop_event.is_set():
            return self._build_empty_result(base_avg)

        # =====================================================================
        # PHASE 2: DOWNLOAD SATURATION & QUEUE FILL (~7.0s)
        # =====================================================================
        _emit_phase("Phase 2/3: Starting Multi-Stream Download Saturation...", 0.22, "download")

        dl_active = threading.Event()
        dl_active.set()
        dl_bytes = [0]
        dl_lock = threading.Lock()

        def _dl_worker(worker_id: int):
            while dl_active.is_set() and not self._stop_event.is_set():
                url = self.DOWNLOAD_URLS[worker_id % len(self.DOWNLOAD_URLS)]
                try:
                    req = urllib.request.Request(
                        url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
                    )
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        while dl_active.is_set() and not self._stop_event.is_set():
                            chunk = resp.read(65536)
                            if not chunk:
                                break
                            with dl_lock:
                                dl_bytes[0] += len(chunk)
                except Exception:
                    time.sleep(0.1)

        # 6 parallel download streams for robust pipe saturation
        dl_threads = [threading.Thread(target=_dl_worker, args=(i,), daemon=True) for i in range(6)]
        for t in dl_threads:
            t.start()

        # Brief spin-up for queue accumulation
        time.sleep(0.35)

        download_rtts: List[float] = []
        t_phase2_start = time.perf_counter()

        while (time.perf_counter() - t_phase2_start) < download_seconds:
            if self._stop_event.is_set():
                break

            r = self.icmp.ping(target_ip, timeout_ms=1200)
            if r.get("success") and r.get("rtt_ms") is not None:
                rtt = r["rtt_ms"]
                download_rtts.append(rtt)
                if on_ping:
                    on_ping(r, "download")

            t_now = time.perf_counter()
            elapsed_dl = t_now - t_phase2_start
            pct = 0.22 + 0.38 * (elapsed_dl / download_seconds)

            with dl_lock:
                bytes_so_far = dl_bytes[0]
            current_dl_mbps = (bytes_so_far * 8.0 / 1_000_000.0) / max(0.1, elapsed_dl)

            _emit_speed(round(current_dl_mbps, 1), "download")
            rem_dl = max(0.0, download_seconds - elapsed_dl)
            _emit_phase(
                f"Phase 2/3: Download Saturation @ {current_dl_mbps:.1f} Mbps ({rem_dl:.1f}s left)...",
                pct,
                "download",
            )

            time.sleep(0.08)

        # Halt download workers
        dl_active.clear()

        t_dl_total = time.perf_counter() - t_phase2_start
        final_dl_mbps = round((dl_bytes[0] * 8.0 / 1_000_000.0) / max(0.1, t_dl_total), 1)

        dl_avg = sum(download_rtts) / len(download_rtts) if download_rtts else base_avg
        dl_min = min(download_rtts) if download_rtts else base_avg
        dl_max = max(download_rtts) if download_rtts else base_avg
        dl_jitter = (
            sum(abs(download_rtts[i] - download_rtts[i - 1]) for i in range(1, len(download_rtts)))
            / max(1, len(download_rtts) - 1)
            if len(download_rtts) > 1
            else 0.0
        )
        dl_delta = max(0.0, dl_avg - base_avg)

        if self._stop_event.is_set():
            return self._build_empty_result(base_avg)

        # Brief recovery period between download and upload
        time.sleep(0.3)

        # =====================================================================
        # PHASE 3: UPLOAD SATURATION & BUFFER FILL (~7.0s)
        # =====================================================================
        _emit_phase("Phase 3/3: Starting Multi-Stream Upload Saturation...", 0.62, "upload")

        up_active = threading.Event()
        up_active.set()
        up_bytes = [0]
        up_lock = threading.Lock()

        def _up_worker():
            while up_active.is_set() and not self._stop_event.is_set():
                try:
                    req = urllib.request.Request(
                        self.UPLOAD_URL,
                        data=self.UPLOAD_CHUNK,
                        method="POST",
                    )
                    req.add_header("Content-Type", "application/octet-stream")
                    req.add_header("User-Agent", "Mozilla/5.0")
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        _ = resp.read()
                        with up_lock:
                            up_bytes[0] += len(self.UPLOAD_CHUNK)
                except Exception:
                    time.sleep(0.05)

        # 4 parallel upload streams for upstream line saturation
        up_threads = [threading.Thread(target=_up_worker, daemon=True) for _ in range(4)]
        for t in up_threads:
            t.start()

        # Brief spin-up for upload buffer buildup
        time.sleep(0.35)

        upload_rtts: List[float] = []
        t_phase3_start = time.perf_counter()

        while (time.perf_counter() - t_phase3_start) < upload_seconds:
            if self._stop_event.is_set():
                break

            r = self.icmp.ping(target_ip, timeout_ms=1200)
            if r.get("success") and r.get("rtt_ms") is not None:
                rtt = r["rtt_ms"]
                upload_rtts.append(rtt)
                if on_ping:
                    on_ping(r, "upload")

            t_now = time.perf_counter()
            elapsed_up = t_now - t_phase3_start
            pct = 0.62 + 0.36 * (elapsed_up / upload_seconds)

            with up_lock:
                bytes_so_far_up = up_bytes[0]
            current_up_mbps = (bytes_so_far_up * 8.0 / 1_000_000.0) / max(0.1, elapsed_up)

            _emit_speed(round(current_up_mbps, 1), "upload")
            rem_up = max(0.0, upload_seconds - elapsed_up)
            _emit_phase(
                f"Phase 3/3: Upload Saturation @ {current_up_mbps:.1f} Mbps ({rem_up:.1f}s left)...",
                pct,
                "upload",
            )

            time.sleep(0.08)

        # Halt upload workers
        up_active.clear()

        t_up_total = time.perf_counter() - t_phase3_start
        final_up_mbps = round((up_bytes[0] * 8.0 / 1_000_000.0) / max(0.1, t_up_total), 1)

        up_avg = sum(upload_rtts) / len(upload_rtts) if upload_rtts else base_avg
        up_min = min(upload_rtts) if upload_rtts else base_avg
        up_max = max(upload_rtts) if upload_rtts else base_avg
        up_jitter = (
            sum(abs(upload_rtts[i] - upload_rtts[i - 1]) for i in range(1, len(upload_rtts)))
            / max(1, len(upload_rtts) - 1)
            if len(upload_rtts) > 1
            else 0.0
        )
        up_delta = max(0.0, up_avg - base_avg)

        # =====================================================================
        # PHASE 4: WAVEFORM-EQUIVALENT BIDIRECTIONAL GRADING
        # =====================================================================
        worst_delta = max(dl_delta, up_delta)
        peak_delta = max(max(0.0, dl_max - base_avg), max(0.0, up_max - base_avg))

        # Primary Culprit Diagnosis
        if up_delta > (dl_delta + 25.0):
            culprit = "UPLOAD"
            culprit_text = (
                f"Upload Bufferbloat is your main bottleneck (+{up_delta:.1f}ms upload spike vs +{dl_delta:.1f}ms download). "
                "Whenever your PC sends data (streaming, Discord screen share, cloud upload), router queues choke."
            )
        elif dl_delta > (up_delta + 25.0):
            culprit = "DOWNLOAD"
            culprit_text = (
                f"Download Bufferbloat is your main bottleneck (+{dl_delta:.1f}ms download spike vs +{up_delta:.1f}ms upload). "
                "Incoming game or stream packets are delayed in router queues."
            )
        else:
            culprit = "BALANCED"
            culprit_text = f"Both directions exhibit comparable queue buildup (Download +{dl_delta:.1f}ms, Upload +{up_delta:.1f}ms)."

        # Standard ITU-T / Waveform.com Grading Standards
        if worst_delta < 5.0:
            grade = "A+"
            desc = "Exceptional Queue Management. Router exhibits near-zero bufferbloat under heavy bidirectional load (Active SQM)."
            rec = "Your router handles active downloads and uploads cleanly. Real-time gaming packets experience zero queuing delay."
        elif worst_delta < 15.0:
            grade = "A"
            desc = f"Minimal Bufferbloat (+{worst_delta:.1f}ms max delay). Gaming packets experience negligible queue delays."
            rec = "Connection is stable and suitable for competitive gaming even with light background traffic."
        elif worst_delta < 30.0:
            grade = "B"
            desc = f"Moderate Bufferbloat (+{worst_delta:.1f}ms queue delay). Noticeable latency increase when others upload/download."
            rec = "Minor rubberbanding possible if large downloads or uploads run during competitive matches."
        elif worst_delta < 60.0:
            grade = "C"
            desc = f"High Bufferbloat (+{worst_delta:.1f}ms added delay). Router buffers cause packet delays and desync."
            rec = "Noticeable desync during active internet traffic. Enabling Smart Queue Management (Cake/FQ-CoDel) on router will resolve this."
        elif worst_delta < 120.0:
            grade = "D"
            desc = f"Severe Bufferbloat (+{worst_delta:.1f}ms queue stall). Peak latency jumps to {max(dl_max, up_max):.1f}ms under load."
            rec = "Router queues severely bloat under traffic. Installing open-source firmware (OpenWrt) with SQM is highly recommended."
        else:
            grade = "F"
            desc = f"Critical Bufferbloat (+{worst_delta:.1f}ms queue stall). Buffer delay exceeds 120ms during network traffic."
            rec = "Severe rubberbanding, hitreg failure, and ghost bullets will occur whenever any device uploads/downloads. SQM router upgrade is critical."

        _emit_phase("Bufferbloat evaluation completed successfully.", 1.0, "complete")

        return {
            "grade": grade,
            "description": desc,
            "recommendation": rec,
            "culprit": culprit,
            "culprit_text": culprit_text,
            # Baseline
            "unloaded_avg_ms": round(base_avg, 2),
            "unloaded_min_ms": round(base_min, 2),
            "unloaded_max_ms": round(base_max, 2),
            "unloaded_jitter_ms": round(base_jitter, 2),
            # Download
            "download_avg_ms": round(dl_avg, 2),
            "download_min_ms": round(dl_min, 2),
            "download_max_ms": round(dl_max, 2),
            "download_jitter_ms": round(dl_jitter, 2),
            "download_delta_ms": round(dl_delta, 2),
            "download_mbps": final_dl_mbps,
            # Upload
            "upload_avg_ms": round(up_avg, 2),
            "upload_min_ms": round(up_min, 2),
            "upload_max_ms": round(up_max, 2),
            "upload_jitter_ms": round(up_jitter, 2),
            "upload_delta_ms": round(up_delta, 2),
            "upload_mbps": final_up_mbps,
            # Deltas & Counts
            "worst_delta_ms": round(worst_delta, 2),
            "peak_delta_ms": round(peak_delta, 2),
            "unloaded_count": len(unloaded_rtts),
            "download_count": len(download_rtts),
            "upload_count": len(upload_rtts),
            "unloaded_rtts": unloaded_rtts,
            "download_rtts": download_rtts,
            "upload_rtts": upload_rtts,
            # Backward-compat keys
            "loaded_avg_ms": round(max(dl_avg, up_avg), 2),
            "loaded_min_ms": round(min(dl_min, up_min), 2),
            "loaded_max_ms": round(max(dl_max, up_max), 2),
            "loaded_jitter_ms": round(max(dl_jitter, up_jitter), 2),
            "delta_ms": round(worst_delta, 2),
            "loaded_count": len(download_rtts) + len(upload_rtts),
        }

    def _build_empty_result(self, base_avg: float) -> Dict[str, Any]:
        return {
            "grade": "N/A",
            "description": "Test was interrupted by user.",
            "recommendation": "Run test again without cancelling.",
            "culprit": "NONE",
            "culprit_text": "Test cancelled.",
            "unloaded_avg_ms": round(base_avg, 2),
            "unloaded_min_ms": round(base_avg, 2),
            "unloaded_max_ms": round(base_avg, 2),
            "unloaded_jitter_ms": 0.0,
            "download_avg_ms": round(base_avg, 2),
            "download_min_ms": round(base_avg, 2),
            "download_max_ms": round(base_avg, 2),
            "download_jitter_ms": 0.0,
            "download_delta_ms": 0.0,
            "download_mbps": 0.0,
            "upload_avg_ms": round(base_avg, 2),
            "upload_min_ms": round(base_avg, 2),
            "upload_max_ms": round(base_avg, 2),
            "upload_jitter_ms": 0.0,
            "upload_delta_ms": 0.0,
            "upload_mbps": 0.0,
            "worst_delta_ms": 0.0,
            "peak_delta_ms": 0.0,
            "unloaded_count": 0,
            "download_count": 0,
            "upload_count": 0,
            "unloaded_rtts": [],
            "download_rtts": [],
            "upload_rtts": [],
            "loaded_avg_ms": round(base_avg, 2),
            "loaded_min_ms": round(base_avg, 2),
            "loaded_max_ms": round(base_avg, 2),
            "loaded_jitter_ms": 0.0,
            "delta_ms": 0.0,
            "loaded_count": 0,
        }
