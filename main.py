"""
Application Entry Point for Ping Tester & Game Network Diagnostics.
Supports both modern CustomTkinter GUI and headless CLI execution.
"""

import sys
import argparse
import os
from typing import Optional, Dict, Any, List

# Portable base directory configuration
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.win32_icmp import Win32ICMPEngine
from core.ping_engine import StreamPingEngine
from core.route_tracer import RouteTracer
from core.zone_analyzer import ZoneAnalyzer
from core.reporter import DiagnosticReporter


def run_cli_diagnostic(target: str, count: Optional[int], rate: float, late_limit: float, duration: Optional[float] = None):
    print("=" * 65)
    print("  PING TESTER & GAMING NETWORK DIAGNOSTIC TOOL (CLI MODE)")
    print("=" * 65)
    
    icmp = Win32ICMPEngine()
    resolved = icmp.resolve_ip(target) or target
    gateway = icmp.get_default_gateway() or "Unknown"
    
    limit_desc = f"{int(duration)}s timer" if duration else f"{count} packets"
    print(f"Target Destination : {target} ({resolved})")
    print(f"Local Gateway      : {gateway}")
    print(f"Test Configuration : {limit_desc} @ {rate} Hz (Late threshold: >{late_limit}ms)")
    print("-" * 65)
    print("Phase 1: Streaming high-frequency ICMP probes...")

    engine = StreamPingEngine(icmp)
    last_stats = {}

    def on_p(p):
        rtt = p.get("rtt_ms")
        seq = p.get("seq", 0)
        late_flag = " [LATE!]" if p.get("is_late") else ""
        if p["success"]:
            print(f"  Seq #{seq:03d} | RTT: {rtt:6.1f} ms{late_flag}")
        else:
            print(f"  Seq #{seq:03d} | DROPPED / TIMED OUT")

    def on_s(s):
        nonlocal last_stats
        last_stats = s

    engine.start_stream(
        target_ip=resolved,
        packet_count=count if duration is None else None,
        duration_seconds=duration,
        tick_rate_hz=rate,
        late_threshold_ms=late_limit,
        on_packet=on_p,
        on_stats=on_s,
    )
    if engine._thread:
        engine._thread.join()

    print("\nPhase 2: Executing 3-Zone Route Trace...")
    tracer = RouteTracer(icmp)
    hops = []

    def on_h(h):
        hops.append(h)
        avg = f"{h['avg_rtt']}ms" if h["avg_rtt"] is not None else "*"
        print(f"  Hop {h['hop']:02d}: {h['ip']:<16} Avg: {avg:<8} Jitter: {h['jitter']}ms  {h['hostname'][:30]}")

    tracer.trace(resolved, max_hops=18, queries_per_hop=3, on_hop=on_h)
    if tracer._thread:
        tracer._thread.join()

    print("\nPhase 3: Synthesizing 3-Zone Diagnostics...")
    gw_res = icmp.ping(gateway, timeout_ms=500)
    gw_stats = {
        "avg_rtt": gw_res.get("rtt_ms", 0.0) if gw_res["success"] else 999.0,
        "mean_jitter": 0.5 if gw_res["success"] else 20.0,
        "loss_pct": 0.0 if gw_res["success"] else 100.0,
    }
    diag = ZoneAnalyzer.analyze(last_stats, hops, gateway_stats=gw_stats)

    report = DiagnosticReporter.generate_text_report(
        target=target,
        stream_stats=last_stats,
        hops=hops,
        diagnosis_dict=diag.to_dict(),
        gateway_ip=gateway,
    )
    print("\n" + report)

    # Save to results
    res_dir = os.path.join(BASE_DIR, "results")
    saved_info = DiagnosticReporter.save_custom_result(
        results_dir=res_dir,
        custom_name=f"CLI_Test_{target}",
        target=target,
        stream_stats=last_stats,
        hops=hops,
        diagnosis_dict=diag.to_dict(),
        gateway_ip=gateway,
        protocol="ICMP",
    )
    print(f"\n[+] Full report saved to: {saved_info['txt_path']}")


def main():
    parser = argparse.ArgumentParser(description="Ping Tester & Gaming Network Diagnostics")
    parser.add_argument("--cli", action="store_true", help="Run in command line interface mode")
    parser.add_argument("--target", type=str, default="103.10.124.116", help="Target IP or hostname")
    parser.add_argument("--count", type=int, default=50, help="Number of packets to send (if not using --duration)")
    parser.add_argument("--duration", type=float, default=None, help="Duration in seconds (e.g. 60 for 1 min, 120 for 2 min)")
    parser.add_argument("--rate", type=float, default=20.0, help="Tick rate in Hz (e.g. 20 for Apex, 60 for Valorant)")
    parser.add_argument("--late", type=float, default=130.0, help="Late packet threshold in ms")

    args = parser.parse_args()

    if args.cli:
        run_cli_diagnostic(args.target, args.count, args.rate, args.late, duration=args.duration)
    else:
        try:
            from ui.app import PingTesterApp
            app = PingTesterApp()
            app.mainloop()
        except ImportError as e:
            print(f"GUI Error: {e}. Falling back to CLI mode...")
            run_cli_diagnostic(args.target, args.count, args.rate, args.late, duration=args.duration)


if __name__ == "__main__":
    main()
