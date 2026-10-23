"""
Report Generator for Network Diagnostics.
Generates human-readable summaries, structured JSON,
copy-pasteable ISP support ticket templates, and manages
custom user-named test runs in the results/ directory.
"""

import os
import re
import json
import time
from typing import Dict, Any, List, Optional


class DiagnosticReporter:
    """Formats, exports, and manages network diagnostic results."""

    @staticmethod
    def sanitize_filename(name: str) -> str:
        """Strip invalid characters for Windows filesystem."""
        s = re.sub(r'[\\/*?:"<>|]', "", name.strip())
        return re.sub(r"\s+", "_", s) or "unnamed_test"

    @classmethod
    def generate_text_report(
        cls,
        target: str,
        stream_stats: Dict[str, Any],
        hops: List[Dict[str, Any]],
        diagnosis_dict: Dict[str, Any],
        gateway_ip: str = "Unknown",
        custom_name: str = "Standard Test",
        protocol: str = "ICMP",
        real_server_ip: Optional[str] = None,
    ) -> str:
        t_str = time.strftime("%Y-%m-%d %H:%M:%S")
        target_line = f"Target Server : {target} (Protocol: {protocol})"
        if real_server_ip and real_server_ip != target and real_server_ip != "-":
            target_line += f"\nReal Match IP : {real_server_ip} (Match Server Host)"
        lines = [
            "=" * 74,
            "               PING TESTER & GAMING NETWORK DIAGNOSTIC REPORT",
            "=" * 74,
            f"Test Name     : {custom_name}",
            f"Timestamp     : {t_str}",
            target_line,
            f"Local Gateway : {gateway_ip}",
            "-" * 74,
            "1. OVERALL QUALITY VERDICT",
            "-" * 74,
            f"Grade         : {diagnosis_dict.get('grade', 'N/A')}",
            f"Verdict       : {diagnosis_dict.get('verdict_title', 'N/A')}",
            f"Summary       : {diagnosis_dict.get('verdict_summary', 'N/A')}",
            "",
            "Zone Breakdown:",
        ]

        for z_name, z_info in diagnosis_dict.get("zone_statuses", {}).items():
            lines.append(f"  * {z_name:<28}: [{z_info.get('status', 'N/A')}] {z_info.get('detail', '')}")

        lines.extend([
            "",
            "-" * 74,
            "2. PACKET TIMING & JITTER METRICS",
            "-" * 74,
            f"Packets Sent        : {stream_stats.get('sent', 0)}",
            f"Packets Received    : {stream_stats.get('received', 0)}",
            f"Packet Loss         : {stream_stats.get('lost', 0)} ({stream_stats.get('loss_pct', 0.0)}%)",
            f"Late Packets        : {stream_stats.get('late_count', 0)} ({stream_stats.get('late_pct', 0.0)}% > {stream_stats.get('late_threshold_ms', 0)}ms)",
            "",
            f"Latency (Min/Avg/Max): {stream_stats.get('min_rtt', 0.0)} ms / {stream_stats.get('avg_rtt', 0.0)} ms / {stream_stats.get('max_rtt', 0.0)} ms",
        ])
        if real_server_ip and real_server_ip != "-":
            avg_val = stream_stats.get('avg_rtt', 0.0)
            lines.append(f"In-Game Expected Latency: ~{avg_val + 16.6:.1f} ms (Physical Route {avg_val:.1f}ms + 16.6ms Apex 60Hz tick buffer)")
        lines.extend([
            f"Percentiles         : Median(p50)={stream_stats.get('median_rtt', 0.0)}ms | p95={stream_stats.get('p95_rtt', 0.0)}ms | p99={stream_stats.get('p99_rtt', 0.0)}ms",
            f"Mean Jitter (Timing): {stream_stats.get('mean_jitter', 0.0)} ms",
            f"RFC 3550 RTP Jitter : {stream_stats.get('rfc_jitter', 0.0)} ms",
            f"Standard Deviation  : {stream_stats.get('std_dev', 0.0)} ms",
        ])

        # 3. Competitive Gaming Impact (Hitreg & Desync)
        comp = diagnosis_dict.get("competitive_impact", {})
        if not comp:
            try:
                from core.zone_analyzer import ZoneAnalyzer
                comp = ZoneAnalyzer.compute_competitive_impact(stream_stats)
            except Exception:
                comp = {}

        if comp:
            lines.extend([
                "",
                "-" * 74,
                "3. COMPETITIVE GAMING IMPACT (HIT-REG & DESYNC ANALYSIS)",
                "-" * 74,
                f"Hit-Registration Risk : [{comp.get('hitreg_risk', 'UNKNOWN')}]",
                f"  * {comp.get('hitreg_detail', '')}",
                f"Cover Desync Window   : [{comp.get('desync_risk', 'UNKNOWN')}] (+{comp.get('desync_delta_ms', 0.0)}ms Max Delta)",
                f"  * {comp.get('desync_detail', '')}",
                f"Action-to-Server Delay: ~{comp.get('action_delay_ms', 0.0)} ms ({comp.get('action_delay_tier', '')})",
                f"  * {comp.get('action_delay_detail', '')}",
                f"Spike / Jitter Rate   : {comp.get('spike_frequency', '')}",
            ])

        lines.extend([
            "",
            "-" * 74,
            "4. ROUTE HOPS & LATENCY VARIANCE",
            "-" * 74,
            f"{'Hop':<4} {'IP Address':<18} {'Avg RTT':<10} {'Jitter':<10} {'Loss%':<8} {'Hostname'}",
            "-" * 74,
        ])

        for h in hops:
            avg_str = f"{h.get('avg_rtt', '-')} ms" if h.get("avg_rtt") is not None else "*"
            jit_str = f"{h.get('jitter', 0.0)} ms" if h.get("jitter") is not None else "-"
            loss_str = f"{h.get('loss_pct', 0.0)}%"
            lines.append(
                f"{h.get('hop', 0):<4} {h.get('ip', '*'):<18} {avg_str:<10} {jit_str:<10} {loss_str:<8} {h.get('hostname', '')[:25]}"
            )

        lines.extend([
            "",
            "-" * 74,
            "5. ACTIONABLE RECOMMENDATIONS",
            "-" * 74,
        ])
        for rec in diagnosis_dict.get("recommendations", []):
            lines.append(f"  [+] {rec}")

        lines.extend([
            "",
            "=" * 74,
            "                  END OF NETWORK DIAGNOSTIC REPORT",
            "=" * 74,
        ])

        return "\n".join(lines)

    @staticmethod
    def generate_isp_ticket_template(
        target: str,
        stream_stats: Dict[str, Any],
        hops: List[Dict[str, Any]],
        diagnosis_dict: Dict[str, Any],
    ) -> str:
        """Generates a concise, technical ISP complaint description."""
        lines = [
            "ISSUE DESCRIPTION: High Network Jitter & Regional Queue Delays on Real-Time Gaming Traffic",
            f"Target Destination: {target}",
            f"Packet Loss: {stream_stats.get('loss_pct', 0.0)}% | Late Packets: {stream_stats.get('late_pct', 0.0)}%",
            f"Latency Variance: Min {stream_stats.get('min_rtt', 0.0)}ms / Avg {stream_stats.get('avg_rtt', 0.0)}ms / Max {stream_stats.get('max_rtt', 0.0)}ms",
            f"Mean Jitter: {stream_stats.get('mean_jitter', 0.0)}ms (95th Percentile: {stream_stats.get('p95_rtt', 0.0)}ms)",
            "",
            "DIAGNOSTIC FINDING:",
            f"Fault Domain: {diagnosis_dict.get('verdict_title', 'Regional ISP Peering')}",
            f"Details: {diagnosis_dict.get('verdict_summary', '')}",
            "",
            "ROUTE TRACE SNAPSHOT:",
        ]
        for h in hops[:10]:
            avg_str = f"{h.get('avg_rtt', '-')}ms" if h.get("avg_rtt") is not None else "*"
            jit_str = f"Jitter={h.get('jitter', 0.0)}ms"
            lines.append(f"Hop {h.get('hop')}: {h.get('ip')} - RTT: {avg_str} ({jit_str}) - {h.get('hostname', '')}")

        lines.append("\nPlease review regional aggregation routing and gateway line profile.")
        return "\n".join(lines)

    @classmethod
    def save_custom_result(
        cls,
        results_dir: str,
        custom_name: str,
        target: str,
        stream_stats: Dict[str, Any],
        hops: List[Dict[str, Any]],
        diagnosis_dict: Dict[str, Any],
        gateway_ip: str = "Unknown",
        protocol: str = "ICMP",
        real_server_ip: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Saves user-named test results inside the results/ folder.
        Stores both a readable .txt report and a structured .json file
        with full timestamps for historical comparison.
        """
        os.makedirs(results_dir, exist_ok=True)
        timestamp_slug = time.strftime("%Y-%m-%d_%H-%M-%S")
        date_readable = time.strftime("%Y-%m-%d %H:%M:%S")
        clean_name = cls.sanitize_filename(custom_name)

        base_filename = f"{timestamp_slug}_{clean_name}"
        txt_path = os.path.join(results_dir, f"{base_filename}.txt")
        json_path = os.path.join(results_dir, f"{base_filename}.json")

        # 1. Save Human-Readable Text Report
        report_text = cls.generate_text_report(
            target=target,
            stream_stats=stream_stats,
            hops=hops,
            diagnosis_dict=diagnosis_dict,
            gateway_ip=gateway_ip,
            custom_name=custom_name,
            protocol=protocol,
            real_server_ip=real_server_ip,
        )
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(report_text)

        # 2. Save Machine-Readable JSON for Comparison
        payload = {
            "custom_name": custom_name,
            "created_at": date_readable,
            "timestamp": time.time(),
            "target": target,
            "real_server_ip": real_server_ip,
            "protocol": protocol,
            "gateway_ip": gateway_ip,
            "stream_stats": stream_stats,
            "hops": hops,
            "diagnosis": diagnosis_dict,
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        return {"txt_path": txt_path, "json_path": json_path, "filename": base_filename}

    @staticmethod
    def list_saved_results(results_dir: str) -> List[Dict[str, Any]]:
        """List all saved results in chronological order."""
        if not os.path.exists(results_dir):
            return []

        entries = []
        for fname in os.listdir(results_dir):
            if fname.endswith(".json"):
                fpath = os.path.join(results_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        data["filepath"] = fpath
                        entries.append(data)
                except Exception:
                    pass

        # Sort newest first
        entries.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        return entries

    @staticmethod
    def append_target_history(
        results_dir: str,
        ip: str,
        port: Any = None,
        real_ip: Optional[str] = None,
        label: Optional[str] = None,
    ) -> None:
        """
        Record tested target IP, real server IP, and port with timestamp into target_history.json.
        Avoids spamming identical entries if triggered repeatedly in a short window.
        """
        if not ip:
            return

        ip_clean = str(ip).strip()
        port_clean = str(port).strip() if port not in (None, 0, "", "None", "N/A") else "-"
        real_clean = str(real_ip).strip() if real_ip not in (None, "", "None", "N/A") else "-"
        if not label:
            label_clean = "Apex Match (Edge Gateway)" if real_clean not in ("-", ip_clean) else "Direct Target"
        else:
            label_clean = str(label).strip()

        os.makedirs(results_dir, exist_ok=True)
        hist_path = os.path.join(results_dir, "target_history.json")
        entries = []
        if os.path.exists(hist_path):
            try:
                with open(hist_path, "r", encoding="utf-8") as f:
                    entries = json.load(f)
            except Exception:
                entries = []

        now = time.time()
        t_str = time.strftime("%Y-%m-%d %H:%M:%S")

        # Deduplication check: if latest entry has same tested_ip, real_ip, and port within 15 seconds, just update timestamp
        if entries:
            last = entries[0]
            last_tested = last.get("tested_ip") or last.get("ip")
            last_real = last.get("real_ip", "-")
            last_port = str(last.get("port", "-"))
            if last_tested == ip_clean and last_real == real_clean and last_port == port_clean:
                if now - last.get("timestamp", 0) < 15:
                    last["timestamp"] = now
                    last["date_time"] = t_str
                    try:
                        with open(hist_path, "w", encoding="utf-8") as f:
                            json.dump(entries, f, indent=2)
                    except Exception:
                        pass
                    return

        new_entry = {
            "date_time": t_str,
            "ip": ip_clean,
            "tested_ip": ip_clean,
            "real_ip": real_clean,
            "port": port_clean,
            "label": label_clean,
            "timestamp": now,
        }
        # Insert newest at top
        entries.insert(0, new_entry)
        entries = entries[:500]

        try:
            with open(hist_path, "w", encoding="utf-8") as f:
                json.dump(entries, f, indent=2)
        except Exception:
            pass

    @staticmethod
    def get_target_history(results_dir: str) -> List[Dict[str, Any]]:
        """Retrieve target IP history sorted newest first with backward compatibility."""
        hist_path = os.path.join(results_dir, "target_history.json")
        if not os.path.exists(hist_path):
            return []
        try:
            with open(hist_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                normalized = []
                for entry in data:
                    t_ip = entry.get("tested_ip") or entry.get("ip", "-")
                    r_ip = entry.get("real_ip") or "-"
                    label = entry.get("label") or ("Apex Match (Edge Gateway)" if r_ip not in ("-", t_ip) else "Direct Target")
                    normalized.append({
                        "date_time": entry.get("date_time", "-"),
                        "ip": t_ip,
                        "tested_ip": t_ip,
                        "real_ip": r_ip,
                        "port": str(entry.get("port", "-")),
                        "label": label,
                        "timestamp": entry.get("timestamp", 0),
                    })
                return sorted(normalized, key=lambda x: x.get("timestamp", 0), reverse=True)
        except Exception:
            return []

    @staticmethod
    def clear_target_history(results_dir: str) -> None:
        """Clear target history log."""
        hist_path = os.path.join(results_dir, "target_history.json")
        if os.path.exists(hist_path):
            try:
                os.remove(hist_path)
            except Exception:
                pass

    @classmethod
    def compare_tests(cls, test_a: Dict[str, Any], test_b: Dict[str, Any]) -> Dict[str, Any]:
        """
        Algorithmic comparison engine between two test runs.
        Analyzes latency deltas, jitter variance, spike mitigation, and hitreg impact.
        Returns detailed side-by-side metrics, score differentials, and an actionable verdict.
        """
        stats_a = test_a.get("stream_stats", {})
        stats_b = test_b.get("stream_stats", {})
        diag_a = test_a.get("diagnosis", {})
        diag_b = test_b.get("diagnosis", {})

        name_a = test_a.get("custom_name", "Test A")
        name_b = test_b.get("custom_name", "Test B")
        target_a = test_a.get("target", "Unknown")
        target_b = test_b.get("target", "Unknown")

        # 1. Latency Metrics
        avg_a = float(stats_a.get("avg_rtt", 0.0))
        avg_b = float(stats_b.get("avg_rtt", 0.0))
        avg_diff = round(avg_b - avg_a, 2)
        avg_pct = round(((avg_b - avg_a) / avg_a * 100.0) if avg_a > 0 else 0.0, 1)

        min_a = float(stats_a.get("min_rtt", 0.0))
        min_b = float(stats_b.get("min_rtt", 0.0))
        min_diff = round(min_b - min_a, 2)

        max_a = float(stats_a.get("max_rtt", 0.0))
        max_b = float(stats_b.get("max_rtt", 0.0))
        max_diff = round(max_b - max_a, 2)

        # 2. Stability & Jitter
        jit_a = float(stats_a.get("mean_jitter", 0.0))
        jit_b = float(stats_b.get("mean_jitter", 0.0))
        jit_diff = round(jit_b - jit_a, 2)
        jit_pct = round(((jit_b - jit_a) / jit_a * 100.0) if jit_a > 0 else 0.0, 1)

        std_a = float(stats_a.get("std_dev", 0.0))
        std_b = float(stats_b.get("std_dev", 0.0))
        std_diff = round(std_b - std_a, 2)

        # 3. Packet Delivery & Spikes
        late_cnt_a = int(stats_a.get("late_count", 0))
        late_cnt_b = int(stats_b.get("late_count", 0))
        late_pct_a = float(stats_a.get("late_pct", 0.0))
        late_pct_b = float(stats_b.get("late_pct", 0.0))
        late_pct_diff = round(late_pct_b - late_pct_a, 2)

        loss_a = float(stats_a.get("loss_pct", 0.0))
        loss_b = float(stats_b.get("loss_pct", 0.0))
        loss_diff = round(loss_b - loss_a, 2)

        # 4. Algorithmic Competitive Scoring
        score_a = 0
        score_b = 0
        highlights = []

        # Average latency weight
        if avg_diff < -1.5:
            score_b += 3
            highlights.append(f"• Latency: {name_b} is {abs(avg_diff)}ms faster ({abs(avg_pct)}% lower input delay).")
        elif avg_diff > 1.5:
            score_a += 3
            highlights.append(f"• Latency: {name_a} is {avg_diff}ms faster ({avg_pct}% lower input delay).")

        # Jitter weight
        if jit_diff < -0.6:
            score_b += 4
            highlights.append(f"• Jitter: {name_b} has {abs(jit_diff)}ms lower jitter ({abs(jit_pct)}% calmer frame timing).")
        elif jit_diff > 0.6:
            score_a += 4
            highlights.append(f"• Jitter: {name_a} has {jit_diff}ms lower jitter ({jit_pct}% calmer frame timing).")

        # Late packet weight (critical for hitreg)
        if late_pct_diff < -0.2:
            score_b += 4
            highlights.append(f"• Hitreg: {name_b} reduced late-arrival spikes by {abs(late_pct_diff)}% (fewer ghost bullets).")
        elif late_pct_diff > 0.2:
            score_a += 4
            highlights.append(f"• Hitreg: {name_a} has {late_pct_diff}% fewer late spikes (fewer ghost bullets).")

        # Peak spike delta weight (critical for cover desync)
        if max_diff < -15.0:
            score_b += 3
            highlights.append(f"• Desync: {name_b} reduced maximum spike by {abs(max_diff)}ms (reduced dying behind cover).")
        elif max_diff > 15.0:
            score_a += 3
            highlights.append(f"• Desync: {name_a} has {max_diff}ms lower peak spike (reduced dying behind cover).")

        # Packet loss weight
        if loss_diff < -0.1:
            score_b += 5
            highlights.append(f"• Packet Loss: {name_b} eliminated {abs(loss_diff)}% loss.")
        elif loss_diff > 0.1:
            score_a += 5
            highlights.append(f"• Packet Loss: {name_a} has {loss_diff}% less packet loss.")

        # Verdict
        if score_b > score_a:
            winner = name_b
            verdict_badge = f"🏆 {name_b} is Superior"
            verdict_color = "#00d26a"
            summary_headline = f"{name_b} delivers a noticeably superior connection for competitive gaming."
        elif score_a > score_b:
            winner = name_a
            verdict_badge = f"🏆 {name_a} is Superior"
            verdict_color = "#0984e3"
            summary_headline = f"{name_a} delivers a noticeably superior connection for competitive gaming."
        else:
            winner = "Tie"
            verdict_badge = "⚖️ Equivalent Performance"
            verdict_color = "#fbc531"
            summary_headline = "Both tests exhibited virtually identical performance and stability."

        summary_text = summary_headline + "\n" + "\n".join(highlights) if highlights else summary_headline

        return {
            "name_a": name_a,
            "name_b": name_b,
            "target_a": target_a,
            "target_b": target_b,
            "winner": winner,
            "verdict_badge": verdict_badge,
            "verdict_color": verdict_color,
            "summary_headline": summary_headline,
            "summary_text": summary_text,
            "highlights": highlights,
            # Raw and diff metrics
            "avg_a": avg_a, "avg_b": avg_b, "avg_diff": avg_diff, "avg_pct": avg_pct,
            "min_a": min_a, "min_b": min_b, "min_diff": min_diff,
            "max_a": max_a, "max_b": max_b, "max_diff": max_diff,
            "jit_a": jit_a, "jit_b": jit_b, "jit_diff": jit_diff, "jit_pct": jit_pct,
            "std_a": std_a, "std_b": std_b, "std_diff": std_diff,
            "late_cnt_a": late_cnt_a, "late_cnt_b": late_cnt_b,
            "late_pct_a": late_pct_a, "late_pct_b": late_pct_b, "late_pct_diff": late_pct_diff,
            "loss_a": loss_a, "loss_b": loss_b, "loss_diff": loss_diff,
            "grade_a": diag_a.get("grade", "N/A"),
            "grade_b": diag_b.get("grade", "N/A"),
        }
