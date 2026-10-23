"""
3-Zone Diagnostic Engine for Gaming Networks.
Analyzes traceroute hops and stream ping metrics to isolate the exact fault domain:
- Zone 1: Local / Home Network (PC to Router)
- Zone 2: ISP Middle-Mile (Router to Regional Exchange / Gateway)
- Zone 3: Transit & Game Server Destination
"""

from typing import List, Dict, Any, Optional


class ZoneDiagnosis:
    """Contains diagnostic findings and actionable recommendations."""

    def __init__(self):
        self.primary_fault_zone: str = "NONE"  # LOCAL, ISP_MIDDLE_MILE, DESTINATION, or NONE
        self.grade: str = "A"                 # A+, A, B, C, D, F
        self.verdict_title: str = ""
        self.verdict_summary: str = ""
        self.recommendations: List[str] = []
        self.competitive_impact: Dict[str, Any] = {}
        self.zone_statuses: Dict[str, Dict[str, Any]] = {
            "Zone 1 (Home LAN)": {"status": "GOOD", "detail": ""},
            "Zone 2 (ISP Middle-Mile)": {"status": "GOOD", "detail": ""},
            "Zone 3 (Game / Destination)": {"status": "GOOD", "detail": ""},
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "primary_fault_zone": self.primary_fault_zone,
            "grade": self.grade,
            "verdict_title": self.verdict_title,
            "verdict_summary": self.verdict_summary,
            "recommendations": self.recommendations,
            "competitive_impact": self.competitive_impact,
            "zone_statuses": self.zone_statuses,
        }


class ZoneAnalyzer:
    """Analyzes stream statistics and hop data to identify root causes."""

    @classmethod
    def analyze(
        cls,
        stream_stats: Dict[str, Any],
        hops: List[Dict[str, Any]],
        gateway_stats: Optional[Dict[str, Any]] = None,
    ) -> ZoneDiagnosis:
        diag = ZoneDiagnosis()
        
        # 1. Evaluate overall stream metrics
        loss_pct = stream_stats.get("loss_pct", 0.0)
        mean_jitter = stream_stats.get("mean_jitter", 0.0)
        late_pct = stream_stats.get("late_pct", 0.0)
        min_rtt = stream_stats.get("min_rtt", 0.0)
        max_rtt = stream_stats.get("max_rtt", 0.0)
        late_threshold = stream_stats.get("late_threshold_ms", 130.0)

        # 2. Determine Letter Grade
        if loss_pct > 5.0 or mean_jitter > 45.0 or late_pct > 25.0:
            diag.grade = "F"
        elif loss_pct > 2.0 or mean_jitter > 25.0 or late_pct > 12.0:
            diag.grade = "D"
        elif loss_pct > 0.5 or mean_jitter > 12.0 or late_pct > 4.0:
            diag.grade = "C"
        elif mean_jitter > 5.0 or late_pct > 1.0:
            diag.grade = "B"
        elif mean_jitter <= 2.5 and loss_pct == 0.0 and late_pct == 0.0:
            diag.grade = "A+"
        else:
            diag.grade = "A"

        # 3. Analyze Zone 1: Home LAN / Local Router
        zone1_fault = False
        zone1_detail = "Local connection to router is clean (< 2ms, 0% loss)."
        if gateway_stats:
            gw_loss = gateway_stats.get("loss_pct", 0.0)
            gw_jitter = gateway_stats.get("mean_jitter", 0.0)
            gw_avg = gateway_stats.get("avg_rtt", 0.0)
            if gw_loss > 1.0 or gw_jitter > 6.0 or gw_avg > 10.0:
                zone1_fault = True
                zone1_detail = f"High latency/jitter to your router ({gw_avg}ms, jitter {gw_jitter}ms, loss {gw_loss}%)."
        elif hops and len(hops) > 0:
            hop1 = hops[0]
            if hop1.get("loss_pct", 0.0) > 10.0 or (hop1.get("avg_rtt") and hop1["avg_rtt"] > 10.0):
                zone1_fault = True
                zone1_detail = f"Hop 1 (Router {hop1.get('ip')}) has high RTT ({hop1.get('avg_rtt')}ms)."

        diag.zone_statuses["Zone 1 (Home LAN)"]["status"] = "DEGRADED" if zone1_fault else "EXCELLENT"
        diag.zone_statuses["Zone 1 (Home LAN)"]["detail"] = zone1_detail

        # 4. Analyze Zone 2: ISP Middle-Mile
        zone2_fault = False
        zone2_detail = "ISP domestic routing is stable."
        culprit_hop = None
        max_hop_jitter = 0.0

        # Look at intermediate hops (hops 2 to 8)
        for h in hops[1:8]:
            h_jitter = h.get("jitter", 0.0)
            h_avg = h.get("avg_rtt")
            if h_jitter > max_hop_jitter:
                max_hop_jitter = h_jitter
                culprit_hop = h

        # If overall jitter is high, or late packets exist, but Zone 1 is clean:
        if not zone1_fault and (mean_jitter > 12.0 or late_pct > 3.0 or max_hop_jitter > 20.0):
            zone2_fault = True
            if culprit_hop and culprit_hop.get("ip") != "*":
                zone2_detail = (
                    f"Congestion / Queuing detected at Hop {culprit_hop['hop']} ({culprit_hop['ip']}). "
                    f"Jitter spiked to {culprit_hop['jitter']}ms."
                )
            else:
                zone2_detail = (
                    f"ISP regional transit is queuing packets. "
                    f"Overall jitter is {mean_jitter}ms with {late_pct}% packets arriving after {late_threshold}ms."
                )

        diag.zone_statuses["Zone 2 (ISP Middle-Mile)"]["status"] = "CONGESTED" if zone2_fault else "GOOD"
        diag.zone_statuses["Zone 2 (ISP Middle-Mile)"]["detail"] = zone2_detail

        # 5. Analyze Zone 3: Transit / Game Server
        zone3_fault = False
        zone3_detail = "Target game server responding cleanly."
        if not zone1_fault and not zone2_fault:
            if loss_pct > 1.0 or mean_jitter > 15.0 or late_pct > 5.0:
                zone3_fault = True
                zone3_detail = (
                    f"Target server or international subsea line experiencing instability "
                    f"({loss_pct}% loss, {mean_jitter}ms jitter)."
                )

        diag.zone_statuses["Zone 3 (Game / Destination)"]["status"] = "UNSTABLE" if zone3_fault else "GOOD"
        diag.zone_statuses["Zone 3 (Game / Destination)"]["detail"] = zone3_detail

        # 6. Synthesize Final Verdict
        if zone1_fault:
            diag.primary_fault_zone = "LOCAL"
            diag.verdict_title = "Local Network Bottleneck (Home LAN / Wi-Fi)"
            diag.verdict_summary = (
                "The timing degradation originates inside your local network. "
                "Packets are delaying or dropping between your PC and your router."
            )
            diag.recommendations = [
                "Switch from Wi-Fi to a direct Cat6 Ethernet cable connection.",
                "Check for other devices on your home network downloading large updates (Bufferbloat).",
                "Restart your home optical router / GPON gateway.",
                "Enable SQM (Smart Queue Management) or QoS on your home router."
            ]
        elif zone2_fault:
            diag.primary_fault_zone = "ISP_MIDDLE_MILE"
            diag.verdict_title = "ISP Middle-Mile Congestion (Domestic Routing Queues)"
            diag.verdict_summary = (
                f"Your local setup is clean, but your ISP is suffering from regional queue delays. "
                f"{late_pct}% of packets arrive late (>{late_threshold}ms) with {mean_jitter}ms average jitter. "
                "This causes micro-stutters and delayed hit-registration in competitive games."
            )
            diag.recommendations = [
                "Restart your router / ONT to attempt drawing a new WAN IP lease on a different BRAS gateway.",
                "Submit a ticket to your ISP with the exported trace report highlighting the congested hop.",
                "Consider routing through an optimized gaming network or alternative peering route to bypass residential ISP congestion."
            ]
        elif zone3_fault:
            diag.primary_fault_zone = "DESTINATION"
            diag.verdict_title = "International Transit / Game Server Issue"
            diag.verdict_summary = (
                "Your local line and domestic ISP routing are fine, but packets are fluctuating "
                "at the subsea cable landing or on the game server's host network."
            )
            diag.recommendations = [
                "Try playing on an alternative regional game server if available.",
                "Check game server status pages or cloud provider outages (AWS/Azure/GCP).",
                "Contact the game publisher support with the destination IP and latency log."
            ]
        else:
            diag.primary_fault_zone = "NONE"
            diag.verdict_title = "Optimal Network Quality"
            diag.verdict_summary = (
                f"No packet timing anomalies detected. Mean jitter is {mean_jitter}ms, "
                f"packet loss is {loss_pct}%, and {100.0 - late_pct:.1f}% of packets arrived within target thresholds."
            )
            diag.recommendations = [
                "Your connection is operating at peak performance for real-time multiplayer gaming."
            ]

        # 7. Calculate Competitive Gaming Impact (Hitreg, Desync, Input Lag)
        diag.competitive_impact = cls.compute_competitive_impact(stream_stats)

        return diag

    @classmethod
    def compute_competitive_impact(cls, stream_stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translates raw network metrics into competitive FPS gameplay reality:
        - Hit registration & rollback desync (No-regs)
        - Desync window ("Dying behind doors / cover")
        - Action-to-server latency (Peeker's advantage)
        - Micro-stutter / spike occurrence rate
        """
        loss_pct = float(stream_stats.get("loss_pct", 0.0))
        late_count = int(stream_stats.get("late_count", 0))
        late_pct = float(stream_stats.get("late_pct", 0.0))
        late_thresh = float(stream_stats.get("late_threshold_ms", 130.0))
        min_rtt = float(stream_stats.get("min_rtt", 0.0))
        avg_rtt = float(stream_stats.get("avg_rtt", 0.0))
        max_rtt = float(stream_stats.get("max_rtt", 0.0))
        mean_jitter = float(stream_stats.get("mean_jitter", 0.0))
        elapsed_sec = float(stream_stats.get("elapsed_sec") or stream_stats.get("duration_seconds") or 60.0)

        # 1. Hit-Registration & No-Reg Risk
        if loss_pct > 1.0 or late_pct > 4.0:
            hitreg_risk = "HIGH RISK"
            hitreg_badge = "🔴 Unstable Hit-Reg"
            hitreg_detail = (
                f"{loss_pct:.1f}% packet loss and {late_pct:.1f}% late packets (>{late_thresh}ms). "
                "Server-side lag compensation will frequently drop hit-verification ticks, causing ghost bullets."
            )
        elif late_count > 0 or mean_jitter > 5.0:
            hitreg_risk = "MODERATE RISK"
            hitreg_badge = "🟡 Occasional No-Regs"
            hitreg_detail = (
                f"{late_count} packet(s) exceeded server rewind threshold (>{late_thresh}ms). "
                "Shots fired during sudden timing spikes may fail to register damage."
            )
        else:
            hitreg_risk = "MINIMAL RISK"
            hitreg_badge = "🟢 Crisp Hit-Reg"
            hitreg_detail = (
                "0% packet loss and 0 late packets. Bullet trajectories and damage ticks register cleanly."
            )

        # 2. Cover Desync Window ("Dying Behind Doors / Walls")
        spike_delta = max(0.0, max_rtt - min_rtt)
        if spike_delta > 45.0 or mean_jitter > 8.0:
            desync_risk = "HIGH VULNERABILITY"
            desync_badge = "🔴 High Desync Window"
            desync_detail = (
                f"+{spike_delta:.1f}ms spike window (Max {max_rtt:.1f}ms vs Min {min_rtt:.1f}ms). "
                "Peak jitter creates a lag window where opponents can shoot or knock you after you duck behind cover."
            )
        elif spike_delta > 20.0 or mean_jitter > 3.5:
            desync_risk = "MODERATE VULNERABILITY"
            desync_badge = "🟡 Minor Desync Window"
            desync_detail = (
                f"+{spike_delta:.1f}ms spike window. Slight position delay during rapid sliding or door-closing."
            )
        else:
            desync_risk = "MINIMAL"
            desync_badge = "🟢 Tight Sync"
            desync_detail = (
                f"+{spike_delta:.1f}ms variance. Client and server character hitboxes remain tightly synchronized."
            )

        # 3. Action-to-Server Delay (Apex 60Hz tick buffer)
        action_delay = avg_rtt + 16.6
        if action_delay < 50.0:
            tier_name = "Tournament Tier (<50ms)"
            tier_badge = "🟢 Instant Peeks"
            tier_detail = "Immediate responsiveness. You hold strong peeker's advantage in aggressive 1v1s."
        elif action_delay < 90.0:
            tier_name = "Competitive Tier (<90ms)"
            tier_badge = "🟢 Fast Peeks"
            tier_detail = "Standard competitive feel. Fast reactions and movement tech execute reliably."
        elif action_delay < 120.0:
            tier_name = f"Moderate Delay (~{action_delay:.0f}ms)"
            tier_badge = "🟡 Moderate Delay"
            tier_detail = (
                f"~{action_delay:.0f}ms action delay ({avg_rtt:.1f}ms ping + 16.6ms tick). "
                "Opponents on sub-40ms ping hold slight peeker's advantage; pre-aiming corners recommended."
            )
        else:
            tier_name = f"Heavy Delay (~{action_delay:.0f}ms)"
            tier_badge = "🔴 Heavy Delay"
            tier_detail = "Must pre-fire aggressively and avoid holding static defensive angles."

        # 4. Spike Frequency
        if late_count > 0 and elapsed_sec > 0:
            interval = round(elapsed_sec / max(1, late_count), 1)
            spike_freq = f"1 late-arrival spike every ~{interval}s of gameplay."
        else:
            spike_freq = "Zero late-arrival spikes detected across entire test session."

        return {
            "hitreg_risk": hitreg_risk,
            "hitreg_badge": hitreg_badge,
            "hitreg_detail": hitreg_detail,
            "desync_risk": desync_risk,
            "desync_badge": desync_badge,
            "desync_delta_ms": round(spike_delta, 1),
            "desync_detail": desync_detail,
            "action_delay_ms": round(action_delay, 1),
            "action_delay_tier": tier_name,
            "action_delay_badge": tier_badge,
            "action_delay_detail": tier_detail,
            "spike_frequency": spike_freq,
        }
