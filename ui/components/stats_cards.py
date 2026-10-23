"""
Modern Metrics & Stat Cards for Network Diagnostics.
Displays live RTT, Jitter, Late Packet Counts, and Grade Badges using CustomTkinter.
"""

import customtkinter as ctk
from typing import Dict, Any


class MetricCard(ctk.CTkFrame):
    """Single stat display card."""

    def __init__(self, master, title: str, unit: str = "", **kwargs):
        super().__init__(master, fg_color="#1e222d", corner_radius=10, **kwargs)

        self.title_label = ctk.CTkLabel(
            self,
            text=title.upper(),
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#8c9ba5",
        )
        self.title_label.pack(anchor="w", padx=14, pady=(10, 2))

        self.val_label = ctk.CTkLabel(
            self,
            text="--",
            font=ctk.CTkFont(family="Segoe UI", size=24, weight="bold"),
            text_color="#ffffff",
        )
        self.val_label.pack(anchor="w", padx=14, pady=(0, 2))

        self.sub_label = ctk.CTkLabel(
            self,
            text=unit,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color="#637282",
        )
        self.sub_label.pack(anchor="w", padx=14, pady=(0, 10))

    def update_val(self, value_text: str, sub_text: str = "", color: str = "#ffffff"):
        self.val_label.configure(text=value_text, text_color=color)
        if sub_text:
            self.sub_label.configure(text=sub_text)


class StatsDashboard(ctk.CTkFrame):
    """Container for high-level diagnostic cards."""

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure((0, 1, 2, 3, 4), weight=1, uniform="stat_cards")

        # 1. Current / Avg Latency
        self.card_latency = MetricCard(self, title="Latency (Avg)", unit="Min: -- | Max: --")
        self.card_latency.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        # 2. Jitter
        self.card_jitter = MetricCard(self, title="Jitter (Variance)", unit="RFC 3550 RTP")
        self.card_jitter.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")

        # 3. Late Packets
        self.card_late = MetricCard(self, title="Late Packets", unit="Threshold: 130ms")
        self.card_late.grid(row=0, column=2, padx=5, pady=5, sticky="nsew")

        # 4. Packet Loss
        self.card_loss = MetricCard(self, title="Packet Loss", unit="0 lost / 0 sent")
        self.card_loss.grid(row=0, column=3, padx=5, pady=5, sticky="nsew")

        # 5. Gaming Grade
        self.card_grade = MetricCard(self, title="Gaming Grade", unit="Waiting for test...")
        self.card_grade.grid(row=0, column=4, padx=5, pady=5, sticky="nsew")

    def update_stats(self, stats: Dict[str, Any], current_rtt: float = None):
        # Latency card
        avg_rtt = stats.get("avg_rtt", 0.0)
        min_rtt = stats.get("min_rtt", 0.0)
        max_rtt = stats.get("max_rtt", 0.0)
        cur_display = f"{current_rtt:.1f} ms" if current_rtt is not None else f"{avg_rtt:.1f} ms"
        color_lat = "#00d26a" if avg_rtt < 60 else ("#fbc531" if avg_rtt < 130 else "#e84118")
        self.card_latency.update_val(cur_display, f"Min: {min_rtt:.1f} | Max: {max_rtt:.1f} ms", color=color_lat)

        # Jitter card
        mean_jitter = stats.get("mean_jitter", 0.0)
        rfc_jitter = stats.get("rfc_jitter", 0.0)
        color_jit = "#00d26a" if mean_jitter < 5 else ("#fbc531" if mean_jitter < 15 else "#e84118")
        self.card_jitter.update_val(f"{mean_jitter:.1f} ms", f"RFC: {rfc_jitter:.1f} ms | p95: {stats.get('p95_rtt', 0.0)}ms", color=color_jit)

        # Late Packets card
        late_pct = stats.get("late_pct", 0.0)
        late_count = stats.get("late_count", 0)
        late_thresh = stats.get("late_threshold_ms", 130.0)
        color_late = "#00d26a" if late_pct == 0 else ("#fbc531" if late_pct < 5 else "#e84118")
        self.card_late.update_val(f"{late_pct:.1f} %", f"{late_count} packets > {int(late_thresh)}ms", color=color_late)

        # Packet Loss card
        loss_pct = stats.get("loss_pct", 0.0)
        lost = stats.get("lost", 0)
        sent = stats.get("sent", 0)
        color_loss = "#00d26a" if loss_pct == 0 else ("#fbc531" if loss_pct < 2 else "#e84118")
        self.card_loss.update_val(f"{loss_pct:.1f} %", f"{lost} lost / {sent} sent", color=color_loss)

    def set_grade(self, grade: str, verdict_short: str):
        grade_colors = {
            "A+": "#00d26a",
            "A": "#00f078",
            "B": "#4cd137",
            "C": "#fbc531",
            "D": "#e17055",
            "F": "#e84118",
        }
        color = grade_colors.get(grade, "#ffffff")
        self.card_grade.update_val(grade, verdict_short, color=color)
