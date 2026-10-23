"""
3-Zone Diagnostic View & Route Hop Tree Component.
Visually isolates whether network issues stem from Home LAN, ISP Middle-Mile, or Game Server.
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk
from typing import List, Dict, Any


class ZonePill(ctk.CTkFrame):
    """Visual status card for a single network zone."""

    def __init__(self, master, zone_name: str, zone_desc: str, **kwargs):
        super().__init__(master, fg_color="#1e222d", corner_radius=8, **kwargs)

        self.lbl_title = ctk.CTkLabel(
            self,
            text=zone_name,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color="#ffffff",
        )
        self.lbl_title.pack(anchor="w", padx=12, pady=(8, 2))

        self.lbl_status = ctk.CTkLabel(
            self,
            text="PENDING",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color="#8c9ba5",
        )
        self.lbl_status.pack(anchor="w", padx=12, pady=(0, 2))

        self.lbl_desc = ctk.CTkLabel(
            self,
            text=zone_desc,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color="#637282",
            wraplength=260,
            justify="left",
        )
        self.lbl_desc.pack(anchor="w", padx=12, pady=(0, 8))

    def set_status(self, status: str, detail: str = ""):
        colors = {
            "EXCELLENT": "#00d26a",
            "GOOD": "#4cd137",
            "CONGESTED": "#fbc531",
            "DEGRADED": "#e17055",
            "UNSTABLE": "#e84118",
            "PENDING": "#8c9ba5",
        }
        c = colors.get(status, "#ffffff")
        self.lbl_status.configure(text=status, text_color=c)
        if detail:
            self.lbl_desc.configure(text=detail)


class ZoneDiagnosisView(ctk.CTkFrame):
    """Full 3-zone visual layout with route hop breakdown table."""

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        # 1. Fault Banner
        self.banner = ctk.CTkFrame(self, fg_color="#242b35", corner_radius=8)
        self.banner.pack(fill="x", padx=5, pady=(0, 8))

        self.lbl_banner_title = ctk.CTkLabel(
            self.banner,
            text="DIAGNOSTIC STATUS: READY",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color="#00d26a",
        )
        self.lbl_banner_title.pack(anchor="w", padx=14, pady=(8, 2))

        self.lbl_banner_desc = ctk.CTkLabel(
            self.banner,
            text="Run a 3-Zone Route Trace or Stream Test to isolate your packet timing bottlenecks.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#b2bec3",
            wraplength=850,
            justify="left",
        )
        self.lbl_banner_desc.pack(anchor="w", padx=14, pady=(0, 8))

        # 2. Zone Pills Row
        self.pills_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.pills_frame.pack(fill="x", padx=5, pady=(0, 8))
        self.pills_frame.grid_columnconfigure((0, 1, 2), weight=1, uniform="zone_pills")

        self.pill_z1 = ZonePill(
            self.pills_frame,
            zone_name="Zone 1: Home LAN / Router",
            zone_desc="PC to local router (Ethernet / Wi-Fi stability)",
        )
        self.pill_z1.grid(row=0, column=0, padx=4, sticky="nsew")

        self.pill_z2 = ZonePill(
            self.pills_frame,
            zone_name="Zone 2: ISP Middle-Mile",
            zone_desc="Router to domestic regional exchanges / core gateways",
        )
        self.pill_z2.grid(row=0, column=1, padx=4, sticky="nsew")

        self.pill_z3 = ZonePill(
            self.pills_frame,
            zone_name="Zone 3: Destination & Game Cloud",
            zone_desc="International subsea cables & target game servers",
        )
        self.pill_z3.grid(row=0, column=2, padx=4, sticky="nsew")

        # 3. Route Hop Table (Treeview)
        table_container = ctk.CTkFrame(self, fg_color="#181a20", corner_radius=8)
        table_container.pack(fill="both", expand=True, padx=5, pady=0)

        # Style Treeview
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background="#181a20",
            foreground="#dcdde1",
            fieldbackground="#181a20",
            rowheight=24,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview.Heading",
            background="#21252d",
            foreground="#7f8c8d",
            font=("Segoe UI", 9, "bold"),
            borderwidth=0,
        )
        style.map("Treeview", background=[("selected", "#2f3640")])

        columns = ("hop", "ip", "avg", "jitter", "loss", "zone", "host")
        self.tree = ttk.Treeview(table_container, columns=columns, show="headings", height=7)

        self.tree.heading("hop", text="Hop", anchor="center")
        self.tree.heading("ip", text="IP Address", anchor="w")
        self.tree.heading("avg", text="Avg RTT", anchor="center")
        self.tree.heading("jitter", text="Jitter", anchor="center")
        self.tree.heading("loss", text="Loss %", anchor="center")
        self.tree.heading("zone", text="Network Zone", anchor="center")
        self.tree.heading("host", text="Hostname / Node Details", anchor="w")

        self.tree.column("hop", width=45, minwidth=40, anchor="center")
        self.tree.column("ip", width=140, minwidth=110, anchor="w")
        self.tree.column("avg", width=80, minwidth=60, anchor="center")
        self.tree.column("jitter", width=80, minwidth=60, anchor="center")
        self.tree.column("loss", width=70, minwidth=50, anchor="center")
        self.tree.column("zone", width=130, minwidth=100, anchor="center")
        self.tree.column("host", width=280, minwidth=180, anchor="w")

        scrollbar = ttk.Scrollbar(table_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        scrollbar.pack(side="right", fill="y", padx=2, pady=2)

    def update_diagnosis(self, diag_dict: Dict[str, Any]):
        title = diag_dict.get("verdict_title", "Network Analysis Complete")
        summary = diag_dict.get("verdict_summary", "")
        fault = diag_dict.get("primary_fault_zone", "NONE")

        colors = {
            "NONE": "#00d26a",
            "LOCAL": "#e17055",
            "ISP_MIDDLE_MILE": "#fbc531",
            "DESTINATION": "#e84118",
        }
        self.lbl_banner_title.configure(text=f"VERDICT: {title.upper()}", text_color=colors.get(fault, "#ffffff"))
        self.lbl_banner_desc.configure(text=summary)

        z_statuses = diag_dict.get("zone_statuses", {})
        if "Zone 1 (Home LAN)" in z_statuses:
            z1 = z_statuses["Zone 1 (Home LAN)"]
            self.pill_z1.set_status(z1.get("status", "GOOD"), z1.get("detail", ""))
        if "Zone 2 (ISP Middle-Mile)" in z_statuses:
            z2 = z_statuses["Zone 2 (ISP Middle-Mile)"]
            self.pill_z2.set_status(z2.get("status", "GOOD"), z2.get("detail", ""))
        if "Zone 3 (Game / Destination)" in z_statuses:
            z3 = z_statuses["Zone 3 (Game / Destination)"]
            self.pill_z3.set_status(z3.get("status", "GOOD"), z3.get("detail", ""))

    def clear_hops(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def add_hop(self, hop_data: Dict[str, Any]):
        hop_num = hop_data.get("hop", 0)
        ip = hop_data.get("ip", "*")
        avg = f"{hop_data.get('avg_rtt')} ms" if hop_data.get("avg_rtt") is not None else "*"
        jit = f"{hop_data.get('jitter', 0.0)} ms" if hop_data.get("jitter") is not None else "-"
        loss = f"{hop_data.get('loss_pct', 0.0)}%"
        host = hop_data.get("hostname", "")

        # Zone tag
        if hop_num == 1:
            zone_tag = "Zone 1 (Home LAN)"
        elif hop_num <= 6 or hop_data.get("is_private"):
            zone_tag = "Zone 2 (ISP Core)"
        else:
            zone_tag = "Zone 3 (Transit/Dest)"

        self.tree.insert("", "end", values=(hop_num, ip, avg, jit, loss, zone_tag, host))
