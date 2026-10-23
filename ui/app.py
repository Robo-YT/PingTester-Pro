"""
Main GUI Application Window for Ping Tester & Gaming Network Diagnostics.
Features:
- Streamlined Target Selector (Auto-Detect Apex, Google DNS, Cloudflare DNS, Custom)
- Dedicated Permanent Start & Stop Buttons
- Visible Duration / Packet Count Input Box on Toolbar
- Interactive In-App Saved Results Viewer (View full historical reports inside the software)
- Instant Post-Test Completion & Direct Save Dialog
- Auto-Detection of Live Apex Legends Servers & Match Sockets
- Dual ICMP & UDP Gaming Probing Engines
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
from typing import Dict, Any, List, Optional, Tuple

from core.win32_icmp import Win32ICMPEngine
from core.ping_engine import StreamPingEngine
from core.udp_engine import UDPEngine
from core.route_tracer import RouteTracer
from core.zone_analyzer import ZoneAnalyzer, ZoneDiagnosis
from core.bufferbloat import BufferbloatTester
from core.reporter import DiagnosticReporter
from core.apex_detector import ApexDetector
from core.passive_sniffer import PassiveNetcodeSniffer
from PIL import Image, ImageDraw, ImageTk
from ui.components.live_graph import LiveLatencyGraph
from ui.components.stats_cards import StatsDashboard
from ui.components.zone_view import ZoneDiagnosisView


# Target Presets
TARGET_PRESETS = {
    "Auto-Detect Apex Server": "AUTO_DETECT",
    "Google DNS (8.8.8.8)": "8.8.8.8",
    "Cloudflare DNS (1.1.1.1)": "1.1.1.1",
    "Custom Target": "",
}


class SavedResultsViewerWindow(ctk.CTkToplevel):
    """
    Dedicated in-app results browser window.
    Lists all saved test runs and displays full test reports directly inside the app.
    """

    def __init__(self, master, results_dir: str):
        super().__init__(master)
        self.title("📂 Saved Results Browser - Ping Tester")
        self.geometry("980x640")
        self.minsize(850, 500)
        self.results_dir = results_dir

        self.transient(master)
        self.grab_set()

        # Top Header
        header = ctk.CTkFrame(self, fg_color="#181a20", height=45, corner_radius=0)
        header.pack(fill="x", padx=0, pady=0)

        lbl_title = ctk.CTkLabel(
            header,
            text="📂 SAVED DIAGNOSTIC RESULTS BROWSER",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color="#00cec9",
        )
        lbl_title.pack(side="left", padx=16, pady=8)

        lbl_hint = ctk.CTkLabel(
            header,
            text="Click any saved test in the list below to view its full diagnostic report",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color="#8c9ba5",
        )
        lbl_hint.pack(side="right", padx=16, pady=8)

        # Main Split Content
        main_pane = ctk.CTkFrame(self, fg_color="transparent")
        main_pane.pack(fill="both", expand=True, padx=12, pady=8)

        # Upper: Saved Tests Table
        lbl_list = ctk.CTkLabel(
            main_pane,
            text="Saved Tests History (Newest First):",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#dfe6e9",
        )
        lbl_list.pack(anchor="w", padx=2, pady=(0, 4))

        table_frame = ctk.CTkFrame(main_pane, fg_color="#181a20", corner_radius=8)
        table_frame.pack(fill="x", padx=0, pady=(0, 8))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "SavedResults.Treeview",
            background="#181a20",
            foreground="#dcdde1",
            fieldbackground="#181a20",
            rowheight=24,
            font=("Segoe UI", 9),
        )
        style.configure(
            "SavedResults.Treeview.Heading",
            background="#21252d",
            foreground="#7f8c8d",
            font=("Segoe UI", 9, "bold"),
            borderwidth=0,
        )
        style.map("SavedResults.Treeview", background=[("selected", "#0984e3")])

        cols = ("date", "name", "target", "proto", "avg", "jitter", "loss", "grade")
        self.tree = ttk.Treeview(
            table_frame,
            columns=cols,
            show="headings",
            height=6,
            style="SavedResults.Treeview",
            selectmode="browse",
        )

        self.tree.heading("date", text="Date & Time", anchor="center")
        self.tree.heading("name", text="Custom Test Name", anchor="w")
        self.tree.heading("target", text="Target IP", anchor="center")
        self.tree.heading("proto", text="Protocol", anchor="center")
        self.tree.heading("avg", text="Avg Ping", anchor="center")
        self.tree.heading("jitter", text="Jitter", anchor="center")
        self.tree.heading("loss", text="Loss %", anchor="center")
        self.tree.heading("grade", text="Grade", anchor="center")

        self.tree.column("date", width=140, anchor="center")
        self.tree.column("name", width=220, anchor="w")
        self.tree.column("target", width=120, anchor="center")
        self.tree.column("proto", width=70, anchor="center")
        self.tree.column("avg", width=80, anchor="center")
        self.tree.column("jitter", width=80, anchor="center")
        self.tree.column("loss", width=65, anchor="center")
        self.tree.column("grade", width=60, anchor="center")

        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        scroll.pack(side="right", fill="y", padx=2, pady=2)

        self.tree.bind("<<TreeviewSelect>>", self._on_select_result)

        # Lower: Full Detailed Report View
        lbl_detail = ctk.CTkLabel(
            main_pane,
            text="Selected Test Full Diagnostic Report & Breakdown:",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#dfe6e9",
        )
        lbl_detail.pack(anchor="w", padx=2, pady=(4, 4))

        self.txt_report_view = ctk.CTkTextbox(
            main_pane,
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color="#14161b",
            text_color="#dfe6e9",
        )
        self.txt_report_view.pack(fill="both", expand=True, padx=0, pady=(0, 6))

        # Bottom Button Bar
        btn_bar = ctk.CTkFrame(self, fg_color="#181a20", height=42, corner_radius=0)
        btn_bar.pack(fill="x", padx=0, pady=0)

        btn_copy = ctk.CTkButton(
            btn_bar,
            text="📋 Copy Full Report",
            command=self._copy_selected_report,
            fg_color="#2d3436",
            hover_color="#3d4446",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=140,
        )
        btn_copy.pack(side="left", padx=12, pady=6)

        btn_delete = ctk.CTkButton(
            btn_bar,
            text="🗑️ Delete Selected",
            command=self._delete_selected_result,
            fg_color="#c0392b",
            hover_color="#d63031",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=130,
        )
        btn_delete.pack(side="left", padx=4, pady=6)

        btn_open = ctk.CTkButton(
            btn_bar,
            text="📁 Open Results Folder",
            command=lambda: os.startfile(self.results_dir) if hasattr(os, "startfile") else None,
            fg_color="#2d3436",
            hover_color="#3d4446",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=150,
        )
        btn_open.pack(side="left", padx=4, pady=6)

        btn_compare = ctk.CTkButton(
            btn_bar,
            text="⚖️ Compare Tests",
            command=lambda: TestComparisonWindow(self),
            fg_color="#6c5ce7",
            hover_color="#5f27cd",
            text_color="#ffffff",
            text_color_disabled="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=130,
        )
        btn_compare.pack(side="left", padx=4, pady=6)

        btn_close = ctk.CTkButton(
            btn_bar,
            text="Close",
            command=self.destroy,
            fg_color="#2d3436",
            hover_color="#3d4446",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=100,
        )
        btn_close.pack(side="right", padx=12, pady=6)

        # Load initial data
        self.results_cache = []
        self._load_results()

    def _load_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.results_cache = DiagnosticReporter.list_saved_results(self.results_dir)
        if not self.results_cache:
            self.txt_report_view.delete("1.0", "end")
            self.txt_report_view.insert(
                "end",
                "No saved test results found in results/ folder.\n\n"
                "Run a test in the main window and save it with your custom name to see full reports here."
            )
            return

        for idx, r in enumerate(self.results_cache):
            date_str = r.get("created_at", "")
            name_str = r.get("custom_name", "Unnamed")
            target = r.get("target", "")
            proto = r.get("protocol", "ICMP")
            stats = r.get("stream_stats", {})
            diag = r.get("diagnosis", {})

            avg_str = f"{stats.get('avg_rtt', 0.0):.1f} ms"
            jit_str = f"{stats.get('mean_jitter', 0.0):.1f} ms"
            loss_str = f"{stats.get('loss_pct', 0.0):.1f} %"
            grade = diag.get("grade", "-")

            self.tree.insert("", "end", iid=str(idx), values=(date_str, name_str, target, proto, avg_str, jit_str, loss_str, grade))

        # Select first row by default
        first_id = self.tree.get_children()[0]
        self.tree.selection_set(first_id)
        self._display_result_detail(0)

    def _on_select_result(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        self._display_result_detail(idx)

    def _display_result_detail(self, idx: int):
        if idx >= len(self.results_cache):
            return
        r = self.results_cache[idx]
        json_path = r.get("filepath", "")
        txt_path = json_path.replace(".json", ".txt")

        content = ""
        if os.path.exists(txt_path):
            try:
                with open(txt_path, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                pass

        if not content:
            # Fallback format from JSON data
            content = DiagnosticReporter.generate_text_report(
                target=r.get("target", ""),
                stream_stats=r.get("stream_stats", {}),
                hops=r.get("hops", []),
                diagnosis_dict=r.get("diagnosis", {}),
                gateway_ip=r.get("gateway_ip", "Unknown"),
                custom_name=r.get("custom_name", "Saved Test"),
                protocol=r.get("protocol", "ICMP"),
            )

        self.txt_report_view.delete("1.0", "end")
        self.txt_report_view.insert("end", content)

    def _copy_selected_report(self):
        text = self.txt_report_view.get("1.0", "end").strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            messagebox.showinfo("Copied", "Report copied to clipboard!")

    def _delete_selected_result(self):
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        r = self.results_cache[idx]
        name = r.get("custom_name", "test")

        if messagebox.askyesno("Confirm Delete", f"Delete saved result '{name}'?"):
            json_path = r.get("filepath", "")
            txt_path = json_path.replace(".json", ".txt")
            try:
                if os.path.exists(json_path):
                    os.remove(json_path)
                if os.path.exists(txt_path):
                    os.remove(txt_path)
            except Exception as e:
                messagebox.showerror("Error", f"Could not delete: {e}")
            self._load_results()


class TargetHistoryWindow(ctk.CTkToplevel):
    """
    Dedicated dialog displaying historical target IPs, real Apex game servers,
    and tested transit routes with exact timestamps and notes.
    Allows loading either the tested 0% loss transit gateway or the direct real server IP.
    """

    def __init__(self, parent: "PingTesterApp"):
        super().__init__(parent)
        self.parent_app = parent
        self.results_dir = parent.results_dir

        self.title("Target IP & Server History")
        self.geometry("820x480")
        self.minsize(720, 380)
        self.configure(fg_color="#181a20")

        self.transient(parent)
        try:
            parent.update_idletasks()
            mx = parent.winfo_x()
            my = parent.winfo_y()
            mw = parent.winfo_width()
            mh = parent.winfo_height()
            x = max(0, mx + (mw - 820) // 2)
            y = max(0, my + (mh - 480) // 2)
            self.geometry(f"820x480+{x}+{y}")
        except Exception:
            pass
        self.lift()
        self.grab_set()

        # Header
        hdr = ctk.CTkFrame(self, fg_color="#1f242d", height=52, corner_radius=0)
        hdr.pack(fill="x", padx=0, pady=0)

        lbl_t = ctk.CTkLabel(
            hdr,
            text="🕒 Target IP History (Real Apex Server & Tested Transit Gateway)",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color="#ffffff",
        )
        lbl_t.pack(anchor="w", padx=14, pady=(8, 0))

        lbl_sub = ctk.CTkLabel(
            hdr,
            text="Displays both the Real Apex Match Server and the Tested Transit Gateway. Double-click or pick an option below to load.",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color="#a4b0be",
        )
        lbl_sub.pack(anchor="w", padx=14, pady=(0, 6))

        # Main Table
        main_pane = ctk.CTkFrame(self, fg_color="transparent")
        main_pane.pack(fill="both", expand=True, padx=12, pady=8)

        table_frame = ctk.CTkFrame(main_pane, fg_color="#14161b", corner_radius=8)
        table_frame.pack(fill="both", expand=True)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "TargetHist.Treeview",
            background="#14161b",
            foreground="#dcdde1",
            fieldbackground="#14161b",
            rowheight=24,
            font=("Segoe UI", 9),
        )
        style.configure(
            "TargetHist.Treeview.Heading",
            background="#21252d",
            foreground="#7f8c8d",
            font=("Segoe UI", 9, "bold"),
            borderwidth=0,
        )
        style.map("TargetHist.Treeview", background=[("selected", "#0984e3")])

        cols = ("datetime", "real_ip", "tested_ip", "port", "label")
        self.tree = ttk.Treeview(
            table_frame,
            columns=cols,
            show="headings",
            style="TargetHist.Treeview",
            selectmode="browse",
        )

        self.tree.heading("datetime", text="Date & Time", anchor="center")
        self.tree.heading("real_ip", text="Real Apex Server IP", anchor="center")
        self.tree.heading("tested_ip", text="Transit / Tested IP", anchor="center")
        self.tree.heading("port", text="Port", anchor="center")
        self.tree.heading("label", text="Route Type / Note", anchor="w")

        self.tree.column("datetime", width=140, anchor="center")
        self.tree.column("real_ip", width=155, anchor="center")
        self.tree.column("tested_ip", width=155, anchor="center")
        self.tree.column("port", width=65, anchor="center")
        self.tree.column("label", width=220, anchor="w")

        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        scroll.pack(side="right", fill="y", padx=2, pady=2)

        self.tree.bind("<Double-1>", lambda e: self._on_load_transit_ip())

        # Bottom Bar
        btn_bar = ctk.CTkFrame(self, fg_color="#181a20", height=44, corner_radius=0)
        btn_bar.pack(fill="x", padx=0, pady=0)

        btn_load_transit = ctk.CTkButton(
            btn_bar,
            text="🎯 Use Transit IP (0% Loss)",
            fg_color="#00b894",
            hover_color="#00a383",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=180,
            command=self._on_load_transit_ip,
        )
        btn_load_transit.pack(side="left", padx=8, pady=6)

        btn_load_real = ctk.CTkButton(
            btn_bar,
            text="🎮 Use Real Server IP",
            fg_color="#0984e3",
            hover_color="#0873c4",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=150,
            command=self._on_load_real_ip,
        )
        btn_load_real.pack(side="left", padx=4, pady=6)

        btn_copy = ctk.CTkButton(
            btn_bar,
            text="📋 Copy Both IPs",
            fg_color="#2d3436",
            hover_color="#3d4446",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=120,
            command=self._on_copy_ips,
        )
        btn_copy.pack(side="left", padx=4, pady=6)

        btn_clear = ctk.CTkButton(
            btn_bar,
            text="🗑 Clear History",
            fg_color="#d63031",
            hover_color="#c0392b",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=110,
            command=self._on_clear_history,
        )
        btn_clear.pack(side="left", padx=4, pady=6)

        btn_close = ctk.CTkButton(
            btn_bar,
            text="Close",
            fg_color="#2d3436",
            hover_color="#3d4446",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=70,
            command=self.destroy,
        )
        btn_close.pack(side="right", padx=10, pady=6)

        self._load_data()

    def _load_data(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        history = DiagnosticReporter.get_target_history(self.results_dir)
        for entry in history:
            self.tree.insert(
                "",
                "end",
                values=(
                    entry.get("date_time", "-"),
                    entry.get("real_ip", "-"),
                    entry.get("tested_ip", "-"),
                    entry.get("port", "-"),
                    entry.get("label", "-"),
                ),
            )

    def _on_load_transit_ip(self):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        if vals and len(vals) >= 3:
            real_ip = vals[1]
            tested_ip = vals[2]
            port = vals[3] if len(vals) >= 4 and vals[3] != "-" else None
            target_to_use = tested_ip if tested_ip != "-" else real_ip
            self.parent_app.load_target_from_history(target_to_use, port, real_ip=real_ip)
            self.destroy()

    def _on_load_real_ip(self):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        if vals and len(vals) >= 2:
            real_ip = vals[1]
            if not real_ip or real_ip == "-":
                messagebox.showinfo(
                    "Real IP Not Available",
                    "This entry does not have a distinct real match IP recorded. Loading tested IP instead."
                )
                self._on_load_transit_ip()
                return
            port = vals[3] if len(vals) >= 4 and vals[3] != "-" else None
            self.parent_app.load_target_from_history(real_ip, port, real_ip=real_ip)
            self.destroy()

    def _on_copy_ips(self):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        if vals and len(vals) >= 3:
            real_ip = vals[1]
            tested_ip = vals[2]
            port = vals[3] if len(vals) >= 4 and vals[3] != "-" else ""
            parts = []
            if real_ip and real_ip != "-":
                parts.append(f"Real Apex Server: {real_ip}:{port}" if port else f"Real Apex Server: {real_ip}")
            if tested_ip and tested_ip != "-":
                parts.append(f"Tested Transit Gateway: {tested_ip}")
            clip_text = " | ".join(parts) if parts else (tested_ip if tested_ip != "-" else real_ip)
            self.clipboard_clear()
            self.clipboard_append(clip_text)
            messagebox.showinfo("Copied", f"Copied to clipboard:\n{clip_text}")

    def _on_clear_history(self):
        if messagebox.askyesno("Confirm Clear", "Clear all target IP history?"):
            DiagnosticReporter.clear_target_history(self.results_dir)
            self._load_data()


class TestCompletionDialog(ctk.CTkToplevel):
    """
    Modern, high-clarity post-test results modal.
    Features a clean 2x3 KPI card grid, competitive gaming verdict,
    dual-route breakdown, and instant one-click saving.
    """

    def __init__(
        self,
        master,
        target_str: str,
        protocol: str,
        stats: Dict[str, Any],
        diag: Optional[ZoneDiagnosis],
        on_save_callback,
    ):
        super().__init__(master)
        self.title("🏁 Network Diagnostic Report & Verdict")
        self.geometry("680x620")
        self.resizable(False, False)
        self.configure(fg_color="#141720")
        self.on_save_callback = on_save_callback

        self.transient(master)
        try:
            master.update_idletasks()
            mx = master.winfo_x()
            my = master.winfo_y()
            mw = master.winfo_width()
            mh = master.winfo_height()
            x = max(0, mx + (mw - 680) // 2)
            y = max(0, my + (mh - 620) // 2)
            self.geometry(f"680x620+{x}+{y}")
        except Exception:
            pass
        self.lift()
        self.attributes("-topmost", True)
        self.after(200, lambda: self.attributes("-topmost", False))
        self.grab_set()

        grade = diag.grade if diag else "A"
        grade_colors = {
            "A+": "#00d26a", "A": "#00f078", "B": "#4cd137",
            "C": "#fbc531", "D": "#e17055", "F": "#e84118",
        }
        badge_color = grade_colors.get(grade, "#00f078")

        # 1. Header Frame
        header = ctk.CTkFrame(self, fg_color="#1a1e28", height=54, corner_radius=0)
        header.pack(fill="x", padx=0, pady=0)

        t_left = ctk.CTkFrame(header, fg_color="transparent")
        t_left.pack(side="left", padx=16, pady=8)

        t_title = ctk.CTkLabel(
            t_left,
            text="🏁 NETWORK DIAGNOSTIC REPORT",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color="#ffffff",
        )
        t_title.pack(anchor="w")

        t_sub = ctk.CTkLabel(
            t_left,
            text=f"Probed via {protocol}  •  {stats.get('sent', 0)} Packets Tested  •  {stats.get('elapsed_sec', 0.0):.1f}s Duration",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color="#8c9ba5",
        )
        t_sub.pack(anchor="w")

        # Grade Badge
        grade_pill = ctk.CTkFrame(header, fg_color="#141720", border_width=2, border_color=badge_color, corner_radius=8)
        grade_pill.pack(side="right", padx=16, pady=8)
        lbl_grade = ctk.CTkLabel(
            grade_pill,
            text=f"GRADE: {grade}",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=badge_color,
            padx=12,
            pady=4,
        )
        lbl_grade.pack()

        # 2. Executive Gaming Verdict Card
        verdict_card = ctk.CTkFrame(self, fg_color="#1c212d", corner_radius=8)
        verdict_card.pack(fill="x", padx=16, pady=(10, 8))

        v_title = diag.verdict_title if diag else "Test Completed Successfully"
        v_summary = diag.verdict_summary if diag else "Connection metrics recorded cleanly."

        lbl_v_title = ctk.CTkLabel(
            verdict_card,
            text=f"🎯 {v_title}",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color="#00cec9",
        )
        lbl_v_title.pack(anchor="w", padx=14, pady=(8, 2))

        lbl_v_text = ctk.CTkLabel(
            verdict_card,
            text=v_summary,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color="#dfe6e9",
            justify="left",
            wraplength=630,
        )
        lbl_v_text.pack(anchor="w", padx=14, pady=(0, 8))

        # 3. 2x3 Visual KPI Grid
        kpi_frame = ctk.CTkFrame(self, fg_color="transparent")
        kpi_frame.pack(fill="x", padx=16, pady=4)
        kpi_frame.grid_columnconfigure((0, 1, 2), weight=1, uniform="kpi")

        avg_rtt = float(stats.get("avg_rtt", 0.0))
        min_rtt = float(stats.get("min_rtt", 0.0))
        max_rtt = float(stats.get("max_rtt", 0.0))
        jitter = float(stats.get("mean_jitter", 0.0))
        late_pct = float(stats.get("late_pct", 0.0))
        late_cnt = int(stats.get("late_count", 0))
        loss_pct = float(stats.get("loss_pct", 0.0))
        lost_cnt = int(stats.get("lost", 0))
        sent_cnt = int(stats.get("sent", 0))

        comp = diag.competitive_impact if diag and hasattr(diag, "competitive_impact") and diag.competitive_impact else {}
        if not comp:
            try:
                comp = ZoneAnalyzer.compute_competitive_impact(stats)
            except Exception:
                comp = {}

        hitreg_b = comp.get("hitreg_badge", "Optimal")
        desync_b = comp.get("desync_badge", "Low (~16ms)")
        act_delay = comp.get("action_delay_ms", round(avg_rtt + 16.6, 1))

        # Box 1: Average Latency
        real_ip = getattr(master, "last_detected_real_ip", None)
        transit_ip = getattr(master, "last_detected_transit_ip", None)
        in_game_est = avg_rtt + 16.6 if (real_ip and real_ip != "-") else avg_rtt
        self._build_kpi_box(
            kpi_frame, row=0, col=0,
            title="⏱️ NETWORK / GAME PING", title_color="#0984e3",
            main_val=f"{avg_rtt:.1f} ms",
            sub_text=f"In-Game Expected: ~{in_game_est:.0f}ms (Min {min_rtt:.0f} / Max {max_rtt:.0f})",
        )

        # Box 2: Jitter
        self._build_kpi_box(
            kpi_frame, row=0, col=1,
            title="〰️ JITTER & TIMING", title_color="#00d26a",
            main_val=f"{jitter:.1f} ms",
            sub_text=f"Variance: ±{jitter*1.2:.1f}ms spread",
        )

        # Box 3: Packet Loss
        loss_color = "#00d26a" if loss_pct == 0.0 else "#e84118"
        self._build_kpi_box(
            kpi_frame, row=0, col=2,
            title="📉 PACKET LOSS", title_color=loss_color,
            main_val=f"{loss_pct:.1f}%",
            sub_text=f"{lost_cnt} of {sent_cnt} dropped",
        )

        # Box 4: Late Spikes
        late_color = "#00d26a" if late_pct == 0.0 else "#f39c12"
        self._build_kpi_box(
            kpi_frame, row=1, col=0,
            title="🎯 LATE ARRIVALS", title_color=late_color,
            main_val=f"{late_pct:.1f}%",
            sub_text=f"{late_cnt} spikes > 130ms limit",
        )

        # Box 5: Hitreg / Ghost Bullets
        self._build_kpi_box(
            kpi_frame, row=1, col=1,
            title="💥 HIT REGISTRATION", title_color="#9b59b6",
            main_val=hitreg_b.replace("•", "").strip() or "Clean",
            sub_text="Bullet registry reliability",
        )

        # Box 6: Action Delay / Desync
        self._build_kpi_box(
            kpi_frame, row=1, col=2,
            title="🛡️ PEEKER'S ADVANTAGE", title_color="#00cec9",
            main_val=f"~{act_delay:.0f} ms",
            sub_text=f"Desync: {desync_b.replace('•', '').strip() or 'Low'}",
        )

        # 4. Route Breakdown Strip
        route_card = ctk.CTkFrame(self, fg_color="#181c26", corner_radius=6)
        route_card.pack(fill="x", padx=16, pady=8)

        real_ip = getattr(master, "last_detected_real_ip", None)
        transit_ip = getattr(master, "last_detected_transit_ip", None)
        if real_ip and real_ip != "-":
            edge_disp = transit_ip if (transit_ip and transit_ip != real_ip) else target_str
            route_text = f"🎮 Real Apex Server: {real_ip}   ⇄   🎯 Probed AWS Datacenter Edge: {edge_disp} (0% Loss Route)"
        else:
            route_text = f"🎯 Destination Tested: {target_str} ({protocol} Probing)"

        lbl_route = ctk.CTkLabel(
            route_card,
            text=route_text,
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color="#74b9ff",
        )
        lbl_route.pack(anchor="w", padx=12, pady=6)

        # 5. Save Section
        save_card = ctk.CTkFrame(self, fg_color="#1c212d", corner_radius=8)
        save_card.pack(fill="x", padx=16, pady=(4, 10))

        lbl_prompt = ctk.CTkLabel(
            save_card,
            text="Save result with custom name (or press Enter):",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#ffffff",
        )
        lbl_prompt.pack(anchor="w", padx=14, pady=(8, 4))

        import time
        default_suggestion = f"Apex_Test_{time.strftime('%H%M%S')}"

        self.entry_name = ctk.CTkEntry(
            save_card,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            height=32,
        )
        self.entry_name.insert(0, default_suggestion)
        self.entry_name.pack(fill="x", padx=14, pady=(0, 8))
        self.entry_name.focus()
        self.entry_name.select_range(0, "end")

        # 6. Button Row
        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 10))

        btn_save = ctk.CTkButton(
            btn_row,
            text="💾 Save Result (Enter)",
            fg_color="#00b894",
            hover_color="#00a383",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            height=34,
            command=self._confirm_save,
        )
        btn_save.pack(side="right", padx=(6, 0))

        btn_copy = ctk.CTkButton(
            btn_row,
            text="📋 Copy Summary",
            fg_color="#2d3436",
            hover_color="#3d4446",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            height=34,
            command=self._copy_summary,
        )
        btn_copy.pack(side="right", padx=6)

        btn_dismiss = ctk.CTkButton(
            btn_row,
            text="❌ Dismiss / Close",
            fg_color="#2d3436",
            hover_color="#3d4446",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            height=34,
            command=self.destroy,
        )
        btn_dismiss.pack(side="right")

        # Keep stats for copy
        self._stats = stats
        self._diag = diag
        self._target = target_str

        self.bind("<Return>", lambda e: self._confirm_save())
        self.bind("<Escape>", lambda e: self.destroy())

    def _build_kpi_box(self, parent, row: int, col: int, title: str, title_color: str, main_val: str, sub_text: str):
        box = ctk.CTkFrame(parent, fg_color="#181c26", corner_radius=6)
        box.grid(row=row, column=col, padx=4, pady=4, sticky="nsew")

        lbl_t = ctk.CTkLabel(
            box,
            text=title,
            font=ctk.CTkFont(family="Segoe UI", size=9, weight="bold"),
            text_color=title_color,
        )
        lbl_t.pack(anchor="w", padx=10, pady=(6, 0))

        lbl_v = ctk.CTkLabel(
            box,
            text=main_val,
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color="#ffffff",
        )
        lbl_v.pack(anchor="w", padx=10, pady=0)

        lbl_s = ctk.CTkLabel(
            box,
            text=sub_text,
            font=ctk.CTkFont(family="Segoe UI", size=9),
            text_color="#8c9ba5",
        )
        lbl_s.pack(anchor="w", padx=10, pady=(0, 6))

    def _copy_summary(self):
        s = self._stats
        avg = s.get("avg_rtt", 0.0)
        jit = s.get("mean_jitter", 0.0)
        loss = s.get("loss_pct", 0.0)
        late = s.get("late_pct", 0.0)
        grade = self._diag.grade if self._diag else "A"
        txt = (
            f"=== Network Diagnostic Verdict ===\n"
            f"Target: {self._target} | Grade: {grade}\n"
            f"Avg Ping: {avg:.1f}ms | Jitter: {jit:.1f}ms | Loss: {loss:.1f}% | Late Spikes: {late:.1f}%\n"
            f"Verdict: {self._diag.verdict_title if self._diag else 'OK'}\n"
        )
        self.clipboard_clear()
        self.clipboard_append(txt)
        messagebox.showinfo("Copied", "Diagnostic summary copied to clipboard!")

    def _confirm_save(self):
        name = self.entry_name.get().strip()
        if not name:
            name = "Unnamed_Test"
        self.destroy()
        self.on_save_callback(name)


class TestComparisonWindow(ctk.CTkToplevel):
    """
    Dedicated comparative analysis window.
    Allows users to select any two saved tests (e.g. before/after router tweak,
    Wi-Fi vs Ethernet, or different servers/ISPs) and view side-by-side metrics
    and algorithmic competitive verdicts.
    """

    def __init__(self, parent: Any):
        super().__init__(parent)
        self.parent_app = parent
        self.results_dir = parent.results_dir

        self.title("⚖️ Test Comparison Engine - Ping Tester")
        self.geometry("780x680")
        self.minsize(700, 580)
        self.configure(fg_color="#181a20")

        self.transient(parent)
        self.grab_set()

        # Header
        hdr = ctk.CTkFrame(self, fg_color="#1f242d", height=50, corner_radius=0)
        hdr.pack(fill="x", padx=0, pady=0)

        lbl_t = ctk.CTkLabel(
            hdr,
            text="⚖️ Competitive Test Comparison Engine",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            text_color="#ffffff",
        )
        lbl_t.pack(anchor="w", padx=16, pady=(8, 0))

        lbl_sub = ctk.CTkLabel(
            hdr,
            text="Compare two saved tests side-by-side to evaluate ping, jitter, hitreg reliability, and desync differences.",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color="#a4b0be",
        )
        lbl_sub.pack(anchor="w", padx=16, pady=(0, 6))

        # Selection Bar
        sel_frame = ctk.CTkFrame(self, fg_color="#14161b", corner_radius=6)
        sel_frame.pack(fill="x", padx=14, pady=(10, 6))

        # Load tests
        self.tests = DiagnosticReporter.list_saved_results(self.results_dir)
        self.test_options = []
        self.test_map = {}

        for idx, t in enumerate(self.tests):
            label = f"{t.get('created_at', '')} • {t.get('custom_name', 'Unnamed')} ({t.get('target', '')})"
            self.test_options.append(label)
            self.test_map[label] = t

        if not self.test_options:
            self.test_options = ["No saved tests available in results/"]

        drop_grid = ctk.CTkFrame(sel_frame, fg_color="transparent")
        drop_grid.pack(fill="x", padx=12, pady=10)

        lbl_a = ctk.CTkLabel(drop_grid, text="Test A (Baseline):", font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), text_color="#0984e3")
        lbl_a.grid(row=0, column=0, sticky="w", padx=(0, 10), pady=(0, 2))

        self.combo_a = ctk.CTkComboBox(
            drop_grid,
            values=self.test_options,
            width=300,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            command=lambda e: self._run_comparison(),
        )
        self.combo_a.grid(row=1, column=0, sticky="w", padx=(0, 10))

        lbl_b = ctk.CTkLabel(drop_grid, text="Test B (Comparison):", font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), text_color="#00b894")
        lbl_b.grid(row=0, column=1, sticky="w", padx=(0, 10), pady=(0, 2))

        self.combo_b = ctk.CTkComboBox(
            drop_grid,
            values=self.test_options,
            width=300,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            command=lambda e: self._run_comparison(),
        )
        self.combo_b.grid(row=1, column=1, sticky="w", padx=(0, 10))

        if len(self.test_options) >= 2:
            self.combo_a.set(self.test_options[1])
            self.combo_b.set(self.test_options[0])
        elif len(self.test_options) == 1:
            self.combo_a.set(self.test_options[0])
            self.combo_b.set(self.test_options[0])

        btn_run = ctk.CTkButton(
            drop_grid,
            text="⚡ Compare",
            fg_color="#0984e3",
            hover_color="#0773c5",
            text_color="#ffffff",
            text_color_disabled="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=90,
            command=self._run_comparison,
        )
        btn_run.grid(row=1, column=2, sticky="e", padx=(6, 0))

        # Content frame
        self.content_frame = ctk.CTkScrollableFrame(self, fg_color="#14161b", corner_radius=8)
        self.content_frame.pack(fill="both", expand=True, padx=14, pady=(0, 8))

        # Bottom Bar
        btn_bar = ctk.CTkFrame(self, fg_color="#181a20", height=42, corner_radius=0)
        btn_bar.pack(fill="x", padx=0, pady=0)

        self.btn_copy = ctk.CTkButton(
            btn_bar,
            text="📋 Copy Comparison Summary",
            fg_color="#2d3436",
            hover_color="#3d4446",
            text_color="#ffffff",
            text_color_disabled="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=190,
            command=self._copy_comparison,
        )
        self.btn_copy.pack(side="left", padx=14, pady=6)

        btn_close = ctk.CTkButton(
            btn_bar,
            text="Close",
            fg_color="#2d3436",
            hover_color="#3d4446",
            text_color="#ffffff",
            text_color_disabled="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=90,
            command=self.destroy,
        )
        btn_close.pack(side="right", padx=14, pady=6)

        self.last_summary_text = ""
        self._run_comparison()

    def _run_comparison(self):
        for child in self.content_frame.winfo_children():
            child.destroy()

        opt_a = self.combo_a.get()
        opt_b = self.combo_b.get()

        test_a = self.test_map.get(opt_a)
        test_b = self.test_map.get(opt_b)

        if not test_a or not test_b:
            lbl_none = ctk.CTkLabel(
                self.content_frame,
                text="Please select two valid saved tests from the dropdowns above to compare.",
                font=ctk.CTkFont(family="Segoe UI", size=12),
                text_color="#a4b0be",
            )
            lbl_none.pack(padx=20, pady=40)
            return

        res = DiagnosticReporter.compare_tests(test_a, test_b)
        self.last_summary_text = res.get("summary_text", "")

        # 1. Verdict Card
        card_verdict = ctk.CTkFrame(self.content_frame, fg_color="#1e222d", corner_radius=8)
        card_verdict.pack(fill="x", padx=6, pady=(4, 10))

        lbl_vbadge = ctk.CTkLabel(
            card_verdict,
            text=res.get("verdict_badge", ""),
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            text_color=res.get("verdict_color", "#ffffff"),
        )
        lbl_vbadge.pack(anchor="w", padx=12, pady=(10, 4))

        lbl_vsum = ctk.CTkLabel(
            card_verdict,
            text=res.get("summary_text", ""),
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#dfe6e9",
            justify="left",
            wraplength=700,
        )
        lbl_vsum.pack(anchor="w", padx=12, pady=(0, 10))

        # 2. Side-by-Side Comparison Table Card
        card_table = ctk.CTkFrame(self.content_frame, fg_color="#1e222d", corner_radius=8)
        card_table.pack(fill="x", padx=6, pady=(0, 10))

        lbl_table_t = ctk.CTkLabel(
            card_table,
            text="📊 METRIC COMPARISON TABLE",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color="#00cec9",
        )
        lbl_table_t.pack(anchor="w", padx=12, pady=(8, 6))

        # Table Header
        tbl_hdr = ctk.CTkFrame(card_table, fg_color="#181a20", height=28, corner_radius=4)
        tbl_hdr.pack(fill="x", padx=10, pady=(0, 4))

        ctk.CTkLabel(tbl_hdr, text="Metric", font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), width=160, anchor="w").pack(side="left", padx=8)
        ctk.CTkLabel(tbl_hdr, text=f"Test A ({res['name_a'][:14]})", font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), text_color="#0984e3", width=145, anchor="center").pack(side="left", padx=4)
        ctk.CTkLabel(tbl_hdr, text=f"Test B ({res['name_b'][:14]})", font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), text_color="#00b894", width=145, anchor="center").pack(side="left", padx=4)
        ctk.CTkLabel(tbl_hdr, text="Difference (Δ)", font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), width=110, anchor="center").pack(side="left", padx=4)
        ctk.CTkLabel(tbl_hdr, text="Impact", font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), width=110, anchor="center").pack(side="left", padx=4)

        rows = [
            (
                "Average Latency",
                f"{res['avg_a']:.1f} ms",
                f"{res['avg_b']:.1f} ms",
                f"{res['avg_diff']:+.1f} ms ({res['avg_pct']:+.1f}%)",
                "#00d26a" if res['avg_diff'] < 0 else ("#e74c3c" if res['avg_diff'] > 0 else "#a4b0be"),
                "Faster" if res['avg_diff'] < 0 else ("Slower" if res['avg_diff'] > 0 else "Equal"),
            ),
            (
                "Min Latency",
                f"{res['min_a']:.1f} ms",
                f"{res['min_b']:.1f} ms",
                f"{res['min_diff']:+.1f} ms",
                "#00d26a" if res['min_diff'] < 0 else ("#e74c3c" if res['min_diff'] > 0 else "#a4b0be"),
                "Lower" if res['min_diff'] < 0 else ("Higher" if res['min_diff'] > 0 else "Equal"),
            ),
            (
                "Max Latency Spike",
                f"{res['max_a']:.1f} ms",
                f"{res['max_b']:.1f} ms",
                f"{res['max_diff']:+.1f} ms",
                "#00d26a" if res['max_diff'] < -5 else ("#e74c3c" if res['max_diff'] > 5 else "#a4b0be"),
                "Tighter Spikes" if res['max_diff'] < 0 else ("Higher Spikes" if res['max_diff'] > 0 else "Equal"),
            ),
            (
                "Mean Jitter",
                f"{res['jit_a']:.1f} ms",
                f"{res['jit_b']:.1f} ms",
                f"{res['jit_diff']:+.1f} ms ({res['jit_pct']:+.1f}%)",
                "#00d26a" if res['jit_diff'] < 0 else ("#e74c3c" if res['jit_diff'] > 0 else "#a4b0be"),
                "More Stable" if res['jit_diff'] < 0 else ("More Jitter" if res['jit_diff'] > 0 else "Equal"),
            ),
            (
                "Standard Deviation",
                f"{res['std_a']:.1f} ms",
                f"{res['std_b']:.1f} ms",
                f"{res['std_diff']:+.1f} ms",
                "#00d26a" if res['std_diff'] < 0 else ("#e74c3c" if res['std_diff'] > 0 else "#a4b0be"),
                "Consistent" if res['std_diff'] < 0 else ("Fluctuating" if res['std_diff'] > 0 else "Equal"),
            ),
            (
                "Late Packets (>130ms)",
                f"{res['late_cnt_a']} ({res['late_pct_a']:.1f}%)",
                f"{res['late_cnt_b']} ({res['late_pct_b']:.1f}%)",
                f"{res['late_pct_diff']:+.1f}%",
                "#00d26a" if res['late_pct_diff'] < 0 else ("#e74c3c" if res['late_pct_diff'] > 0 else "#a4b0be"),
                "Better Hitreg" if res['late_pct_diff'] < 0 else ("More No-Regs" if res['late_pct_diff'] > 0 else "Equal"),
            ),
            (
                "Packet Loss",
                f"{res['loss_a']:.1f}%",
                f"{res['loss_b']:.1f}%",
                f"{res['loss_diff']:+.1f}%",
                "#00d26a" if res['loss_diff'] < 0 else ("#e74c3c" if res['loss_diff'] > 0 else "#a4b0be"),
                "Clean" if res['loss_diff'] <= 0 else "Drop Warning",
            ),
            (
                "Overall Grade",
                f"Grade {res['grade_a']}",
                f"Grade {res['grade_b']}",
                f"{res['grade_a']} → {res['grade_b']}",
                "#00d26a" if res['grade_b'] < res['grade_a'] else ("#e74c3c" if res['grade_b'] > res['grade_a'] else "#a4b0be"),
                "Upgraded" if res['grade_b'] < res['grade_a'] else ("Downgraded" if res['grade_b'] > res['grade_a'] else "Same"),
            ),
        ]

        for metric, val_a, val_b, diff, color, impact in rows:
            r_frame = ctk.CTkFrame(card_table, fg_color="transparent", height=24)
            r_frame.pack(fill="x", padx=10, pady=2)

            ctk.CTkLabel(r_frame, text=metric, font=ctk.CTkFont(family="Segoe UI", size=11), width=160, anchor="w", text_color="#dfe6e9").pack(side="left", padx=8)
            ctk.CTkLabel(r_frame, text=val_a, font=ctk.CTkFont(family="Segoe UI", size=11), width=145, anchor="center", text_color="#a4b0be").pack(side="left", padx=4)
            ctk.CTkLabel(r_frame, text=val_b, font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), width=145, anchor="center", text_color="#ffffff").pack(side="left", padx=4)
            ctk.CTkLabel(r_frame, text=diff, font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), width=110, anchor="center", text_color=color).pack(side="left", padx=4)
            ctk.CTkLabel(r_frame, text=impact, font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"), width=110, anchor="center", text_color=color).pack(side="left", padx=4)

        ctk.CTkFrame(card_table, fg_color="transparent", height=6).pack()

    def _copy_comparison(self):
        if not self.last_summary_text:
            return
        self.clipboard_clear()
        self.clipboard_append(self.last_summary_text)
        messagebox.showinfo("Copied", "Comparison summary copied to clipboard!")


class CircularProgressGauge(tk.Canvas):
    """
    Custom Circular Ring Progress Gauge for Bufferbloat Testing.
    Draws a smooth 360-degree animated arc with live throughput, delta, and phase states.
    """

    def __init__(self, master, size: int = 180, **kwargs):
        super().__init__(
            master,
            width=size,
            height=size,
            bg="#14161b",
            highlightthickness=0,
            **kwargs,
        )
        self.size = size
        self.pct = 0.0
        self.phase_key = "idle"
        self.phase_title = "READY"
        self.main_text = "--"
        self.unit_text = "Mbps"
        self.sub_text = "Click Start"
        self.arc_color = "#00d2d3"
        self.track_color = "#202531"

        self.redraw()

    def set_progress(self, pct: float, phase_key: Optional[str] = None):
        """Update just the progress percentage and optionally phase color while preserving current labels."""
        self.pct = max(0.0, min(1.0, pct))
        if phase_key:
            self.phase_key = phase_key
            phase_colors = {
                "baseline": "#00d2d3",
                "download": "#0984e3",
                "upload": "#e056fd",
                "complete": "#00d26a",
                "idle": "#74b9ff",
            }
            if phase_key in phase_colors:
                self.arc_color = phase_colors[phase_key]
        self.redraw()

    def update_state(
        self,
        pct: float,
        phase_key: str,
        phase_title: str,
        main_text: str,
        unit_text: str = "Mbps",
        sub_text: str = "",
        color: Optional[str] = None,
    ):
        self.pct = max(0.0, min(1.0, pct))
        self.phase_key = phase_key
        self.phase_title = phase_title
        self.main_text = main_text
        self.unit_text = unit_text
        self.sub_text = sub_text

        phase_colors = {
            "baseline": "#00d2d3",
            "download": "#0984e3",
            "upload": "#e056fd",
            "complete": "#00d26a",
            "idle": "#74b9ff",
        }
        self.arc_color = color or phase_colors.get(phase_key, "#0984e3")
        self.redraw()

    def redraw(self):
        self.delete("all")
        s = self.size
        pad = 12
        width = 11

        x0, y0 = pad, pad
        x1, y1 = s - pad, s - pad

        # Attempt smooth anti-aliased rendering with Pillow 4x supersampling + Lanczos downsampling
        rendered_with_pil = False
        try:
            scale = 4
            hi_size = s * scale
            hi_pad = pad * scale
            hi_width = width * scale

            # Dark background matching Canvas bg #14161b (20, 22, 27)
            img = Image.new("RGBA", (hi_size, hi_size), (20, 22, 27, 255))
            draw = ImageDraw.Draw(img)

            # 1. Background Track Ring (0 to 360)
            hx0, hy0 = hi_pad, hi_pad
            hx1, hy1 = hi_size - hi_pad, hi_size - hi_pad
            draw.arc([hx0, hy0, hx1, hy1], start=0, end=360, fill=self.track_color, width=hi_width)

            # 2. Foreground Active Progress Arc (from 270 degrees = top, sweeping clockwise)
            if self.pct > 0.005:
                sweep = self.pct * 360.0
                start_deg = 270
                end_deg = 270 + sweep
                draw.arc([hx0, hy0, hx1, hy1], start=start_deg, end=end_deg, fill=self.arc_color, width=hi_width)

            smooth_img = img.resize((s, s), resample=Image.Resampling.LANCZOS)
            self._tk_gauge_img = ImageTk.PhotoImage(smooth_img)
            self.create_image(0, 0, image=self._tk_gauge_img, anchor="nw")
            rendered_with_pil = True
        except Exception:
            rendered_with_pil = False

        if not rendered_with_pil:
            # Fallback to standard GDI Canvas arc
            self.create_arc(
                x0, y0, x1, y1,
                start=90,
                extent=-359.9,
                style="arc",
                width=width,
                outline=self.track_color,
            )
            extent_angle = - (self.pct * 359.9)
            if abs(extent_angle) > 1.0:
                self.create_arc(
                    x0, y0, x1, y1,
                    start=90,
                    extent=extent_angle,
                    style="arc",
                    width=width,
                    outline=self.arc_color,
                )

        cx = s / 2
        cy = s / 2

        # 3. Inside Circle Texts
        # Phase Header
        self.create_text(
            cx, cy - 36,
            text=self.phase_title.upper(),
            fill="#a4b0be",
            font=("Segoe UI", 9, "bold"),
            anchor="center",
        )

        # Main Large Value
        self.create_text(
            cx, cy - 6,
            text=self.main_text,
            fill="#ffffff",
            font=("Segoe UI", 22, "bold"),
            anchor="center",
        )

        # Unit / Sub-metric
        self.create_text(
            cx, cy + 18,
            text=self.unit_text,
            fill=self.arc_color,
            font=("Segoe UI", 10, "bold"),
            anchor="center",
        )

        # Bottom Note / Queue Delta
        self.create_text(
            cx, cy + 38,
            text=self.sub_text,
            fill="#dfe6e9",
            font=("Segoe UI", 8),
            anchor="center",
        )


class BufferbloatWindow(ctk.CTkToplevel):
    """
    Dedicated interactive Bufferbloat Evaluator Window (Waveform-Equivalent 3-Phase).
    Features a modern round circular progress ring, bidirectional saturation (Download & Upload),
    side-by-side queue bloat breakdown, and official ITU-T / Waveform grade verdict.
    """

    def __init__(self, parent: Any, target_ip: str):
        super().__init__(parent)
        self.parent_app = parent
        self.target_ip = target_ip
        self.tester = BufferbloatTester()

        self.title("⚡ 3-Phase Bufferbloat & Loaded Latency Evaluator")
        self.geometry("780x670")
        self.minsize(720, 600)
        self.configure(fg_color="#181a20")

        self.transient(parent)
        try:
            parent.update_idletasks()
            mx = parent.winfo_x()
            my = parent.winfo_y()
            mw = parent.winfo_width()
            mh = parent.winfo_height()
            x = max(0, mx + (mw - 780) // 2)
            y = max(0, my + (mh - 670) // 2)
            self.geometry(f"780x670+{x}+{y}")
        except Exception:
            pass
        self.lift()
        self.grab_set()

        # Header
        hdr = ctk.CTkFrame(self, fg_color="#1f242d", height=52, corner_radius=0)
        hdr.pack(fill="x", padx=0, pady=0)

        lbl_t = ctk.CTkLabel(
            hdr,
            text="⚡ 3-Phase Bidirectional Bufferbloat Evaluator",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            text_color="#ffffff",
        )
        lbl_t.pack(anchor="w", padx=16, pady=(8, 0))

        lbl_sub = ctk.CTkLabel(
            hdr,
            text=f"Waveform-Equivalent Test: Baseline ➔ Multi-Stream Download ➔ Multi-Stream Upload (Target: {target_ip})",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color="#a4b0be",
        )
        lbl_sub.pack(anchor="w", padx=16, pady=(0, 6))

        # Center Section: Circular Progress Ring & Live Stats
        center_panel = ctk.CTkFrame(self, fg_color="#14161b", corner_radius=8)
        center_panel.pack(fill="x", padx=14, pady=(10, 6))

        # 3 Columns: [Current Ping Stats] [Circular Progress Meter] [Live Queue Bloat]
        center_panel.grid_columnconfigure((0, 2), weight=1, uniform="side")
        center_panel.grid_columnconfigure(1, weight=0)

        # Left: Live Ping box
        left_box = ctk.CTkFrame(center_panel, fg_color="#1a1e28", corner_radius=6)
        left_box.grid(row=0, column=0, padx=12, pady=12, sticky="nsew")

        lbl_cur_ping_title = ctk.CTkLabel(left_box, text="LIVE TARGET PING", font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"), text_color="#74b9ff")
        lbl_cur_ping_title.pack(anchor="w", padx=12, pady=(10, 2))

        self.lbl_live_ping = ctk.CTkLabel(left_box, text="-- ms", font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"), text_color="#ffffff")
        self.lbl_live_ping.pack(anchor="w", padx=12, pady=0)

        self.lbl_live_phase_desc = ctk.CTkLabel(left_box, text="Awaiting start...", font=ctk.CTkFont(family="Segoe UI", size=9), text_color="#8c9ba5")
        self.lbl_live_phase_desc.pack(anchor="w", padx=12, pady=(0, 10))

        # Center: Round Circular Progress Gauge
        self.gauge = CircularProgressGauge(center_panel, size=180)
        self.gauge.grid(row=0, column=1, padx=8, pady=8)

        # Right: Live Delta Box
        right_box = ctk.CTkFrame(center_panel, fg_color="#1a1e28", corner_radius=6)
        right_box.grid(row=0, column=2, padx=12, pady=12, sticky="nsew")

        lbl_cur_delta_title = ctk.CTkLabel(right_box, text="ADDED QUEUE DELTA", font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"), text_color="#e67e22")
        lbl_cur_delta_title.pack(anchor="w", padx=12, pady=(10, 2))

        self.lbl_live_delta = ctk.CTkLabel(right_box, text="+0.0 ms", font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"), text_color="#f39c12")
        self.lbl_live_delta.pack(anchor="w", padx=12, pady=0)

        self.lbl_live_speed = ctk.CTkLabel(right_box, text="Speed: -- Mbps", font=ctk.CTkFont(family="Segoe UI", size=9), text_color="#8c9ba5")
        self.lbl_live_speed.pack(anchor="w", padx=12, pady=(0, 10))

        # 3 Side-by-Side Breakdown Cards (Baseline, Download Bloat, Upload Bloat)
        cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        cards_frame.pack(fill="x", padx=14, pady=4)
        cards_frame.grid_columnconfigure((0, 1, 2), weight=1, uniform="kpi")

        # Card 1: Baseline Idle
        self.card_idle = ctk.CTkFrame(cards_frame, fg_color="#1e222d", corner_radius=8)
        self.card_idle.grid(row=0, column=0, padx=(0, 4), sticky="nsew")

        lbl_i_t = ctk.CTkLabel(self.card_idle, text="1. IDLE BASELINE", font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"), text_color="#00cec9")
        lbl_i_t.pack(anchor="w", padx=10, pady=(6, 2))
        self.lbl_idle_val = ctk.CTkLabel(self.card_idle, text="-- ms", font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"), text_color="#ffffff")
        self.lbl_idle_val.pack(anchor="w", padx=10, pady=0)
        self.lbl_idle_sub = ctk.CTkLabel(self.card_idle, text="Jitter: -- ms", font=ctk.CTkFont(family="Segoe UI", size=9), text_color="#8c9ba5")
        self.lbl_idle_sub.pack(anchor="w", padx=10, pady=(0, 6))

        # Card 2: Download Bloat
        self.card_dl = ctk.CTkFrame(cards_frame, fg_color="#1e222d", corner_radius=8)
        self.card_dl.grid(row=0, column=1, padx=4, sticky="nsew")

        lbl_dl_t = ctk.CTkLabel(self.card_dl, text="2. DOWNLOAD BLOAT", font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"), text_color="#0984e3")
        lbl_dl_t.pack(anchor="w", padx=10, pady=(6, 2))
        self.lbl_dl_val = ctk.CTkLabel(self.card_dl, text="+-- ms", font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"), text_color="#ffffff")
        self.lbl_dl_val.pack(anchor="w", padx=10, pady=0)
        self.lbl_dl_sub = ctk.CTkLabel(self.card_dl, text="Speed: -- Mbps", font=ctk.CTkFont(family="Segoe UI", size=9), text_color="#8c9ba5")
        self.lbl_dl_sub.pack(anchor="w", padx=10, pady=(0, 6))

        # Card 3: Upload Bloat
        self.card_up = ctk.CTkFrame(cards_frame, fg_color="#1e222d", corner_radius=8)
        self.card_up.grid(row=0, column=2, padx=(4, 0), sticky="nsew")

        lbl_up_t = ctk.CTkLabel(self.card_up, text="3. UPLOAD BLOAT", font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"), text_color="#e056fd")
        lbl_up_t.pack(anchor="w", padx=10, pady=(6, 2))
        self.lbl_up_val = ctk.CTkLabel(self.card_up, text="+-- ms", font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"), text_color="#ffffff")
        self.lbl_up_val.pack(anchor="w", padx=10, pady=0)
        self.lbl_up_sub = ctk.CTkLabel(self.card_up, text="Speed: -- Mbps", font=ctk.CTkFont(family="Segoe UI", size=9), text_color="#8c9ba5")
        self.lbl_up_sub.pack(anchor="w", padx=10, pady=(0, 6))

        # Culprit / Verdict Callout Strip
        self.culprit_frame = ctk.CTkFrame(self, fg_color="#1c212d", corner_radius=6)
        self.culprit_frame.pack(fill="x", padx=14, pady=6)

        self.lbl_verdict_badge = ctk.CTkLabel(
            self.culprit_frame,
            text="GRADE: READY",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#00cec9",
        )
        self.lbl_verdict_badge.pack(anchor="w", padx=12, pady=(6, 2))

        self.lbl_verdict_desc = ctk.CTkLabel(
            self.culprit_frame,
            text="Click '▶ Start 3-Phase Evaluation' to test both Download & Upload lines under saturation.",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color="#dfe6e9",
            justify="left",
            wraplength=730,
        )
        self.lbl_verdict_desc.pack(anchor="w", padx=12, pady=(0, 6))

        # Real-time Stream Log
        self.txt_log = ctk.CTkTextbox(
            self,
            font=ctk.CTkFont(family="Consolas", size=9),
            fg_color="#14161b",
            text_color="#dfe6e9",
            height=130,
        )
        self.txt_log.pack(fill="both", expand=True, padx=14, pady=(2, 6))
        self.txt_log.insert("end", "3-Phase Bufferbloat Evaluation ready. Tests true latency under idle, download, and upload saturation.\n")

        # Bottom Action Bar
        btn_bar = ctk.CTkFrame(self, fg_color="#181a20", height=42, corner_radius=0)
        btn_bar.pack(fill="x", padx=0, pady=0)

        self.btn_start_test = ctk.CTkButton(
            btn_bar,
            text="▶ Start 3-Phase Evaluation",
            fg_color="#00b894",
            hover_color="#00a383",
            text_color="#ffffff",
            text_color_disabled="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=180,
            command=self._start_evaluation,
        )
        self.btn_start_test.pack(side="left", padx=14, pady=6)

        self.btn_stop_test = ctk.CTkButton(
            btn_bar,
            text="⏹ Cancel",
            fg_color="#2d3436",
            hover_color="#3d4446",
            text_color="#a4b0be",
            text_color_disabled="#7f8c8d",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=90,
            state="disabled",
            command=self._cancel_evaluation,
        )
        self.btn_stop_test.pack(side="left", padx=4, pady=6)

        btn_close = ctk.CTkButton(
            btn_bar,
            text="Close",
            fg_color="#2d3436",
            hover_color="#3d4446",
            text_color="#ffffff",
            text_color_disabled="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=80,
            command=self._on_close,
        )
        btn_close.pack(side="right", padx=14, pady=6)

        self._base_rtt = 0.0
        self.current_pct = 0.05
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        if self.tester.is_running:
            self.tester.stop()
        self.destroy()

    def _cancel_evaluation(self):
        if self.tester.is_running:
            self.tester.stop()
        self.current_pct = 0.0
        self.btn_start_test.configure(state="normal", text="▶ Run Again", fg_color="#00b894")
        self.btn_stop_test.configure(state="disabled", fg_color="#2d3436")
        self.lbl_verdict_desc.configure(text="Test cancelled by user.")
        self.gauge.update_state(0.0, "idle", "CANCELLED", "--", "Stopped", "Cancelled by user", "#e84118")

    def _start_evaluation(self):
        self.btn_start_test.configure(state="disabled", text="▶ Evaluating...", fg_color="#1e222d")
        self.btn_stop_test.configure(state="normal", fg_color="#e74c3c", hover_color="#c0392b", text_color="#ffffff")
        self.txt_log.delete("1.0", "end")
        self.txt_log.insert("end", f"=== STARTING 3-PHASE BUFFERBLOAT EVALUATION TO {self.target_ip} ===\n")
        self._base_rtt = 0.0
        self.current_pct = 0.05

        self.gauge.update_state(0.05, "baseline", "BASELINE", "--", "ms", "Measuring Idle RTT", "#00cec9")
        self.lbl_verdict_badge.configure(text="EVALUATION IN PROGRESS...", text_color="#00cec9")
        self.lbl_verdict_desc.configure(text="Phase 1: Measuring idle baseline ping without background traffic...")

        self.tester.start_test_async(
            target_ip=self.target_ip,
            unloaded_seconds=3.5,
            download_seconds=7.0,
            upload_seconds=7.0,
            on_phase=lambda msg, pct, p_key="idle": self.after(0, self._on_phase_update, msg, pct, p_key),
            on_ping=lambda p, phase: self.after(0, self._on_ping_update, p, phase),
            on_speed=lambda mbps, phase="download": self.after(0, self._on_speed_update, mbps, phase),
            on_complete=lambda res: self.after(0, self._on_test_complete, res),
        )

    def _on_phase_update(self, msg: str, pct: float, p_key: str = "idle"):
        self.current_pct = pct
        self.gauge.set_progress(pct, p_key)
        self.lbl_live_phase_desc.configure(text=msg)
        if p_key == "baseline":
            self.lbl_verdict_desc.configure(text="Phase 1/3: Measuring true idle round-trip latency...")
        elif p_key == "download":
            self.lbl_verdict_desc.configure(text="Phase 2/3: Saturating downstream pipe with 6 parallel streams to test download queue bloat...")
        elif p_key == "upload":
            self.lbl_verdict_desc.configure(text="Phase 3/3: Saturating upstream pipe with multi-stream HTTP POST chunks (Waveform-grade test)...")

    def _on_speed_update(self, mbps: float, phase: str = "download"):
        self.lbl_live_speed.configure(text=f"Speed: {mbps:.1f} Mbps")
        if phase == "download":
            self.lbl_dl_sub.configure(text=f"Speed: {mbps:.1f} Mbps")
            self.gauge.update_state(
                self.current_pct, "download", "DOWNLOAD",
                f"{mbps:.1f}", "Mbps",
                f"Bloat: {self.lbl_live_delta.cget('text')}"
            )
        elif phase == "upload":
            self.lbl_up_sub.configure(text=f"Speed: {mbps:.1f} Mbps")
            self.gauge.update_state(
                self.current_pct, "upload", "UPLOAD",
                f"{mbps:.1f}", "Mbps",
                f"Bloat: {self.lbl_live_delta.cget('text')}"
            )

    def _on_ping_update(self, p: Dict[str, Any], phase: str):
        rtt = p.get("rtt_ms")
        if rtt is None:
            self.txt_log.insert("end", f"[{phase.upper():<8}] TIMEOUT\n")
            self.txt_log.see("end")
            return

        self.lbl_live_ping.configure(text=f"{rtt:.1f} ms")

        if phase == "unloaded":
            self.lbl_idle_val.configure(text=f"{rtt:.1f} ms")
            self._base_rtt = rtt
            self.gauge.update_state(
                self.current_pct, "baseline", "BASELINE",
                f"{rtt:.1f}", "ms RTT",
                "Measuring Idle"
            )
            self.txt_log.insert("end", f"[IDLE    ] RTT = {rtt:5.1f} ms\n")
        elif phase == "download":
            delta = max(0.0, rtt - self._base_rtt)
            self.lbl_live_delta.configure(text=f"+{delta:.1f} ms")
            self.lbl_dl_val.configure(text=f"+{delta:.1f} ms")
            self.txt_log.insert("end", f"[DOWN-LOAD] RTT = {rtt:5.1f} ms (Delta: +{delta:4.1f}ms)\n")
        elif phase == "upload":
            delta = max(0.0, rtt - self._base_rtt)
            self.lbl_live_delta.configure(text=f"+{delta:.1f} ms")
            self.lbl_up_val.configure(text=f"+{delta:.1f} ms")
            self.txt_log.insert("end", f"[UP-LOAD  ] RTT = {rtt:5.1f} ms (Delta: +{delta:4.1f}ms)\n")

        self.txt_log.see("end")

    def _on_test_complete(self, res: Dict[str, Any]):
        self.btn_start_test.configure(state="normal", text="▶ Run Again", fg_color="#00b894")
        self.btn_stop_test.configure(state="disabled", fg_color="#2d3436")
        self.current_pct = 1.0

        grade = res.get("grade", "N/A")
        worst_delta = res.get("worst_delta_ms", 0.0)
        u_avg = res.get("unloaded_avg_ms", 0.0)
        u_jit = res.get("unloaded_jitter_ms", 0.0)

        dl_delta = res.get("download_delta_ms", 0.0)
        dl_mbps = res.get("download_mbps", 0.0)

        up_delta = res.get("upload_delta_ms", 0.0)
        up_mbps = res.get("upload_mbps", 0.0)

        grade_colors = {
            "A+": "#00d26a", "A": "#00f078", "B": "#4cd137",
            "C": "#fbc531", "D": "#e17055", "F": "#e84118",
        }
        b_color = grade_colors.get(grade, "#ffffff")

        # Update Gauge to 100% complete with final grade
        self.gauge.update_state(
            1.0, "complete", "COMPLETE",
            f"{grade}", f"Worst: +{worst_delta:.0f}ms",
            f"DL +{dl_delta:.0f}ms | UP +{up_delta:.0f}ms",
            color=b_color,
        )

        # Update Cards
        self.lbl_idle_val.configure(text=f"{u_avg:.1f} ms")
        self.lbl_idle_sub.configure(text=f"Jitter: {u_jit:.1f} ms")

        self.lbl_dl_val.configure(text=f"+{dl_delta:.1f} ms")
        self.lbl_dl_sub.configure(text=f"Speed: {dl_mbps:.1f} Mbps")

        self.lbl_up_val.configure(text=f"+{up_delta:.1f} ms")
        self.lbl_up_sub.configure(text=f"Speed: {up_mbps:.1f} Mbps")

        self.lbl_live_delta.configure(text=f"+{worst_delta:.1f} ms")

        # Culprit & Verdict
        self.lbl_verdict_badge.configure(
            text=f"🏁 FINAL GRADE: {grade}  (Waveform.com Grading Standard • Worst Bloat: +{worst_delta:.1f} ms)",
            text_color=b_color,
        )
        culprit_desc = res.get("culprit_text", "")
        rec_desc = res.get("recommendation", "")
        self.lbl_verdict_desc.configure(
            text=f"{culprit_desc}\nRecommendation: {rec_desc}"
        )

        # Detailed Log
        self.txt_log.insert("end", "\n" + "=" * 60 + "\n")
        self.txt_log.insert("end", f"🏁 FINAL 3-PHASE BUFFERBLOAT GRADE: {grade}\n")
        self.txt_log.insert("end", f"• Idle Baseline Ping : {u_avg:.1f} ms (Jitter: {u_jit:.1f} ms)\n")
        self.txt_log.insert("end", f"• Download Saturation: +{dl_delta:.1f} ms bloat @ {dl_mbps:.1f} Mbps\n")
        self.txt_log.insert("end", f"• Upload Saturation  : +{up_delta:.1f} ms bloat @ {up_mbps:.1f} Mbps\n")
        self.txt_log.insert("end", f"• Worst-Case Spike   : +{worst_delta:.1f} ms queue stall\n")
        self.txt_log.insert("end", f"• Bottleneck Culprit : {res.get('culprit', 'BALANCED')}\n")
        self.txt_log.insert("end", f"• Diagnostic Summary : {res.get('description', '')}\n")
        self.txt_log.insert("end", f"• Recommendation     : {rec_desc}\n")
        self.txt_log.insert("end", "=" * 60 + "\n")
        self.txt_log.see("end")


class PingTesterApp(ctk.CTk):
    """Main application window."""

    def __init__(self):
        super().__init__()

        # Window settings
        self.title("Ping Tester & Game Network Diagnostics (Apex Legends UDP / ICMP Analyzer)")
        self.geometry("1180x840")
        self.minsize(1080, 720)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Core Engines
        self.icmp = Win32ICMPEngine()
        self.stream_engine = StreamPingEngine(self.icmp)
        self.udp_engine = UDPEngine()
        self.tracer = RouteTracer(self.icmp)
        self.bufferbloat_tester = BufferbloatTester(self.icmp)
        self.passive_sniffer = PassiveNetcodeSniffer()

        # Dynamic paths (portable across user installations)
        if getattr(sys, "frozen", False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.results_dir = os.path.join(base_dir, "results")
        os.makedirs(self.results_dir, exist_ok=True)

        # State
        self.current_target = "103.10.124.116"
        self.current_udp_port = 27015
        self.local_gateway = self.icmp.get_default_gateway() or "192.168.1.1"
        self.last_stream_stats: Dict[str, Any] = {}
        self.last_hops: List[Dict[str, Any]] = []
        self.last_diagnosis: Optional[ZoneDiagnosis] = None
        self.last_test_protocol = "ICMP"
        self.last_detected_real_ip: Optional[str] = None
        self.last_detected_transit_ip: Optional[str] = None

        # Build UI
        self._build_header()
        self._build_controls()
        self._build_stats_row()
        self._build_main_notebook()
        self._build_footer()

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color="#181a20", height=46, corner_radius=0)
        header.pack(fill="x", padx=0, pady=0)

        lbl_app = ctk.CTkLabel(
            header,
            text="⚡ PING TESTER & GAMING NETWORK DIAGNOSTICS",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            text_color="#00d26a",
        )
        lbl_app.pack(side="left", padx=16, pady=8)

        self.lbl_gw_info = ctk.CTkLabel(
            header,
            text=f"Gateway: {self.local_gateway} • Mode: Dual ICMP/UDP",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#8c9ba5",
        )
        self.lbl_gw_info.pack(side="right", padx=16, pady=8)

    def _build_controls(self):
        ctrl_frame = ctk.CTkFrame(self, fg_color="#1f242d", corner_radius=8)
        ctrl_frame.pack(fill="x", padx=12, pady=(8, 4))

        # --- Row 1: Target Selector, IP Box, Auto-Detect, Detection Mode, IP History, Compare, View Results ---
        row1 = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        row1.pack(fill="x", padx=10, pady=(8, 4))

        lbl_target = ctk.CTkLabel(row1, text="Target:", font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"))
        lbl_target.pack(side="left", padx=(0, 4))

        self.preset_combo = ctk.CTkComboBox(
            row1,
            values=list(TARGET_PRESETS.keys()),
            width=180,
            command=self._on_preset_change,
        )
        self.preset_combo.pack(side="left", padx=(0, 6))

        lbl_ip = ctk.CTkLabel(row1, text="IP:", font=ctk.CTkFont(family="Segoe UI", size=11))
        lbl_ip.pack(side="left", padx=(2, 4))

        self.entry_target = ctk.CTkEntry(
            row1,
            placeholder_text="Target IP (e.g. 103.10.124.116)",
            width=150,
            font=ctk.CTkFont(family="Segoe UI", size=11),
        )
        self.entry_target.insert(0, self.current_target)
        self.entry_target.pack(side="left", padx=(0, 6))

        # Auto-Detect Button (High-Contrast Orange with Crisp White Bold Text)
        self.btn_auto_detect = ctk.CTkButton(
            row1,
            text="🎯 Auto-Detect",
            fg_color="#d35400",
            hover_color="#e67e22",
            text_color="#ffffff",
            text_color_disabled="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=110,
            command=self._on_auto_detect_apex,
        )
        self.btn_auto_detect.pack(side="left", padx=(0, 6))

        # Detection Mode Dropdown (Mutual Exclusion: Transit Gateway vs Driver UDP)
        self.combo_detect_mode = ctk.CTkComboBox(
            row1,
            values=["🎯 Transit Gateway (0% Loss)", "🎮 Driver UDP (Real Apex IP)"],
            width=200,
            command=self._on_detect_mode_change,
        )
        self.combo_detect_mode.pack(side="left", padx=(0, 6))

        # View Results Button (Far Right of Row 1)
        self.btn_view_results = ctk.CTkButton(
            row1,
            text="📂 View Results",
            fg_color="#2980b9",
            hover_color="#3498db",
            text_color="#ffffff",
            text_color_disabled="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=110,
            command=self._open_results_viewer,
        )
        self.btn_view_results.pack(side="right", padx=(3, 0))

        # Test Comparison Button (Between IP History and View Results)
        self.btn_compare = ctk.CTkButton(
            row1,
            text="⚖️ Compare",
            fg_color="#6c5ce7",
            hover_color="#5f27cd",
            text_color="#ffffff",
            text_color_disabled="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=95,
            command=self._open_comparison_viewer,
        )
        self.btn_compare.pack(side="right", padx=(3, 2))

        # Target IP History Button (Left Side of Compare)
        self.btn_ip_history = ctk.CTkButton(
            row1,
            text="🕒 IP History",
            fg_color="#34495e",
            hover_color="#415b76",
            text_color="#ffffff",
            text_color_disabled="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=95,
            command=self._open_ip_history_viewer,
        )
        self.btn_ip_history.pack(side="right", padx=(3, 2))

        # --- Row 2: Tick Rate, Protocol, Mode, Visible Time Box, Late Limit, Start, Stop, Trace, Bufferbloat ---
        row2 = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        row2.pack(fill="x", padx=10, pady=(4, 8))

        lbl_rate = ctk.CTkLabel(row2, text="Rate:", font=ctk.CTkFont(family="Segoe UI", size=11))
        lbl_rate.pack(side="left", padx=(0, 4))

        self.combo_rate = ctk.CTkComboBox(
            row2,
            values=["20 Hz (Apex)", "60 Hz (Competitive)", "10 Hz (Fast)", "1 Hz (Standard)"],
            width=135,
        )
        self.combo_rate.pack(side="left", padx=(0, 6))

        # Protocol dropdown moved to Row 2
        lbl_proto = ctk.CTkLabel(row2, text="Proto:", font=ctk.CTkFont(family="Segoe UI", size=11))
        lbl_proto.pack(side="left", padx=(2, 4))

        self.combo_proto = ctk.CTkComboBox(
            row2,
            values=["ICMP (Reliable)", "UDP (Game Port)"],
            width=135,
        )
        self.combo_proto.pack(side="left", padx=(0, 6))

        # Length / Duration Mode selector
        lbl_mode = ctk.CTkLabel(row2, text="Mode:", font=ctk.CTkFont(family="Segoe UI", size=11))
        lbl_mode.pack(side="left", padx=(0, 4))

        self.combo_length_mode = ctk.CTkComboBox(
            row2,
            values=["Timer (Seconds)", "Timer (Minutes)", "Packet Count", "Continuous"],
            width=130,
            command=self._on_mode_change,
        )
        self.combo_length_mode.pack(side="left", padx=(0, 4))

        # Visible Time / Count Entry Box (Always present on screen!)
        self.entry_length_val = ctk.CTkEntry(row2, width=50, font=ctk.CTkFont(family="Segoe UI", size=11))
        self.entry_length_val.insert(0, "60")
        self.entry_length_val.pack(side="left", padx=(0, 2))

        self.lbl_length_unit = ctk.CTkLabel(row2, text="sec", font=ctk.CTkFont(family="Segoe UI", size=11))
        self.lbl_length_unit.pack(side="left", padx=(0, 6))

        # Late threshold
        lbl_thresh = ctk.CTkLabel(row2, text="Late:", font=ctk.CTkFont(family="Segoe UI", size=11))
        lbl_thresh.pack(side="left", padx=(0, 4))

        self.entry_threshold = ctk.CTkEntry(row2, width=45, font=ctk.CTkFont(family="Segoe UI", size=11))
        self.entry_threshold.insert(0, "130")
        self.entry_threshold.pack(side="left", padx=(0, 2))

        lbl_ms = ctk.CTkLabel(row2, text="ms", font=ctk.CTkFont(family="Segoe UI", size=11))
        lbl_ms.pack(side="left", padx=(0, 8))

        # Permanent Dedicated Start & Stop Buttons side-by-side (High Contrast, Bold White Text)
        self.btn_start = ctk.CTkButton(
            row2,
            text="▶ Start Test",
            fg_color="#00a885",
            hover_color="#00b894",
            text_color="#ffffff",
            text_color_disabled="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=95,
            command=self._start_stream_test,
        )
        self.btn_start.pack(side="left", padx=2)

        self.btn_stop = ctk.CTkButton(
            row2,
            text="⏹ Stop Test",
            fg_color="#2d3436",
            hover_color="#3d4446",
            text_color="#a4b0be",
            text_color_disabled="#7f8c8d",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=85,
            state="disabled",
            command=self._stop_stream_test,
        )
        self.btn_stop.pack(side="left", padx=2)

        self.btn_trace = ctk.CTkButton(
            row2,
            text="🔍 Route Trace",
            fg_color="#2980b9",
            hover_color="#3498db",
            text_color="#ffffff",
            text_color_disabled="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=95,
            command=self._run_route_trace,
        )
        self.btn_trace.pack(side="left", padx=2)

        self.btn_bufferbloat = ctk.CTkButton(
            row2,
            text="⚡ Bufferbloat",
            fg_color="#8e44ad",
            hover_color="#9b59b6",
            text_color="#ffffff",
            text_color_disabled="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=105,
            command=self._run_bufferbloat_test,
        )
        self.btn_bufferbloat.pack(side="left", padx=2)

    def _build_stats_row(self):
        self.dashboard = StatsDashboard(self)
        self.dashboard.pack(fill="x", padx=12, pady=4)

    def _build_main_notebook(self):
        self.tabs = ctk.CTkTabview(self, fg_color="#181a20")
        self.tabs.pack(fill="both", expand=True, padx=12, pady=4)

        self.tab_monitor = self.tabs.add("  📈 Live Latency & Jitter Monitor  ")
        self.tab_zones = self.tabs.add("  🗺️ 3-Zone Route & Fault Locator  ")
        self.tab_report = self.tabs.add("  📋 Diagnostic Report & ISP Complaint  ")
        self.tab_history = self.tabs.add("  📂 Saved Results History  ")

        # --- Tab 1: Live Monitor ---
        self.graph = LiveLatencyGraph(self.tab_monitor, height=220, late_threshold_ms=130.0)
        self.graph.pack(fill="both", expand=True, padx=8, pady=(8, 4))

        log_frame = ctk.CTkFrame(self.tab_monitor, fg_color="#14161b", height=95)
        log_frame.pack(fill="x", padx=8, pady=(4, 8))

        self.txt_packet_log = ctk.CTkTextbox(
            log_frame,
            height=85,
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color="#14161b",
            text_color="#c8d6e5",
        )
        self.txt_packet_log.pack(fill="both", expand=True, padx=4, pady=4)
        self.txt_packet_log.insert(
            "end",
            "Ready. Choose your target, set your test duration, and click 'Start Test'.\n"
        )

        # --- Tab 2: 3-Zone Route & Fault Locator ---
        self.zone_view = ZoneDiagnosisView(self.tab_zones)
        self.zone_view.pack(fill="both", expand=True, padx=6, pady=6)

        # --- Tab 3: Report & ISP Ticket ---
        report_frame = ctk.CTkFrame(self.tab_report, fg_color="#14161b")
        report_frame.pack(fill="both", expand=True, padx=6, pady=6)

        btn_row = ctk.CTkFrame(report_frame, fg_color="transparent")
        btn_row.pack(fill="x", padx=8, pady=6)

        btn_save_custom = ctk.CTkButton(
            btn_row,
            text="💾 Save Result with Name",
            command=self._open_manual_save_dialog,
            fg_color="#00b894",
            hover_color="#00a383",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
        )
        btn_save_custom.pack(side="left", padx=4)

        btn_copy_isp = ctk.CTkButton(
            btn_row,
            text="📋 Copy ISP Support Ticket",
            command=self._copy_isp_ticket,
            fg_color="#2d3436",
            hover_color="#3d4446",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
        )
        btn_copy_isp.pack(side="left", padx=4)

        self.txt_report = ctk.CTkTextbox(
            report_frame,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color="#14161b",
            text_color="#dfe6e9",
        )
        self.txt_report.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.txt_report.insert("end", "Complete a test or trace to generate an in-depth diagnostic report.")

        # --- Tab 4: Saved Results History ---
        self._build_history_tab()

    def _build_history_tab(self):
        hist_container = ctk.CTkFrame(self.tab_history, fg_color="#181a20")
        hist_container.pack(fill="both", expand=True, padx=6, pady=6)

        hist_ctrls = ctk.CTkFrame(hist_container, fg_color="transparent")
        hist_ctrls.pack(fill="x", padx=6, pady=6)

        btn_open_viewer = ctk.CTkButton(
            hist_ctrls,
            text="🔍 Open Full Results Browser",
            command=self._open_results_viewer,
            fg_color="#0984e3",
            hover_color="#0773c5",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=180,
        )
        btn_open_viewer.pack(side="left", padx=4)

        btn_refresh = ctk.CTkButton(
            hist_ctrls,
            text="🔄 Refresh List",
            command=self._refresh_history_list,
            fg_color="#2d3436",
            hover_color="#3d4446",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=120,
        )
        btn_refresh.pack(side="left", padx=4)

        btn_open_folder = ctk.CTkButton(
            hist_ctrls,
            text="📁 Open Results Folder",
            command=lambda: os.startfile(self.results_dir) if hasattr(os, "startfile") else None,
            fg_color="#2d3436",
            hover_color="#3d4446",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=140,
        )
        btn_open_folder.pack(side="left", padx=4)

        self.txt_history = ctk.CTkTextbox(
            hist_container,
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color="#14161b",
            text_color="#dfe6e9",
        )
        self.txt_history.pack(fill="both", expand=True, padx=6, pady=6)
        self._refresh_history_list()

    def _build_footer(self):
        footer = ctk.CTkFrame(self, fg_color="#181a20", height=28, corner_radius=0)
        footer.pack(fill="x", padx=0, pady=0)

        self.lbl_status = ctk.CTkLabel(
            footer,
            text="Idle • Ready for network diagnostic session",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color="#8c9ba5",
        )
        self.lbl_status.pack(side="left", padx=12, pady=4)

    def _on_mode_change(self, choice: str):
        """Updates unit label and default values when mode changes."""
        if "Seconds" in choice:
            self.entry_length_val.configure(state="normal")
            self.entry_length_val.delete(0, "end")
            self.entry_length_val.insert(0, "60")
            self.lbl_length_unit.configure(text="sec")
        elif "Minutes" in choice:
            self.entry_length_val.configure(state="normal")
            self.entry_length_val.delete(0, "end")
            self.entry_length_val.insert(0, "2")
            self.lbl_length_unit.configure(text="min")
        elif "Packet Count" in choice:
            self.entry_length_val.configure(state="normal")
            self.entry_length_val.delete(0, "end")
            self.entry_length_val.insert(0, "100")
            self.lbl_length_unit.configure(text="pkts")
        elif "Continuous" in choice:
            self.entry_length_val.delete(0, "end")
            self.entry_length_val.insert(0, "∞")
            self.entry_length_val.configure(state="disabled")
            self.lbl_length_unit.configure(text="loop")

    def _on_preset_change(self, choice: str):
        if choice == "Auto-Detect Apex Server":
            self._on_auto_detect_apex()
            return

        ip = TARGET_PRESETS.get(choice, "")
        if ip and ip != "AUTO_DETECT":
            self.entry_target.delete(0, "end")
            self.entry_target.insert(0, ip)

    def _on_detect_mode_change(self, choice: str):
        """
        Switches between Datacenter Edge Gateway (Transit) and Real Apex Match Server (Driver UDP).
        Enforces mutual exclusion: selecting one automatically disables the other.
        """
        if "Driver UDP" in choice:
            # Driver UDP mode: Real match host IP
            if self.last_detected_real_ip:
                self.entry_target.delete(0, "end")
                self.entry_target.insert(0, self.last_detected_real_ip)
                self.lbl_status.configure(
                    text=f"🎮 Real Apex Server Locked: {self.last_detected_real_ip}. Probing will measure 100% physical route directly to the AWS datacenter (0% firewall loss)."
                )
            else:
                self.lbl_status.configure(
                    text="🎮 Driver UDP Mode active: Targets Real Match Server IP. Probing measures 100% physical route directly to the server rack."
                )
        else:
            # Transit Gateway mode: Datacenter Edge Gateway (bypasses AWS ICMP drop)
            if self.last_detected_transit_ip:
                self.entry_target.delete(0, "end")
                self.entry_target.insert(0, self.last_detected_transit_ip)
                self.lbl_status.configure(
                    text=f"🎯 Transit Gateway Mode active: Target set to Edge Gateway {self.last_detected_transit_ip} (0% Loss)."
                )
            else:
                self.lbl_status.configure(
                    text="🎯 Transit Gateway Mode active: Targets Datacenter Edge Gateway for 0% Loss. Click '🎯 Auto-Detect' during a match."
                )

    def _on_auto_detect_apex(self):
        """
        Scans for active Apex Legends match packets (via raw UDP socket / driver when elevated)
        or resolves official Singapore SDR game relay.
        Fills the target and records history without auto-starting the test.
        """
        self.btn_auto_detect.configure(state="disabled", text="⏳ Sniffing...", text_color="#ffffff", text_color_disabled="#ffffff")
        self.lbl_status.configure(text="Sniffing active match UDP packets from Apex Legends...")
        self.update_idletasks()

        sel_mode_text = getattr(self, "combo_detect_mode", None)
        mode_val = "direct" if (sel_mode_text and "Driver UDP" in sel_mode_text.get()) else "transit"

        try:
            res = ApexDetector.detect(mode=mode_val)
        finally:
            self.btn_auto_detect.configure(state="normal", text="🎯 Auto-Detect", text_color="#ffffff")

        target_ip = res.get("detected_ip")
        target_port = res.get("detected_port", 27015)
        self.current_udp_port = target_port

        if target_ip:
            self.entry_target.delete(0, "end")
            self.entry_target.insert(0, target_ip)

        if res.get("in_match"):
            real_ip = res.get("real_match_ip", target_ip)
            gw_ip = res.get("gateway_ip")
            self.last_detected_real_ip = real_ip
            self.last_detected_transit_ip = gw_ip or target_ip
            self.combo_proto.set("ICMP (Reliable)")

            if mode_val == "direct":
                label = "Apex Match (Driver UDP - Real IP)"
                self.lbl_status.configure(
                    text=f"🎮 [DRIVER UDP] Real Match Server Locked: {target_ip}:{target_port}. Probing will measure 100% physical route (0% firewall loss). Click '▶ Start Test'!"
                )
            else:
                if gw_ip and gw_ip != real_ip:
                    label = "Apex Match (Edge Gateway)"
                    self.lbl_status.configure(
                        text=f"🎯 [TRANSIT ROUTE] Datacenter Edge Gateway Locked: {target_ip} (0% Loss) [Real: {real_ip}:{target_port}]. Driver mode disabled. Click '▶ Start Test'!"
                    )
                else:
                    label = "Apex Match (Direct)"
                    self.lbl_status.configure(
                        text=f"🎯 Apex Match Detected: {target_ip}:{target_port}. Click '▶ Start Test'!"
                    )

            DiagnosticReporter.append_target_history(
                self.results_dir,
                ip=target_ip,
                port=target_port,
                real_ip=real_ip,
                label=label,
            )
        else:
            self.last_detected_real_ip = None
            self.last_detected_transit_ip = target_ip
            self.combo_proto.set("ICMP (Reliable)")
            label = "Singapore SDR Relay (Lobby)"
            self.lbl_status.configure(
                text=f"Apex in Lobby/Closed. Target set to Singapore Game Relay: {target_ip}:{target_port}. Click '▶ Start Test' when ready!"
            )
            DiagnosticReporter.append_target_history(
                self.results_dir,
                ip=target_ip,
                port=target_port,
                real_ip="-",
                label=label,
            )

    def _open_ip_history_viewer(self):
        """Opens the dedicated Target IP & Port History dialog."""
        TargetHistoryWindow(self)

    def load_target_from_history(self, ip: str, port: Optional[Any] = None, real_ip: Optional[str] = None):
        """Callback from TargetHistoryWindow to load an IP & port back into the target box."""
        if not ip or ip == "-":
            return
        self.entry_target.delete(0, "end")
        self.entry_target.insert(0, ip)
        self.preset_combo.set("Custom Target")
        if real_ip and real_ip != "-" and real_ip != ip:
            self.last_detected_real_ip = real_ip
            self.last_detected_transit_ip = ip
        else:
            self.last_detected_real_ip = ip
            self.last_detected_transit_ip = ip

        if port and str(port).strip() not in ("-", "None", ""):
            try:
                self.current_udp_port = int(port)
            except ValueError:
                pass
        port_suffix = f":{port}" if port and str(port).strip() not in ("-", "None", "") else ""
        if real_ip and real_ip != "-" and real_ip != ip:
            self.lbl_status.configure(
                text=f"Loaded from History: Transit {ip} (Real Apex Host: {real_ip}{port_suffix}). Ready to test!"
            )
        else:
            self.lbl_status.configure(text=f"Loaded target from history: {ip}{port_suffix}. Ready to test!")

    def _get_target_ip(self) -> str:
        raw = self.entry_target.get().strip()
        if not raw:
            return "103.10.124.116"
        resolved = self.icmp.resolve_ip(raw)
        return resolved or raw

    def _get_threshold(self) -> float:
        try:
            return float(self.entry_threshold.get().strip())
        except Exception:
            return 130.0

    def _get_tick_rate(self) -> float:
        val = self.combo_rate.get()
        if "20 Hz" in val:
            return 20.0
        elif "60 Hz" in val:
            return 60.0
        elif "10 Hz" in val:
            return 10.0
        return 1.0

    def _get_test_limit(self) -> Tuple[Optional[int], Optional[float]]:
        """
        Parses Length/Duration mode and input value.
        Returns (packet_count, duration_seconds).
        """
        mode = self.combo_length_mode.get()
        val_str = self.entry_length_val.get().strip()

        if "Continuous" in mode:
            return (None, None)

        try:
            val_num = float(val_str)
        except ValueError:
            val_num = 60.0

        if "Seconds" in mode:
            return (None, max(2.0, val_num))
        elif "Minutes" in mode:
            return (None, max(5.0, val_num * 60.0))
        elif "Packet Count" in mode:
            return (int(max(5, val_num)), None)

        return (None, 60.0)

    def _start_stream_test(self):
        """Starts stream testing."""
        is_driver_udp_mode = "Driver UDP" in self.combo_detect_mode.get()
        is_udp_mode = "UDP" in self.combo_proto.get()

        active_engine = self.udp_engine if is_udp_mode else self.stream_engine
        self.last_test_protocol = "UDP" if is_udp_mode else "ICMP"

        if active_engine.is_running:
            return

        target = self._get_target_ip()
        threshold = self._get_threshold()
        tick_rate = self._get_tick_rate()
        count, duration_sec = self._get_test_limit()

        # Determine physical probe destination to prevent AWS DDoS drops
        probe_target = target
        if is_driver_udp_mode or (self.last_detected_real_ip and target == self.last_detected_real_ip):
            if self.last_detected_transit_ip:
                probe_target = self.last_detected_transit_ip
            else:
                gw, _ = ApexDetector.find_edge_gateway(target)
                if gw and gw != target:
                    probe_target = gw
                    self.last_detected_real_ip = target
                    self.last_detected_transit_ip = gw

        # Record target IP & Port in history
        port_to_record = self.current_udp_port if is_udp_mode else None
        real_ip_to_record = self.last_detected_real_ip if self.last_detected_real_ip and self.last_detected_real_ip != probe_target else "-"
        label_to_record = "Apex Match (Driver UDP - Real IP)" if is_driver_udp_mode else ("Apex Match (Edge Gateway)" if real_ip_to_record != "-" else "Direct Target")
        DiagnosticReporter.append_target_history(
            self.results_dir,
            ip=target,
            port=port_to_record,
            real_ip=real_ip_to_record,
            label=label_to_record,
        )

        self.graph.clear()
        self.graph.set_late_threshold(threshold)

        # Update button states
        self.btn_start.configure(
            state="disabled",
            text="▶ Running...",
            fg_color="#1e222d",
            text_color="#ffffff",
            text_color_disabled="#ffffff",
        )
        self.btn_stop.configure(
            state="normal",
            text="⏹ Stop Test",
            fg_color="#e74c3c",
            hover_color="#c0392b",
            text_color="#ffffff",
        )

        length_desc = f"{int(duration_sec)}s timer" if duration_sec else (f"{count} packets" if count else "Continuous")
        if probe_target != target:
            self.lbl_status.configure(
                text=f"Probing physical network path to Apex Server {target} via Datacenter Edge {probe_target} (0% Loss)..."
            )
            self.txt_packet_log.delete("1.0", "end")
            self.txt_packet_log.insert(
                "end",
                f"--- Probing Physical Route to Apex Server {target} (via Datacenter Edge Gateway {probe_target} • 0% Firewall Loss) ---\n"
            )
        else:
            self.lbl_status.configure(
                text=f"Streaming {self.last_test_protocol} probes to {target} ({length_desc} @ {tick_rate}Hz)..."
            )
            self.txt_packet_log.delete("1.0", "end")
            self.txt_packet_log.insert(
                "end",
                f"--- Starting {self.last_test_protocol} Stream: Target={target} | Mode={length_desc} | Rate={tick_rate}Hz | LateLimit={threshold}ms ---\n"
            )

        def on_packet(p):
            self.after(0, self._handle_packet_update, p)

        def on_stats(s):
            self.after(0, self._handle_stats_update, s)

        def on_finished(final_stats):
            self.after(0, self._handle_stream_finished, final_stats)

        if is_udp_mode:
            self.udp_engine.start_udp_stream(
                target_ip=probe_target,
                target_port=self.current_udp_port,
                packet_count=count,
                duration_seconds=duration_sec,
                tick_rate_hz=tick_rate,
                late_threshold_ms=threshold,
                on_packet=on_packet,
                on_stats=on_stats,
                on_finished=on_finished,
            )
        else:
            self.stream_engine.start_stream(
                target_ip=probe_target,
                packet_count=count,
                duration_seconds=duration_sec,
                tick_rate_hz=tick_rate,
                late_threshold_ms=threshold,
                on_packet=on_packet,
                on_stats=on_stats,
                on_finished=on_finished,
            )

    def _stop_stream_test(self):
        """Immediately stops any running stream test."""
        if self.stream_engine.is_running:
            self.stream_engine.stop()
        if self.udp_engine.is_running:
            self.udp_engine.stop()

        self.btn_start.configure(
            state="normal",
            text="▶ Start Test",
            fg_color="#00a885",
            hover_color="#00b894",
            text_color="#ffffff",
        )
        self.btn_stop.configure(
            state="disabled",
            text="⏹ Stop Test",
            fg_color="#2d3436",
            hover_color="#3d4446",
            text_color="#a4b0be",
            text_color_disabled="#7f8c8d",
        )
        self.lbl_status.configure(text="Stream test stopped by user.")

    def _handle_packet_update(self, p: Dict[str, Any]):
        rtt = p.get("rtt_ms")
        is_late = p.get("is_late", False)
        success = p.get("success", False)
        seq = p.get("seq", 0)

        self.graph.add_packet(rtt, is_late, success)

        if success:
            tag = " [LATE!]" if is_late else ""
            log_line = f"Seq #{seq:03d}: RTT={rtt:6.1f} ms | Status=OK{tag}\n"
        else:
            tip = ""
            if self.last_test_protocol == "UDP" and seq == 3:
                tip = " -> [TIP: If UDP shows timeouts, this server drops unsolicited UDP queries. Switch protocol to 'ICMP (Reliable)' for 0% loss live latency testing!]"
            log_line = f"Seq #{seq:03d}: DROPPED / TIMEOUT ({p.get('status_text')}){tip}\n"

        self.txt_packet_log.insert("end", log_line)
        self.txt_packet_log.see("end")

    def _handle_stats_update(self, stats: Dict[str, Any]):
        self.last_stream_stats = stats
        self.dashboard.update_stats(stats)

        rem = stats.get("remaining_sec")
        sent = stats.get("sent", 0)
        avg = stats.get("avg_rtt", 0.0)
        jit = stats.get("mean_jitter", 0.0)

        if rem is not None:
            m, s = divmod(int(rem), 60)
            self.lbl_status.configure(text=f"⏱️ Time Left: {m:02d}:{s:02d} • Packets: {sent} • Avg: {avg:.1f}ms • Jitter: {jit:.1f}ms")
        else:
            self.lbl_status.configure(text=f"Probing {self.last_test_protocol}... Packets: {sent} • Avg: {avg:.1f}ms • Jitter: {jit:.1f}ms")

    def _handle_stream_finished(self, final_stats: Dict[str, Any]):
        self.btn_start.configure(
            state="normal",
            text="▶ Start Test",
            fg_color="#00a885",
            hover_color="#00b894",
            text_color="#ffffff",
        )
        self.btn_stop.configure(
            state="disabled",
            text="⏹ Stop Test",
            fg_color="#2d3436",
            hover_color="#3d4446",
            text_color="#a4b0be",
            text_color_disabled="#7f8c8d",
        )

        sent_count = final_stats.get("sent", 0)
        if sent_count == 0:
            self.lbl_status.configure(
                text="⚠️ No response packets received from target destination."
            )
            return

        avg_rtt = final_stats.get('avg_rtt', 0.0)
        real_ip = getattr(self, "last_detected_real_ip", None)
        in_game_desc = f" (In-game expected: ~{avg_rtt + 16.6:.0f}ms)" if (real_ip and real_ip != "-") else ""
        self.lbl_status.configure(
            text=f"Test finished: {final_stats.get('sent')} packets. Network Ping={avg_rtt:.1f}ms{in_game_desc}, Jitter={final_stats.get('mean_jitter'):.1f}ms"
        )
        try:
            self._run_analysis()
        except Exception as e:
            print(f"Error during analysis: {e}")

        # Instant Automatic Test Completion & Direct Save Dialog
        try:
            TestCompletionDialog(
                master=self,
                target_str=self._get_target_ip(),
                protocol=self.last_test_protocol,
                stats=final_stats,
                diag=self.last_diagnosis,
                on_save_callback=self._execute_save_custom_result,
            )
        except Exception as e:
            print(f"Error opening TestCompletionDialog: {e}")

    def _run_route_trace(self):
        target = self._get_target_ip()
        real_ip = self.last_detected_real_ip if self.last_detected_real_ip and self.last_detected_real_ip != target else "-"
        DiagnosticReporter.append_target_history(
            self.results_dir,
            ip=target,
            port=None,
            real_ip=real_ip,
            label="Traceroute Target",
        )
        self.zone_view.clear_hops()
        self.btn_trace.configure(
            state="disabled",
            text="⏳ Tracing...",
            fg_color="#1c5980",
            text_color="#ffffff",
            text_color_disabled="#ffffff",
        )
        self.lbl_status.configure(text=f"Executing 3-Zone Route Trace to {target}...")
        self.tabs.set("  🗺️ 3-Zone Route & Fault Locator  ")

        self.last_hops = []

        def on_hop(h):
            self.after(0, self._handle_hop_update, h)

        def on_progress(cur, max_h):
            self.after(0, lambda: self.lbl_status.configure(text=f"Tracing route... Hop {cur}/{max_h}"))

        def on_complete(hops):
            self.after(0, self._handle_trace_complete, hops)

        self.tracer.trace(
            target_ip=target,
            max_hops=20,
            queries_per_hop=3,
            on_hop=on_hop,
            on_progress=on_progress,
            on_complete=on_complete,
        )

    def _handle_hop_update(self, h: Dict[str, Any]):
        self.last_hops.append(h)
        self.zone_view.add_hop(h)

    def _handle_trace_complete(self, hops: List[Dict[str, Any]]):
        self.btn_trace.configure(
            state="normal",
            text="🔍 Route Trace",
            fg_color="#2980b9",
            hover_color="#3498db",
            text_color="#ffffff",
        )
        self.lbl_status.configure(text=f"Route trace completed. {len(hops)} hops mapped.")
        self._run_analysis()

    def _open_comparison_viewer(self):
        """Opens the dedicated comparative test analysis dialog."""
        TestComparisonWindow(self)

    def _run_bufferbloat_test(self):
        """Opens the dedicated interactive Bufferbloat Evaluator."""
        target = self._get_target_ip()
        real_ip = self.last_detected_real_ip if self.last_detected_real_ip and self.last_detected_real_ip != target else "-"
        DiagnosticReporter.append_target_history(
            self.results_dir,
            ip=target,
            port=None,
            real_ip=real_ip,
            label="Bufferbloat Target",
        )
        bb_target = target
        if self.last_detected_transit_ip and (target == self.last_detected_real_ip):
            bb_target = self.last_detected_transit_ip
        BufferbloatWindow(self, target_ip=bb_target)

    def _run_analysis(self):
        target = self._get_target_ip()
        stream_stats = self.last_stream_stats or {
            "sent": 1, "received": 1, "lost": 0, "loss_pct": 0.0,
            "late_count": 0, "late_pct": 0.0, "late_threshold_ms": self._get_threshold(),
            "min_rtt": 0.0, "avg_rtt": 0.0, "max_rtt": 0.0, "mean_jitter": 0.0,
        }

        gw_res = self.icmp.ping(self.local_gateway, timeout_ms=500)
        gw_stats = {
            "avg_rtt": gw_res.get("rtt_ms", 0.0) if gw_res["success"] else 999.0,
            "mean_jitter": 0.5 if gw_res["success"] else 20.0,
            "loss_pct": 0.0 if gw_res["success"] else 100.0,
        }

        diag = ZoneAnalyzer.analyze(stream_stats, self.last_hops, gateway_stats=gw_stats)
        self.last_diagnosis = diag

        self.zone_view.update_diagnosis(diag.to_dict())
        short_verdict = diag.primary_fault_zone.replace("_", " ")
        self.dashboard.set_grade(diag.grade, short_verdict)

        report_text = DiagnosticReporter.generate_text_report(
            target=target,
            stream_stats=stream_stats,
            hops=self.last_hops,
            diagnosis_dict=diag.to_dict(),
            gateway_ip=self.local_gateway,
            protocol=self.last_test_protocol,
            real_server_ip=self.last_detected_real_ip,
        )
        self.txt_report.delete("1.0", "end")
        self.txt_report.insert("end", report_text)

    def _open_results_viewer(self):
        """Opens the full in-app Saved Results Browser window."""
        SavedResultsViewerWindow(self, results_dir=self.results_dir)

    def _open_manual_save_dialog(self):
        """Allows manual saving from the report tab if desired."""
        if not self.last_stream_stats and not self.last_hops:
            messagebox.showwarning("No Test Data", "Please run a stream test or route trace before saving.")
            return

        TestCompletionDialog(
            master=self,
            target_str=self._get_target_ip(),
            protocol=self.last_test_protocol,
            stats=self.last_stream_stats,
            diag=self.last_diagnosis,
            on_save_callback=self._execute_save_custom_result,
        )

    def _execute_save_custom_result(self, custom_name: str):
        target = self._get_target_ip()
        diag_dict = self.last_diagnosis.to_dict() if self.last_diagnosis else {}

        res = DiagnosticReporter.save_custom_result(
            results_dir=self.results_dir,
            custom_name=custom_name,
            target=target,
            stream_stats=self.last_stream_stats,
            hops=self.last_hops,
            diagnosis_dict=diag_dict,
            gateway_ip=self.local_gateway,
            protocol=self.last_test_protocol,
            real_server_ip=self.last_detected_real_ip,
        )

        messagebox.showinfo(
            "Result Saved Successfully",
            f"Test result saved with custom label '{custom_name}'.\n\n"
            f"Stored in:\n{res['txt_path']}\n{res['json_path']}"
        )
        self._refresh_history_list()

    def _refresh_history_list(self):
        """Loads and lists all saved results in the history tab."""
        results = DiagnosticReporter.list_saved_results(self.results_dir)
        self.txt_history.delete("1.0", "end")

        if not results:
            self.txt_history.insert(
                "end",
                "No saved results found yet in results/.\n\n"
                "Run a test and save your result to build your historical comparison log.\n"
            )
            return

        lines = [
            "=" * 84,
            f"                    SAVED RESULTS HISTORY ({len(results)} RUNS LOGGED)",
            "=" * 84,
            f"{'Timestamp':<20} {'Custom Test Label':<28} {'Target':<16} {'Avg RTT':<10} {'Jitter':<9} {'Grade'}",
            "-" * 84,
        ]

        for r in results:
            c_name = r.get("custom_name", "Unnamed")[:26]
            created = r.get("created_at", "")[:19]
            target = r.get("target", "")[:15]
            stats = r.get("stream_stats", {})
            diag = r.get("diagnosis", {})
            avg_str = f"{stats.get('avg_rtt', 0.0)}ms"
            jit_str = f"{stats.get('mean_jitter', 0.0)}ms"
            grade = diag.get("grade", "-")

            lines.append(f"{created:<20} {c_name:<28} {target:<16} {avg_str:<10} {jit_str:<9} {grade}")

        lines.extend([
            "",
            "-" * 84,
            "💡 Click 'Open Full Results Browser' or use the 'View Results' button to read full reports.",
            f"Folder Location: {self.results_dir}",
            "=" * 84,
        ])

        self.txt_history.insert("end", "\n".join(lines))

    def _copy_isp_ticket(self):
        if not self.last_diagnosis:
            messagebox.showwarning("No Data", "Please run a stream test or route trace first.")
            return

        target = self._get_target_ip()
        ticket_text = DiagnosticReporter.generate_isp_ticket_template(
            target=target,
            stream_stats=self.last_stream_stats,
            hops=self.last_hops,
            diagnosis_dict=self.last_diagnosis.to_dict(),
        )
        self.clipboard_clear()
        self.clipboard_append(ticket_text)
        messagebox.showinfo("Copied", "ISP Complaint ticket text copied to clipboard!")
