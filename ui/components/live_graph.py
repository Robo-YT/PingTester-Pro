"""
High-Performance Canvas-Based Live Latency & Jitter Graph with Full Timeline Scroller.
Renders real-time packet timings, gridlines, late-packet threshold indicators,
and supports horizontal scrolling across long test runs (e.g., 30-minute tests)
while continuing live background collection.
"""

import tkinter as tk
import customtkinter as ctk
from typing import List, Dict, Any, Optional


class LiveLatencyGraph(ctk.CTkFrame):
    """
    Interactive real-time latency graph with horizontal timeline scrolling.
    Supports continuous 30+ minute testing with live tracking and historical scrubbing.
    """

    def __init__(
        self,
        master,
        width: int = 600,
        height: int = 220,
        visible_points: int = 90,
        late_threshold_ms: float = 130.0,
        **kwargs,
    ):
        super().__init__(master, fg_color="#181a20", corner_radius=6, **kwargs)

        self.visible_points = visible_points
        self.late_threshold_ms = late_threshold_ms
        self.history: List[Dict[str, Any]] = []
        self.start_index: int = 0
        self.follow_tail: bool = True
        self._drag_start_x: Optional[int] = None
        self._drag_start_idx: int = 0

        # Colors
        self.c_bg = "#181a20"
        self.c_grid = "#282c37"
        self.c_grid_text = "#687082"
        self.c_normal_line = "#00d26a"
        self.c_normal_dot = "#00f078"
        self.c_late_line = "#f9822c"
        self.c_late_dot = "#ff4757"
        self.c_threshold_line = "#e84118"
        self.c_loss_marker = "#ff3838"

        # 1. Top Mini-Header (Status & Jump to Live button)
        self.top_bar = ctk.CTkFrame(self, fg_color="transparent", height=24)
        self.top_bar.pack(fill="x", padx=6, pady=(4, 0))

        self.lbl_info = ctk.CTkLabel(
            self.top_bar,
            text="● Live Packet Stream (Ready)",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color="#00cec9",
        )
        self.lbl_info.pack(side="left", padx=4)

        self.btn_jump_live = ctk.CTkButton(
            self.top_bar,
            text="⏩ Jump to Live",
            width=90,
            height=20,
            fg_color="#0984e3",
            hover_color="#0873c4",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=9, weight="bold"),
            command=self.jump_to_live,
        )
        # Hidden by default in live mode

        # 2. Main Canvas Plot
        self.canvas = tk.Canvas(
            self,
            width=width,
            height=height,
            bg=self.c_bg,
            highlightthickness=0,
        )
        self.canvas.pack(fill="both", expand=True, padx=4, pady=2)

        # 3. Bottom Horizontal Scrollbar
        self.scrollbar = ctk.CTkScrollbar(
            self,
            orientation="horizontal",
            height=12,
            corner_radius=6,
            command=self._on_scrollbar_scroll,
        )
        self.scrollbar.pack(fill="x", padx=6, pady=(0, 4))
        self.scrollbar.set(0.0, 1.0)

        # Event Bindings
        self.canvas.bind("<Configure>", lambda e: self.redraw())
        self.canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind("<Shift-MouseWheel>", self._on_mousewheel)
        self.canvas.bind("<ButtonPress-1>", self._on_drag_start)
        self.canvas.bind("<B1-Motion>", self._on_drag_motion)
        self.canvas.bind("<Double-Button-1>", lambda e: self.jump_to_live())

    def set_late_threshold(self, threshold_ms: float):
        self.late_threshold_ms = max(10.0, threshold_ms)
        self.redraw()

    def add_packet(self, rtt_ms: Optional[float], is_late: bool, success: bool):
        self.history.append({
            "rtt": rtt_ms,
            "is_late": is_late,
            "success": success,
        })
        # Keep generous buffer (up to 120,000 packets ~ 100 minutes at 20Hz)
        if len(self.history) > 120000:
            self.history.pop(0)

        if self.follow_tail:
            self.start_index = max(0, len(self.history) - self.visible_points)

        self._update_scrollbar()
        self._update_info_label()
        self.redraw()

    def clear(self):
        self.history.clear()
        self.start_index = 0
        self.follow_tail = True
        self.btn_jump_live.pack_forget()
        self._update_scrollbar()
        self._update_info_label()
        self.redraw()

    def jump_to_live(self):
        self.follow_tail = True
        self.start_index = max(0, len(self.history) - self.visible_points)
        self.btn_jump_live.pack_forget()
        self._update_scrollbar()
        self._update_info_label()
        self.redraw()

    def _update_info_label(self):
        total = len(self.history)
        if total == 0:
            self.lbl_info.configure(text="● Live Packet Stream (Ready)", text_color="#00cec9")
            return

        if self.follow_tail:
            self.lbl_info.configure(
                text=f"● LIVE • Showing latest {min(total, self.visible_points)} of {total:,} packets",
                text_color="#00d26a",
            )
            self.btn_jump_live.pack_forget()
        else:
            end_idx = min(total, self.start_index + self.visible_points)
            self.lbl_info.configure(
                text=f"⏸ PAUSED (Scrolled) • Viewing #{self.start_index + 1:,} - #{end_idx:,} of {total:,}",
                text_color="#fbc531",
            )
            self.btn_jump_live.pack(side="right", padx=4)

    def _update_scrollbar(self):
        total = len(self.history)
        if total <= self.visible_points:
            self.scrollbar.set(0.0, 1.0)
            return

        left = self.start_index / total
        right = min(1.0, (self.start_index + self.visible_points) / total)
        self.scrollbar.set(left, right)

    def _on_scrollbar_scroll(self, action, *args):
        total = len(self.history)
        if total <= self.visible_points:
            return

        max_start = max(0, total - self.visible_points)
        if action == "moveto":
            frac = float(args[0])
            self.start_index = max(0, min(max_start, int(frac * total)))
        elif action == "scroll":
            delta = int(args[0])
            step = 10 if args[1] == "units" else 40
            self.start_index = max(0, min(max_start, self.start_index + delta * step))

        # Check if snapped back to live end
        if self.start_index >= (max_start - 1):
            self.follow_tail = True
        else:
            self.follow_tail = False

        self._update_scrollbar()
        self._update_info_label()
        self.redraw()

    def _on_mousewheel(self, event):
        total = len(self.history)
        if total <= self.visible_points:
            return

        max_start = max(0, total - self.visible_points)
        # On Windows event.delta is typically +/- 120
        delta = -1 if event.delta > 0 else 1
        self.start_index = max(0, min(max_start, self.start_index + delta * 8))

        if self.start_index >= (max_start - 1):
            self.follow_tail = True
        else:
            self.follow_tail = False

        self._update_scrollbar()
        self._update_info_label()
        self.redraw()

    def _on_drag_start(self, event):
        self._drag_start_x = event.x
        self._drag_start_idx = self.start_index

    def _on_drag_motion(self, event):
        if self._drag_start_x is None:
            return
        dx = event.x - self._drag_start_x
        w = max(100, self.canvas.winfo_width())
        total = len(self.history)
        if total <= self.visible_points:
            return

        # Convert dx pixel drag to index offset
        pts_per_pixel = self.visible_points / w
        idx_delta = -int(dx * pts_per_pixel * 1.5)

        max_start = max(0, total - self.visible_points)
        self.start_index = max(0, min(max_start, self._drag_start_idx + idx_delta))

        if self.start_index >= (max_start - 1):
            self.follow_tail = True
        else:
            self.follow_tail = False

        self._update_scrollbar()
        self._update_info_label()
        self.redraw()

    def redraw(self):
        self.canvas.delete("all")
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 50 or h < 50:
            return

        pad_left = 50
        pad_right = 20
        pad_top = 22
        pad_bottom = 25
        plot_w = w - pad_left - pad_right
        plot_h = h - pad_top - pad_bottom

        # Get current slice to draw
        total = len(self.history)
        if total == 0:
            # Draw empty guide
            self.canvas.create_text(
                w / 2, h / 2,
                text="Waiting for stream test packets... (Click '▶ Start Test')",
                fill="#636e72",
                font=("Segoe UI", 10),
            )
            return

        sub_slice = self.history[self.start_index : self.start_index + self.visible_points]

        # Determine scale max based on currently visible points + late threshold
        valid_rtts = [p["rtt"] for p in sub_slice if p["success"] and p["rtt"] is not None]
        highest_rtt = max(valid_rtts) if valid_rtts else 50.0
        scale_max = max(highest_rtt * 1.15, self.late_threshold_ms * 1.25, 60.0)

        # 1. Draw Grid Lines
        grid_steps = 4
        for i in range(grid_steps + 1):
            val = (scale_max / grid_steps) * i
            y = pad_top + plot_h - (val / scale_max) * plot_h
            self.canvas.create_line(pad_left, y, w - pad_right, y, fill=self.c_grid, dash=(2, 4))
            self.canvas.create_text(
                pad_left - 8,
                y,
                text=f"{int(val)}ms",
                fill=self.c_grid_text,
                font=("Segoe UI", 8),
                anchor="e",
            )

        # 2. Draw Threshold Line
        y_thresh = pad_top + plot_h - (self.late_threshold_ms / scale_max) * plot_h
        if pad_top <= y_thresh <= (pad_top + plot_h):
            self.canvas.create_line(
                pad_left,
                y_thresh,
                w - pad_right,
                y_thresh,
                fill=self.c_threshold_line,
                dash=(4, 3),
                width=1,
            )
            self.canvas.create_text(
                w - pad_right - 4,
                y_thresh - 8,
                text=f"Late Limit ({int(self.late_threshold_ms)}ms)",
                fill=self.c_threshold_line,
                font=("Segoe UI", 8, "bold"),
                anchor="e",
            )

        # 3. Draw Plot Line & Markers
        if len(sub_slice) < 2:
            return

        step_x = plot_w / max(1, self.visible_points - 1)
        points = []
        for idx, pt in enumerate(sub_slice):
            x = pad_left + idx * step_x
            if pt["success"] and pt["rtt"] is not None:
                y = pad_top + plot_h - (pt["rtt"] / scale_max) * plot_h
                y = max(pad_top, min(pad_top + plot_h, y))
                points.append((x, y, pt))
            else:
                # Dropped packet marker at baseline
                y_drop = pad_top + plot_h
                self.canvas.create_text(x, y_drop - 8, text="X", fill=self.c_loss_marker, font=("Segoe UI", 9, "bold"))

        # Draw line segments
        for i in range(len(points) - 1):
            x1, y1, p1 = points[i]
            x2, y2, p2 = points[i + 1]
            line_color = self.c_late_line if (p2["is_late"] or p1["is_late"]) else self.c_normal_line
            self.canvas.create_line(x1, y1, x2, y2, fill=line_color, width=2, smooth=True)

        # Draw dots
        for x, y, pt in points:
            dot_color = self.c_late_dot if pt["is_late"] else self.c_normal_dot
            r = 3.5 if pt["is_late"] else 2.5
            self.canvas.create_oval(x - r, y - r, x + r, y + r, fill=dot_color, outline="")
