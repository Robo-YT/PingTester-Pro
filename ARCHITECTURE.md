# 🏗️ Architecture & Technical Specification

## 1. System Overview

**Ping Tester** is engineered to measure microsecond-precision network latency, packet timing distributions, and route stability on Windows systems without requiring administrative privileges.

```
Ping Tester
├── core/
│   ├── win32_icmp.py     # Native 64-bit Windows ICMP engine via Win32 Iphlpapi.dll
│   ├── ping_engine.py    # Multi-tick stream prober (1Hz - 60Hz) with duration & count limiters
│   ├── udp_engine.py     # Direct UDP probing engine with gaming port query payloads
│   ├── apex_detector.py  # Match socket resolver with real match IP auto-fill
│   ├── route_tracer.py   # High-speed native TTL route discovery and hop variance analyzer
│   ├── zone_analyzer.py  # 3-Zone fault isolation heuristic (Local vs Middle-Mile vs Transit)
│   ├── bufferbloat.py    # Active load vs idle baseline latency evaluator
│   ├── passive_sniffer.py# Live in-game netcode sniffer for real match latency
│   └── reporter.py       # Plain text, JSON, and ISP complaint ticket formatter
└── ui/
    ├── app.py            # Main CustomTkinter window, SavedResultsViewerWindow, controllers
    └── components/
        ├── live_graph.py     # 60 FPS Canvas-based real-time latency plot with threshold marker
        ├── stats_cards.py    # High-level metric cards (RTT, Jitter, Late %, Loss %, Grade)
        └── zone_view.py      # Visual 3-zone status pills and route hop table
```

---

## 2. In-App Results Browser (`SavedResultsViewerWindow`)

* **Dual-Pane Interactive Viewer:**
  - `Treeview`: Lists historical runs with timestamps, names, target IPs, protocols, and grades.
  - `CTkTextbox`: Dynamically loads and renders full `.txt` report files upon row selection.
* **Management Controls:**
  - Clipboard export, selective file deletion, and direct Windows Explorer folder launching.
