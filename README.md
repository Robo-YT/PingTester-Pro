# ⚡ Ping Tester & Gaming Network Diagnostics

A high-precision Windows network diagnostic utility engineered specifically for competitive online gaming. It isolates the exact physical root cause of latency spikes, micro-jitter, bufferbloat, and **"late-arriving packets"** that standard speed tests and default Windows `ping` completely overlook.

Includes **Live Match Server Auto-Detection for Apex Legends**, **Competitive Gaming Impact Engine (Hitreg & Desync Analysis)**, **3-Zone Fault Isolation (LAN vs ISP vs Server)**, **Interactive Bufferbloat Evaluator**, and **In-App Results History & Comparison**.

---

## 🌟 Key Features

* **🎮 Competitive Gaming Impact Engine:**
  - **Hit-Registration (No-Reg) Risk:** Quantifies ghost bullets caused by late packets crossing server rollback windows.
  - **Cover Desync Window:** Measures peak spike delta ($\text{Max} - \text{Min}$) to determine vulnerability to dying behind doors or walls.
  - **Action-to-Server Delay:** Calculates true end-to-end timing (Physical Network RTT + Tick Processing Buffer).
  - **Spike Frequency:** Pinpoints how frequently packet delivery anomalies disrupt live gameplay.

* **🔍 3-Zone Fault Domain Isolation:**
  - **Zone 1 (Home LAN):** Identifies local issues (Wi-Fi channel congestion, faulty Ethernet cables, local buffer bloat).
  - **Zone 2 (ISP Middle-Mile):** Pinpoints ISP gateway latency, CMTS/OLT drops, and carrier routing congestion.
  - **Zone 3 (Transit & Datacenter):** Tracks tier-1 transit routes, peering exchanges, and destination server edge nodes.

* **🎯 Live Apex Match Detection & Physical Route Probing:**
  - Automatically identifies active match servers and UDP game ports while in a match or the Firing Range.
  - Utilizes active edge gateway probing when AWS/EA match hosts drop ICMP echo requests, ensuring accurate physical latency measurements without artificial packet loss.

* **⚡ Real-Time Bufferbloat Evaluator:**
  - Sustained multi-threaded line saturation across Download and Upload directions.
  - Measures idle baseline latency vs active loaded latency.
  - Assigns official Bufferbloat grades (`A+` to `F`) according to ITU-T standards and provides actionable router SQM recommendations.

* **⚖️ Test Comparison Engine:**
  - Compare any two historical test runs side-by-side.
  - Provides objective metric deltas and algorithmic verdicts to verify if router tweaks, QoS/SQM settings, or ISP changes resolved connection problems.

* **📂 In-App Results Browser & One-Click ISP Complaint Tickets:**
  - View all past test runs inside the software.
  - Generates ready-to-submit, technically rigorous ISP support ticket text with full route traces and timestamped packet metrics.

---

## 🚀 How to Run

### Option 1: Standalone Executable (Recommended)
1. Extract the downloaded release package to any folder on your computer.
2. Double-click **`PingTester.exe`** to launch the application.
3. *(Optional)* For live Apex Legends UDP socket sniffing, right-click `PingTester.exe` and select **Run as Administrator**, or double-click `run_as_admin.bat`.

> **Note:** All diagnostic reports and test histories are automatically saved in a local `results\` folder created right next to `PingTester.exe`. No installation or external dependencies are required.

### Option 2: Running from Source (For Developers)
If you prefer running directly from Python source code:
1. Ensure Python 3.10+ is installed.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Launch GUI:
   ```bash
   python main.py
   ```
4. Or run headless in CLI mode:
   ```bash
   python main.py --cli --target 8.8.8.8 --count 50 --rate 20
   ```

---

## 🎮 How to Test Gaming Connections

### Testing During Live Gameplay:
1. Start your game (e.g., Apex Legends) and load into a match or the Firing Range.
2. Open Ping Tester and click **`🎯 Auto-Detect`**.
3. The software will detect the active match host IP and configure the optimal test parameters.
4. Click **`▶ Start Test`**. Observe the live latency graph, jitter distribution, and hitreg risk in real time.
5. Click **`💾 Save Result`** when finished to store the data for comparison.

### Evaluating Bufferbloat:
1. Click **`⚡ Bufferbloat`** on the main navigation bar.
2. Click **`▶ Start Bufferbloat Test`**.
3. The evaluator will measure idle latency, saturate the download and upload pipes, and provide an actionable grade (`A+` through `F`).

### Comparing Before & After:
1. Click **`⚖️ Compare`** on the top toolbar.
2. Select Test 1 (Baseline) and Test 2 (After optimization).
3. Review the side-by-side performance delta and algorithmic verdict.

---

## 📊 Understanding Network Quality Grades

| Grade | Avg RTT | Jitter | Late Spikes | Gaming Suitability |
| :---: | :---: | :---: | :---: | :--- |
| **A+** | < 35 ms | < 2 ms | 0% | Tournament / Esports Grade. Perfect hit registration. |
| **A** | < 60 ms | < 4 ms | < 1% | Optimal. Responsive gameplay with negligible desync. |
| **B** | < 90 ms | < 8 ms | < 3% | Good. Minor compensation on high-tick competitive servers. |
| **C** | < 120 ms | < 15 ms | < 8% | Fair. Noticeable peekers advantage and occasional no-regs. |
| **D / F** | > 120 ms | > 15 ms | > 8% | Poor. Heavy desync, rubberbanding, and dying behind cover. |

---

## 🛡️ Privacy & Security

* **100% Anti-Cheat Safe:** Does not inject code, hook game memory, or read game processes. Only standard Windows networking APIs and passive socket inspection are used.
* **Completely Private:** All logs, telemetry, and test results are stored locally on your machine in the `results\` folder. No data is sent to external cloud servers.

---

## 🛠️ Building from Source

To compile a standalone binary for distribution:
```cmd
build_exe.bat
```
The compiled application will be generated in `dist\PingTester\`.
