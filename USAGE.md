# Network Flow Entropy Monitor - Usage Guide

This guide will walk you through using the Network Flow Entropy Monitor from installation to advanced features.

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Dashboard Overview](#dashboard-overview)
4. [Starting Packet Capture](#starting-packet-capture)
5. [Understanding Entropy](#understanding-entropy)
6. [Using Filters](#using-filters)
7. [Viewing Alerts](#viewing-alerts)
8. [Working with Logs](#working-with-logs)
9. [Stopping and Quitting](#stopping-and-quitting)
10. [Troubleshooting](#troubleshooting)
11. [Advanced Usage](#advanced-usage)

---

## Installation

### Prerequisites

- Python 3.7 or higher
- Root/Administrator privileges (required for packet capture)
- Network interface with active traffic

### Step 1: Install Dependencies

```bash
pip3 install scapy aiohttp
```

Or if you need to install for all users:

```bash
sudo pip3 install scapy aiohttp
```

### Step 2: Verify Installation

Check that Python and required packages are installed:

```bash
python3 --version
python3 -c "import scapy; import aiohttp; print('All dependencies installed')"
```

---

## Quick Start

### 1. Start the Server

**Important**: You must run with `sudo` (or as Administrator on Windows) to capture packets:

```bash
sudo python3 tap.py
```

You should see output like:

```
Available network interfaces: en0 (10.31.3.23), en1, en2, ...
Waiting for interface selection before starting capture...
Please select an interface in the dashboard to begin packet capture.

============================================================
Hammer4D Demon dashboard running at http://0.0.0.0:8080/
WebSocket endpoint: ws://0.0.0.0:8080/ws
============================================================
⚠️  IMPORTANT: Select a network interface in the dashboard
   to start packet capture. Capture will not start automatically.
============================================================
```

### 2. Open the Dashboard

Open your web browser and navigate to:

```
http://localhost:8080
```

Or if accessing from another machine:

```
http://YOUR_SERVER_IP:8080
```

### 3. Accept Legal Warning

On first visit, you'll see a legal warning modal. **Read it carefully** and click:

- **"I Understand and Accept"** - to proceed (warning won't show again)
- **"Decline & Exit"** - to close the page

### 4. Select Network Interface

1. In the dashboard header, find the **"Network Interface"** dropdown
2. Select an interface (e.g., `en0 (10.31.3.23)`)
3. Click **"Start Capture"** button
4. Wait a few seconds for flows to appear

### 5. Monitor Flows

You should now see:
- Real-time entropy graphs for each flow
- Current entropy values
- Any anomaly alerts

---

## Dashboard Overview

### Header Section

The top header contains all controls:

- **Top N Flows**: Select how many flows to display (5, 10, 20, 50, or All)
- **Filter by Protocol**: Filter flows by TCP, UDP, or All
- **Search Flow**: Search for specific IP addresses
- **Network Interface**: Select and start/stop capture
- **Start/Stop Capture**: Control packet capture
- **Quit Server**: Shut down the application
- **Status Indicator**: Shows connection status (green = connected, red = disconnected)

### Alerts Section

Appears automatically when anomalies are detected:
- **Yellow alerts**: Entropy spikes (sudden increase)
- **Red alerts**: Entropy drops (sudden decrease)
- Shows flow name, entropy value, and percentage change

### Charts Grid

Each flow gets its own card showing:
- **Flow name**: Source IP → Destination IP (Protocol)
- **Current entropy value**: Large number at top right
- **Real-time graph**: Line chart showing entropy over time
- **Last 50 data points**: Automatically updated every second

### Logs Section

Shows all available log files:
- **Filename**: Name of the log file
- **Size**: File size in KB
- **Modified**: Last modification date/time
- **Download button**: Download the CSV log file

---

## Starting Packet Capture

### Method 1: Using the Dashboard (Recommended)

1. Select a network interface from the dropdown
2. Click **"Start Capture"** button
3. The interface dropdown will be disabled
4. **"Stop Capture"** button will appear
5. Flows will start appearing in the charts grid

### Method 2: Understanding Interface Selection

**Physical Interfaces** (recommended):
- `en0`, `en1`, `en2` - Ethernet interfaces (macOS)
- `eth0`, `eth1` - Ethernet interfaces (Linux)
- `wlan0`, `wlan1` - Wireless interfaces (Linux)

**Virtual Interfaces** (usually less useful):
- `utun0`, `utun1` - Tunnel interfaces
- `awdl0` - Apple Wireless Direct Link
- `bridge0` - Bridge interfaces

**Tip**: Choose an interface with an IP address (shown in parentheses) for best results.

### What Happens When You Start Capture

1. Packet capture begins on the selected interface
2. Log file is created in `data/` directory
3. Flows are identified and tracked
4. Entropy is calculated every second
5. Data is sent to dashboard via WebSocket
6. Charts update in real-time

---

## Understanding Entropy

### What is Entropy?

**Shannon Entropy** measures the randomness or unpredictability in data. In network monitoring:

- **High Entropy**: More random/unpredictable patterns
- **Low Entropy**: More regular/predictable patterns

### What Your Tool Calculates

The tool calculates entropy based on **packet inter-arrival times**:
- Measures time between consecutive packets in a flow
- Calculates how random these intervals are
- Higher entropy = more irregular timing
- Lower entropy = more regular timing

### Interpreting Entropy Values

- **0.0 - 2.0**: Very regular patterns (low randomness)
- **2.0 - 4.0**: Moderate randomness
- **4.0 - 6.0**: High randomness
- **6.0+**: Very high randomness (unpredictable)

### What Entropy Tells You

**Normal Traffic**:
- Consistent entropy values
- Gradual changes over time
- Predictable patterns

**Anomalous Traffic** (alerts triggered):
- **Spikes**: Sudden increase in entropy
  - Possible causes: DDoS, scanning, data exfiltration
- **Drops**: Sudden decrease in entropy
  - Possible causes: Connection issues, rate limiting, filtering

---

## Using Filters

### Top N Flows Filter

**Purpose**: Limit the number of flows displayed

**How to use**:
1. Select a number from the "Top N Flows" dropdown
2. Flows are sorted by current entropy (highest first)
3. Only the top N flows are shown

**Use cases**:
- Focus on most active flows
- Reduce visual clutter
- Compare top performers

### Protocol Filter

**Purpose**: Filter flows by network protocol

**Options**:
- **All Protocols**: Show TCP, UDP, and others
- **TCP**: Only Transmission Control Protocol flows
- **UDP**: Only User Datagram Protocol flows

**Use cases**:
- Analyze specific protocol behavior
- Compare TCP vs UDP entropy patterns
- Focus on protocol-specific issues

### Search Filter

**Purpose**: Find specific flows by IP address

**How to use**:
1. Type an IP address in the "Search Flow" box
2. Only flows containing that IP are shown
3. Works with source or destination IPs
4. Case-insensitive partial matching

**Examples**:
- `192.168.1.1` - Find all flows involving this IP
- `10.0` - Find all flows with IPs starting with 10.0
- `google` - Won't work (only searches IPs, not hostnames)

**Use cases**:
- Monitor specific servers
- Track suspicious IPs
- Analyze client-server communication

### Combining Filters

All filters work together:
- Select "Top 10" + "TCP" + search "192.168" = Top 10 TCP flows involving 192.168.x.x

---

## Viewing Alerts

### When Alerts Appear

Alerts are automatically generated when:
- Entropy changes by more than 50% compared to recent average
- This indicates a significant pattern change

### Alert Types

**SPIKE (Yellow Alert)**:
- Entropy suddenly increased
- Possible causes:
  - DDoS attack
  - Port scanning
  - Data exfiltration
  - Network congestion

**DROP (Red Alert)**:
- Entropy suddenly decreased
- Possible causes:
  - Connection issues
  - Rate limiting
  - Firewall blocking
  - Service degradation

### Alert Information

Each alert shows:
- **Flow**: Which flow triggered the alert
- **Type**: SPIKE or DROP
- **Entropy**: Current entropy value
- **Change**: Percentage change from previous average

### Alert Behavior

- Alerts appear in real-time
- They persist until new data replaces them
- Multiple alerts can appear simultaneously
- Alerts are logged in CSV files

---

## Working with Logs

### Automatic Logging

When you start capture:
- A log file is automatically created
- Located in the `data/` directory
- Filename format: `entropy_log_{interface}_{timestamp}.csv`
- Example: `entropy_log_en0_20251213_121106.csv`

### Log File Contents

Each CSV file contains:
- **timestamp**: Date and time of the entry
- **interface**: Network interface name
- **flow**: Flow identifier (source→destination (protocol))
- **entropy**: Entropy value
- **alert_type**: SPIKE, DROP, or empty
- **alert_change**: Percentage change if alert occurred

### Viewing Logs in Dashboard

1. Scroll to the "Log Files" section
2. See all available log files
3. Each entry shows:
   - Filename
   - File size
   - Last modified date
4. Click **"Refresh"** to reload the list

### Downloading Logs

1. Find the log file you want
2. Click the **"Download"** button
3. File will download to your default download location
4. Open in Excel, Python, or any CSV viewer

### Analyzing Logs

**In Excel/Google Sheets**:
- Import CSV
- Create pivot tables
- Generate charts
- Filter by alert type

**In Python**:
```python
import pandas as pd
df = pd.read_csv('entropy_log_en0_20251213_121106.csv')
# Analyze data
print(df.describe())
print(df[df['alert_type'] != ''].head())
```

**In Command Line**:
```bash
# Count alerts
grep -c "SPIKE\|DROP" data/entropy_log_*.csv

# Find flows with highest entropy
sort -t, -k4 -rn data/entropy_log_*.csv | head
```

---

## Stopping and Quitting

### Stop Capture

**Method 1: Dashboard Button**
1. Click **"Stop Capture"** button
2. Packet capture stops
3. Interface dropdown re-enables
4. Charts remain visible (but won't update)
5. Log file is closed

**Method 2: Change Interface**
- Selecting a new interface automatically stops current capture
- Starts new capture on new interface
- Previous flows are cleared

### Quit Server

**Method 1: Dashboard Button**
1. Click **"Quit Server"** button
2. Confirm the dialog
3. Server shuts down gracefully
4. Page will close automatically

**Method 2: Keyboard Interrupt**
1. In the terminal, press `Ctrl+C`
2. Server performs cleanup
3. All tasks are cancelled
4. Log files are closed
5. Server exits

### What Happens on Quit

1. Packet capture stops
2. Log file is closed and saved
3. All background tasks are cancelled
4. Web server shuts down
5. Clean exit (no errors)

---

## Troubleshooting

### Problem: "Permission denied" error

**Solution**: Run with `sudo`
```bash
sudo python3 tap.py
```

### Problem: No flows appearing

**Possible causes**:
1. No network traffic on selected interface
   - **Solution**: Generate some traffic (browse web, ping, etc.)
2. Wrong interface selected
   - **Solution**: Try a different interface
3. Firewall blocking packets
   - **Solution**: Check firewall settings

### Problem: Dashboard not loading

**Check**:
1. Server is running (check terminal)
2. Correct URL: `http://localhost:8080`
3. Port not blocked by firewall
4. Browser console for errors (F12)

### Problem: "Port already in use"

**Solution**: The server will automatically try ports 8080-8089. If all are busy:
```bash
# Find what's using the port
lsof -i :8080

# Kill the process (replace PID)
kill -9 PID
```

### Problem: High CPU usage

**Possible causes**:
1. Too many active flows
   - **Solution**: Use "Top N Flows" filter
2. High network traffic
   - **Solution**: This is normal, tool is processing packets

### Problem: WebSocket disconnects

**Symptoms**: Status shows "Disconnected"
**Solution**: 
- Check server is still running
- Refresh the page
- Check network connection
- Server will auto-reconnect

### Problem: No IP address shown for interface

**This is normal** for:
- Virtual interfaces (utun, awdl, etc.)
- Inactive interfaces
- Interfaces without IP configuration

**Solution**: Use physical interfaces (en0, eth0, wlan0) for best results

---

## Advanced Usage

### Running in Background

**Linux/macOS**:
```bash
# Run in background
sudo nohup python3 tap.py > tap.log 2>&1 &

# Check if running
ps aux | grep tap.py

# Stop it
pkill -f tap.py
```

### Accessing from Remote Machine

1. Start server (it binds to `0.0.0.0` by default)
2. Find server IP address:
   ```bash
   # Linux/macOS
   ifconfig | grep "inet "
   
   # Or
   ip addr show
   ```
3. Access from another machine:
   ```
   http://SERVER_IP:8080
   ```
4. **Security Note**: No authentication by default - use firewall rules

### Customizing Configuration

**Edit `tap.py` to change**:
- `MAX_FLOW_LEN = 100` - Maximum packets per flow
- `ENTROPY_REFRESH = 1` - Update interval (seconds)
- `ALERT_THRESHOLD_RATIO = 0.5` - Alert threshold (50% change)

### Analyzing Log Files

**Find anomalies**:
```bash
# Count alerts per flow
awk -F',' '$5 != "" {print $3}' data/*.csv | sort | uniq -c | sort -rn

# Average entropy per flow
awk -F',' '{sum[$3]+=$4; count[$3]++} END {for (i in sum) print i, sum[i]/count[i]}' data/*.csv
```

### Performance Tips

1. **Limit displayed flows**: Use "Top N" filter
2. **Filter by protocol**: Reduces processing
3. **Close unused browser tabs**: Reduces WebSocket connections
4. **Use SSD for data directory**: Faster log writes

### Best Practices

1. **Start with your own network**: Test on networks you own
2. **Monitor during normal operations**: Establish baseline
3. **Review alerts regularly**: Investigate anomalies
4. **Archive old logs**: Keep storage manageable
5. **Document findings**: Note what's normal vs abnormal

---

## Keyboard Shortcuts

Currently, the dashboard doesn't have keyboard shortcuts, but you can:
- Use browser shortcuts:
  - `Ctrl+R` / `Cmd+R`: Refresh page
  - `Ctrl+F` / `Cmd+F`: Find in page
  - `F12`: Open developer console

---

## Tips and Tricks

### Tip 1: Establish Baseline
Run the tool during normal operations to understand typical entropy patterns for your network.

### Tip 2: Compare Time Periods
Download logs from different time periods and compare entropy patterns to identify trends.

### Tip 3: Focus on Alerts
Use the alerts section to quickly identify flows that need attention.

### Tip 4: Use Filters Strategically
- Start with "Top 10" to see most active flows
- Filter by protocol to analyze specific traffic types
- Search for specific IPs when investigating issues

### Tip 5: Monitor Multiple Sessions
Run multiple instances on different interfaces (if you have multiple network cards) by changing the port in code.

---

## Getting Help

If you encounter issues:

1. Check the **Troubleshooting** section above
2. Review terminal output for error messages
3. Check browser console (F12) for JavaScript errors
4. Verify all dependencies are installed
5. Ensure you have proper permissions (sudo)

---

## Next Steps

- Read `README.md` for feature overview
- Check `IDEAS.md` for future improvements
- Experiment with different network scenarios
- Analyze your log files to understand patterns

---

**Remember**: Always use this tool responsibly and only on networks you own or have authorization to monitor!

