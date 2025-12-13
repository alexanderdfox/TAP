# Network Flow Entropy Monitor

A real-time network packet capture and entropy analysis tool with a beautiful web-based dashboard.

## ⚠️ LEGAL WARNING

**IMPORTANT: READ THIS BEFORE USING THIS SOFTWARE**

### United States Federal Law (18 U.S.C. § 2511)

The interception of electronic communications is generally **PROHIBITED** under federal wiretap laws. This software captures network traffic, which may be considered illegal interception in many circumstances.

#### Legal Requirements:

1. **Authorization Required**: You may ONLY monitor networks that you:
   - Own completely, OR
   - Have explicit written authorization to monitor

2. **Your Own Network**: Monitoring traffic on networks you own is generally legal, but you must:
   - Ensure you have the legal right to monitor
   - Comply with all applicable laws and regulations
   - Respect privacy expectations

3. **Unauthorized Monitoring is Illegal**: 
   - Monitoring networks you don't own without authorization is a **FEDERAL CRIME**
   - Penalties can include fines and imprisonment
   - Civil liability may also apply

### State Laws

Many states have additional laws regarding electronic surveillance:

- **All-Party Consent States**: Some states (e.g., California, Florida, Massachusetts) require consent from ALL parties to a communication
- **One-Party Consent States**: Other states allow monitoring if at least one party consents
- **State laws may be more restrictive than federal law**

### Best Practices

1. ✅ **Only use on networks you own or have explicit permission to monitor**
2. ✅ **Obtain written authorization before monitoring any network**
3. ✅ **Respect privacy and confidentiality**
4. ✅ **Comply with your organization's security policies**
5. ✅ **Consult with legal counsel if unsure about legality**
6. ❌ **NEVER monitor networks without authorization**
7. ❌ **NEVER intercept communications you're not authorized to access**

### Disclaimer

**THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.**

By using this software, you acknowledge that:
- You have read and understood the legal warnings above
- You will only use this tool on networks you own or have authorization to monitor
- You understand that unauthorized network monitoring may be illegal
- You accept full legal responsibility for your use of this tool
- The authors and contributors are not responsible for any misuse or legal consequences

**USE AT YOUR OWN RISK. THE AUTHORS ASSUME NO LIABILITY FOR ILLEGAL USE OF THIS SOFTWARE.**

## Features

- 🌐 **Real-time Network Monitoring**: Capture and analyze network traffic in real-time
- 📊 **Entropy Analysis**: Calculate Shannon entropy for network flows to detect anomalies
- 🚨 **Anomaly Detection**: Automatic alerts for entropy spikes and drops (possible network anomalies)
- 📈 **Interactive Dashboard**: Beautiful dark-themed web interface with real-time charts
- 🔍 **Flow Filtering**: Filter by protocol, search by IP, and select top N flows
- 💾 **Logging**: Automatic CSV logging of all entropy data
- 📥 **Download Logs**: Download and analyze historical data
- 🎨 **Modern UI**: Dark theme with glassmorphism design
- ⚡ **Performance**: Efficient packet capture and processing

## Requirements

- Python 3.7+
- Root/Administrator privileges (for packet capture)
- Required Python packages:
  - `scapy`
  - `aiohttp`

## Installation

1. Clone or download this repository

2. Install dependencies:
```bash
pip3 install scapy aiohttp
```

3. Run with sudo (required for packet capture):
```bash
sudo python3 tap.py
```

## Usage

1. **Start the server**:
   ```bash
   sudo python3 tap.py
   ```

2. **Open the dashboard**:
   - Navigate to `http://localhost:8080/` in your browser
   - Accept the legal warning (first time only)

3. **Select network interface**:
   - Choose an interface from the dropdown
   - Click "Start Capture" to begin monitoring

4. **Monitor flows**:
   - View real-time entropy graphs for each flow
   - Use filters to focus on specific flows
   - Watch for anomaly alerts

5. **Download logs**:
   - All data is automatically logged to CSV files
   - Download logs from the dashboard

6. **Stop capture**:
   - Click "Stop Capture" to pause monitoring
   - Click "Quit Server" to shut down the application

## Network Interfaces

The tool automatically detects available network interfaces on your system. Physical interfaces (en0, eth0, wlan0, etc.) are prioritized over virtual interfaces.

## Log Files

Log files are saved in the `data/` directory with the format:
```
entropy_log_{interface}_{timestamp}.csv
```

Each log file contains:
- Timestamp
- Network interface
- Flow information
- Entropy values
- Alert information (when anomalies detected)

## Configuration

- **MAX_FLOW_LEN**: Maximum number of packets per flow (default: 100)
- **ENTROPY_REFRESH**: Update interval in seconds (default: 1)
- **ALERT_THRESHOLD_RATIO**: Entropy change threshold for alerts (default: 0.5 = 50%)

## Troubleshooting

### Permission Denied
- Make sure you're running with `sudo` or as administrator
- Packet capture requires elevated privileges

### Port Already in Use
- The server will automatically try ports 8080-8089
- Or manually kill the process using the port

### No Network Data
- Ensure you've selected a network interface
- Check that the interface is active and receiving traffic
- Verify you have permission to capture on that interface

## Security Notes

- This tool requires root/administrator privileges
- Only use on networks you own or have authorization to monitor
- Log files may contain sensitive network information
- Secure log files appropriately

## License

This software is provided for educational and authorized network monitoring purposes only. See the LEGAL WARNING section above.

## Contributing

Contributions are welcome, but please ensure:
- All code changes maintain legal compliance
- Documentation is updated
- Legal warnings are preserved

## Support

For issues, questions, or concerns:
1. Check the troubleshooting section
2. Review the legal warnings
3. Consult with legal counsel for authorization questions

---

**Remember: Unauthorized network monitoring is illegal. Use responsibly and only on networks you own or have explicit permission to monitor.**

