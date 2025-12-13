import asyncio
import time
import math
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, get_if_list, get_if_addr
from aiohttp import web
from aiohttp.web_runner import GracefulExit
import json
import os
import platform
import socket
from datetime import datetime
import csv
import signal
import sys

flows = defaultdict(list)
flow_entropy_history = defaultdict(lambda: deque(maxlen=100))  # Store entropy history per flow
MAX_FLOW_LEN = 100
ENTROPY_REFRESH = 1  # seconds
websocket_clients = set()
ALERT_THRESHOLD_RATIO = 0.5  # Alert if entropy changes by more than 50%
current_interface = None
sniff_task = None
log_file = None
log_writer = None
log_csv_file = None
shutdown_flag = False

# Create data directory if it doesn't exist
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
os.makedirs(DATA_DIR, exist_ok=True)

# Calculate Shannon entropy
def entropy(values):
	if not values:
		return 0.0
	total = sum(values)
	if total == 0:
		return 0.0
	probs = [v / total for v in values if v > 0]
	return -sum(p * math.log2(p) for p in probs)

# Process incoming packets
def process(pkt):
	now = time.time()
	key = None
	if IP in pkt:
		ip = pkt[IP]
		proto = None
		if TCP in pkt:
			proto = "TCP"
		elif UDP in pkt:
			proto = "UDP"
		else:
			proto = str(ip.proto)
		key = (ip.src, ip.dst, proto)
	if key:
		flows[key].append(now)
		if len(flows[key]) > MAX_FLOW_LEN:
			flows[key] = flows[key][-MAX_FLOW_LEN:]

# Get IP address for an interface
def get_interface_ip(iface):
	"""Get IP address for a network interface"""
	try:
		# Try using scapy's get_if_addr
		ip = get_if_addr(iface)
		if ip and ip != '0.0.0.0':
			return ip
	except Exception:
		pass
	
	try:
		# Fallback: use socket to get IP
		import socket
		# Create a socket to get interface info
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		# Try to connect to a dummy address to get the interface IP
		s.connect(('8.8.8.8', 80))
		ip = s.getsockname()[0]
		s.close()
		# This gives us an IP, but not necessarily for the specific interface
		# For now, we'll use scapy's method primarily
	except Exception:
		pass
	
	# Try alternative method using netifaces if available
	try:
		import netifaces  # type: ignore
		addrs = netifaces.ifaddresses(iface)
		if netifaces.AF_INET in addrs:
			ip = addrs[netifaces.AF_INET][0].get('addr', '')
			if ip and ip != '0.0.0.0':
				return ip
	except ImportError:
		pass
	except Exception:
		pass
	
	return None

# Get available network interfaces with IP addresses
def get_network_interfaces():
	"""Get list of available network interfaces with IP addresses on the current OS"""
	interfaces = []
	physical_interfaces = []
	virtual_interfaces = []
	
	try:
		# Use scapy's get_if_list for cross-platform interface detection
		if_list = get_if_list()
		for iface in if_list:
			# Skip loopback
			if iface.startswith('lo'):
				continue
			
			# Get IP address for this interface
			ip = get_interface_ip(iface)
			interface_info = {
				"name": iface,
				"ip": ip
			}
			
			# Categorize interfaces
			if (iface.startswith('en') or iface.startswith('eth') or 
			    iface.startswith('wlan') or iface.startswith('wifi')):
				physical_interfaces.append(interface_info)
			elif (iface.startswith('utun') or iface.startswith('awdl') or 
			      iface.startswith('bridge') or iface.startswith('gif') or
			      iface.startswith('stf') or iface.startswith('anpi') or
			      iface.startswith('llw') or iface.startswith('ap')):
				virtual_interfaces.append(interface_info)
			else:
				# Unknown type, add to physical list
				physical_interfaces.append(interface_info)
		
		# Sort by name, then combine
		physical_interfaces.sort(key=lambda x: x['name'])
		virtual_interfaces.sort(key=lambda x: x['name'])
		interfaces = physical_interfaces + virtual_interfaces
		
	except Exception as e:
		print(f"Warning: Could not get interface list: {e}")
		# Fallback: try common interface names based on OS
		system = platform.system()
		if system == "Darwin":  # macOS
			fallback_names = ["en0", "en1", "en2", "en3"]
		elif system == "Linux":
			fallback_names = ["eth0", "eth1", "wlan0", "wlan1"]
		else:
			fallback_names = ["eth0"]
		
		interfaces = [{"name": name, "ip": get_interface_ip(name)} for name in fallback_names]
	
	return interfaces if interfaces else [{"name": "eth0", "ip": None}]

# Async sniffing wrapper
async def sniff_async(interface=None):
	global current_interface, shutdown_flag
	if interface is None:
		interfaces = get_network_interfaces()
		interface = interfaces[0]['name'] if interfaces else "eth0"
	
	current_interface = interface
	try:
		print(f"Starting packet capture on interface: {interface}")
		# Run sniff in a thread - it will block until cancelled
		await asyncio.to_thread(sniff, prn=process, store=False, iface=interface)
	except asyncio.CancelledError:
		print("Packet capture cancelled")
		raise
	except Exception as e:
		if not shutdown_flag:
			print(f"Warning: Packet sniffing failed on {interface}: {e}")
			print("Note: Packet sniffing requires root permissions (run with sudo)")
			print("Web server will continue running but no network data will be captured.")

# Compute entropy per flow and detect anomalies
def get_flow_entropies():
	result = {}
	alerts = []
	
	for flow, times in flows.items():
		if len(times) > 3:
			intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
			entropy_val = entropy(intervals)
			result[flow] = entropy_val
			
			# Store entropy history
			flow_entropy_history[flow].append(entropy_val)
			
			# Detect anomalies (spikes or drops)
			history = list(flow_entropy_history[flow])
			if len(history) >= 5:
				recent_avg = sum(history[-5:]) / 5
				prev_avg = sum(history[-10:-5]) / 5 if len(history) >= 10 else recent_avg
				
				if prev_avg > 0:
					change_ratio = abs(entropy_val - prev_avg) / prev_avg
					if change_ratio > ALERT_THRESHOLD_RATIO:
						alert_type = "SPIKE" if entropy_val > prev_avg else "DROP"
						flow_str = f"{flow[0]}->{flow[1]} ({flow[2]})"
						alerts.append({
							"flow": flow_str,
							"type": alert_type,
							"entropy": round(entropy_val, 3),
							"previous_avg": round(prev_avg, 3),
							"change": round(change_ratio * 100, 1)
						})
	
	return result, alerts

# WebSocket handler for real-time updates
async def websocket_handler(request):
	global websocket_clients
	ws = web.WebSocketResponse()
	await ws.prepare(request)
	websocket_clients.add(ws)
	
	try:
		async for msg in ws:
			if msg.type == web.WSMsgType.ERROR:
				break
	except Exception:
		pass
	finally:
		websocket_clients.discard(ws)
	
	return ws

# Initialize log file
def init_log_file():
	global log_file, log_writer, log_csv_file
	if current_interface:
		timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
		log_filename = f"entropy_log_{current_interface}_{timestamp}.csv"
		log_path = os.path.join(DATA_DIR, log_filename)
		
		log_csv_file = open(log_path, 'w', newline='')
		log_writer = csv.writer(log_csv_file)
		# Write header
		log_writer.writerow(['timestamp', 'interface', 'flow', 'entropy', 'alert_type', 'alert_change'])
		log_csv_file.flush()
		
		print(f"Logging started: {log_path}")

# Close log file
def close_log_file():
	global log_file, log_writer, log_csv_file
	if log_csv_file:
		log_csv_file.close()
		log_csv_file = None
		log_writer = None

# Write to log file
def write_log_entry(entropies, alerts, timestamp, interface):
	global log_writer, log_csv_file
	if log_writer and log_csv_file:
		try:
			dt = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
			
			# Write entropy data for each flow
			for flow_str, entropy_val in entropies.items():
				# Check if this flow has an alert
				alert_info = None
				for alert in alerts:
					if alert['flow'] == flow_str:
						alert_info = alert
						break
				
				if alert_info:
					log_writer.writerow([
						dt,
						interface or '',
						flow_str,
						entropy_val,
						alert_info['type'],
						f"{alert_info['change']}%"
					])
				else:
					log_writer.writerow([
						dt,
						interface or '',
						flow_str,
						entropy_val,
						'',
						''
					])
			
			log_csv_file.flush()
		except Exception as e:
			print(f"Error writing to log: {e}")

# Broadcast entropy data to all WebSocket clients
async def broadcast_entropy():
	global websocket_clients, current_interface, shutdown_flag
	while not shutdown_flag:
		await asyncio.sleep(ENTROPY_REFRESH)
		if shutdown_flag:
			break
		if websocket_clients or log_writer:
			entropies, alerts = get_flow_entropies()
			timestamp = time.time()
			
			# Convert tuple keys to strings for JSON
			entropies_str = {}
			entropy_history_data = {}
			
			for k, v in entropies.items():
				flow_str = f"{k[0]}->{k[1]} ({k[2]})"
				entropies_str[flow_str] = round(v, 3)
				# Include history for charting
				entropy_history_data[flow_str] = {
					"current": round(v, 3),
					"history": [round(h, 3) for h in list(flow_entropy_history[k])]
				}
			
			# Write to log file
			if log_writer:
				write_log_entry(entropies_str, alerts, timestamp, current_interface)
			
			data = {
				"entropies": entropies_str,
				"entropy_history": entropy_history_data,
				"alerts": alerts,
				"timestamp": timestamp,
				"interface": current_interface
			}
			
			# Send to all connected clients
			if websocket_clients:
				disconnected = set()
				for ws in websocket_clients:
					try:
						await ws.send_json(data)
					except Exception:
						disconnected.add(ws)
				
				websocket_clients -= disconnected

# Serve HTML dashboard
async def dashboard(request):
	html_path = os.path.join(os.path.dirname(__file__), 'dashboard.html')
	if os.path.exists(html_path):
		with open(html_path, 'r') as f:
			return web.Response(text=f.read(), content_type='text/html')
	else:
		return web.Response(text="Dashboard file not found", status=404)

# Get available interfaces endpoint
async def get_interfaces(request):
	interfaces = get_network_interfaces()
	return web.Response(text=json.dumps({
		"interfaces": interfaces,
		"current": current_interface
	}), content_type='application/json')

# Change interface endpoint
async def change_interface(request):
	global sniff_task, current_interface
	
	data = await request.json()
	new_interface = data.get('interface')
	
	if not new_interface:
		return web.Response(text=json.dumps({"error": "Interface not specified"}), 
			status=400, content_type='application/json')
	
	# Cancel existing sniff task
	if sniff_task and not sniff_task.done():
		sniff_task.cancel()
		try:
			await sniff_task
		except asyncio.CancelledError:
			pass
	
	# Clear existing flows when changing interface
	flows.clear()
	flow_entropy_history.clear()
	
	# Start new sniff task with new interface
	sniff_task = asyncio.create_task(sniff_async(interface=new_interface))
	
	return web.Response(text=json.dumps({
		"success": True,
		"interface": new_interface
	}), content_type='application/json')

# Web server route (legacy JSON endpoint)
async def handle(request):
	entropies, alerts = get_flow_entropies()
	# Convert tuple keys to strings for JSON
	entropies_str = {f"{k[0]}->{k[1]} ({k[2]})": round(v, 3) for k, v in entropies.items()}
	return web.Response(text=json.dumps({"entropies": entropies_str, "alerts": alerts}), content_type='application/json')

# Start/stop capture endpoint
async def start_capture(request):
	global sniff_task, current_interface
	
	data = await request.json()
	interface = data.get('interface')
	
	if not interface:
		return web.Response(text=json.dumps({"error": "Interface not specified"}), 
			status=400, content_type='application/json')
	
	# If already capturing on this interface, return success
	if current_interface == interface and sniff_task and not sniff_task.done():
		return web.Response(text=json.dumps({
			"success": True,
			"interface": interface,
			"message": "Already capturing on this interface"
		}), content_type='application/json')
	
	# Cancel existing sniff task if any
	if sniff_task and not sniff_task.done():
		sniff_task.cancel()
		try:
			await sniff_task
		except asyncio.CancelledError:
			pass
	
	# Close old log file if exists
	close_log_file()
	
	# Clear existing flows when starting new capture
	flows.clear()
	flow_entropy_history.clear()
	
	# Start new sniff task with selected interface
	current_interface = interface
	sniff_task = asyncio.create_task(sniff_async(interface=interface))
	
	# Initialize log file
	init_log_file()
	
	return web.Response(text=json.dumps({
		"success": True,
		"interface": interface,
		"message": f"Started capturing on {interface}"
	}), content_type='application/json')

async def stop_capture(request):
	global sniff_task, current_interface
	
	if sniff_task and not sniff_task.done():
		sniff_task.cancel()
		try:
			await sniff_task
		except asyncio.CancelledError:
			pass
		sniff_task = None
	
	# Close log file
	close_log_file()
	current_interface = None
	
	return web.Response(text=json.dumps({
		"success": True,
		"message": "Capture stopped"
	}), content_type='application/json')

# Get list of log files
async def list_logs(request):
	logs = []
	try:
		for filename in os.listdir(DATA_DIR):
			if filename.startswith('entropy_log_') and filename.endswith('.csv'):
				filepath = os.path.join(DATA_DIR, filename)
				stat = os.stat(filepath)
				logs.append({
					"filename": filename,
					"size": stat.st_size,
					"modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
				})
		# Sort by modified time, newest first
		logs.sort(key=lambda x: x['modified'], reverse=True)
	except Exception as e:
		return web.Response(text=json.dumps({"error": str(e)}), 
			status=500, content_type='application/json')
	
	return web.Response(text=json.dumps({"logs": logs}), content_type='application/json')

# Download log file
async def download_log(request):
	filename = request.query.get('file')
	if not filename:
		return web.Response(text="Filename required", status=400)
	
	# Security: prevent directory traversal
	if '..' in filename or '/' in filename or '\\' in filename:
		return web.Response(text="Invalid filename", status=400)
	
	filepath = os.path.join(DATA_DIR, filename)
	
	if not os.path.exists(filepath):
		return web.Response(text="File not found", status=404)
	
	# Return file for download
	return web.FileResponse(
		filepath,
		headers={
			'Content-Disposition': f'attachment; filename="{filename}"',
			'Content-Type': 'text/csv'
		}
	)

# Quit/shutdown endpoint
async def quit_server(request):
	global shutdown_flag, sniff_task
	shutdown_flag = True
	
	# Stop capture if running
	if sniff_task and not sniff_task.done():
		sniff_task.cancel()
	
	# Close log file
	close_log_file()
	
	return web.Response(text=json.dumps({
		"success": True,
		"message": "Server shutting down..."
	}), content_type='application/json')

# Main async function
async def main():
	global sniff_task, shutdown_flag
	
	# Get available interfaces but don't start automatically
	interfaces = get_network_interfaces()
	interface_names = [iface['name'] + (f" ({iface['ip']})" if iface.get('ip') else "") for iface in interfaces]
	print(f"Available network interfaces: {', '.join(interface_names)}")
	print("Waiting for interface selection before starting capture...")
	print("Please select an interface in the dashboard to begin packet capture.")
	
	# Start broadcasting entropy updates
	asyncio.create_task(broadcast_entropy())

	# Start web server
	app = web.Application()
	app.add_routes([
		web.get('/', dashboard),
		web.get('/dashboard', dashboard),
		web.get('/ws', websocket_handler),
		web.get('/flows', handle),
		web.get('/api/interfaces', get_interfaces),
		web.post('/api/interface', change_interface),
		web.post('/api/capture/start', start_capture),
		web.post('/api/capture/stop', stop_capture),
		web.get('/api/logs', list_logs),
		web.get('/api/logs/download', download_log),
		web.post('/api/quit', quit_server)
	])
	runner = web.AppRunner(app)
	await runner.setup()
	
	# Try to bind to port 8080, if it fails try 8081, 8082, etc.
	port = 8080
	max_attempts = 10
	for attempt in range(max_attempts):
		try:
			site = web.TCPSite(runner, '0.0.0.0', port)
			await site.start()
			print(f"\n{'='*60}")
			print(f"Hammer4D Demon dashboard running at http://0.0.0.0:{port}/")
			print(f"WebSocket endpoint: ws://0.0.0.0:{port}/ws")
			print(f"{'='*60}")
			print("⚠️  IMPORTANT: Select a network interface in the dashboard")
			print("   to start packet capture. Capture will not start automatically.")
			print(f"{'='*60}\n")
			break
		except OSError as e:
			if e.errno == 48:  # Address already in use
				port += 1
				if attempt == max_attempts - 1:
					print(f"Error: Could not find an available port after {max_attempts} attempts")
					raise
			else:
				raise

	# Setup signal handlers for clean shutdown
	def signal_handler(signum, frame):
		global shutdown_flag
		print("\nReceived shutdown signal, cleaning up...")
		shutdown_flag = True
	
	# Register signal handlers
	signal.signal(signal.SIGINT, signal_handler)
	signal.signal(signal.SIGTERM, signal_handler)
	
	# Keep alive
	try:
		while not shutdown_flag:
			await asyncio.sleep(0.5)
	except KeyboardInterrupt:
		print("\nReceived KeyboardInterrupt, shutting down...")
		shutdown_flag = True
	except Exception as e:
		print(f"\nUnexpected error: {e}")
		import traceback
		traceback.print_exc()
		shutdown_flag = True
	finally:
		print("\nShutting down gracefully...")
		shutdown_flag = True
		
		# Close log file if open
		close_log_file()
		
		# Cancel all background tasks
		print("Cancelling background tasks...")
		all_tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
		for task in all_tasks:
			if not task.done():
				task.cancel()
		
		# Stop capture if running
		if sniff_task and not sniff_task.done():
			print("Stopping packet capture...")
			sniff_task.cancel()
			try:
				await asyncio.wait_for(sniff_task, timeout=1.0)
			except (asyncio.CancelledError, asyncio.TimeoutError):
				pass
		
		# Wait briefly for cancelled tasks
		if all_tasks:
			try:
				await asyncio.wait_for(
					asyncio.gather(*all_tasks, return_exceptions=True),
					timeout=1.0
				)
			except (asyncio.TimeoutError, Exception):
				pass
		
		# Clean up runner
		print("Stopping web server...")
		try:
			await runner.cleanup()
		except Exception as e:
			print(f"Error during cleanup: {e}")
		
		print("Server stopped cleanly.")

if __name__ == "__main__":
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print("\nForced exit. Server stopped.")
		sys.exit(0)
	except Exception as e:
		print(f"\nFatal error: {e}")
		sys.exit(1)
