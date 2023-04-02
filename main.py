from flask import Flask, jsonify, request
from apscheduler.schedulers.background import BackgroundScheduler
from scapy.all import ARP, Ether, srp
import requests
import json

app = Flask(__name__)
scheduler = None
ntfy_user = ""
ntfy_pass = ""
port = 5000

# Load known MAC addresses from file
try:
    with open('known_macs.json') as f:
        known_macs = json.load(f)
except FileNotFoundError:
    known_macs = []


# Define function to scan network
def scan_network():
    with app.app_context():
        # Set up ARP request
        arp = ARP(pdst='192.168.1.0/24')
        ether = Ether(dst='ff:ff:ff:ff:ff:ff')
        packet = ether/arp

        # Send ARP request and capture responses
        result = srp(packet, timeout=3, verbose=0)[0]

        # Parse responses and create device lists
        known_devices = []
        unknown_devices = []
        for sent, received in result:
            # Check if device is known
            known = received.hwsrc in known_macs

            # Add device to known or unknown list
            device = {'ip': received.psrc, 'mac': received.hwsrc}
            if known:
                known_devices.append(device)
            else:
                unknown_devices.append(device)

        # If there are any unknown devices, send notification to NTFY API
        if unknown_devices:
            message = f"Unknown devices detected:\n"
            for device in unknown_devices:
                message += f"- {device['mac']} ({device['ip']})\n"
            response = requests.post('https://ntfy.maxluo.org/home-stats', auth=(ntfy_user, ntfy_pass), data=message.strip())

        # Create device list and return as JSON
        devices = known_devices + unknown_devices
        for device in devices:
            device['known'] = device['mac'] in known_macs
        return jsonify(devices)

# Define endpoint to scan network
@app.route('/scan')
def scan():
    return scan_network()

# Define endpoint to get known MAC addresses
@app.route('/known-macs')
def get_known_macs():
    return jsonify(known_macs)

# Define endpoint to add known MAC address
@app.route('/known-macs', methods=['POST'])
def add_known_mac():
    mac = request.json.get('mac')
    if mac:
        known_macs.append(mac)
        # Backup known MAC addresses to file
        with open('known_macs.json', 'w') as f:
            json.dump(known_macs, f)
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Missing MAC address'})

# Define function to start scheduler
def start_scheduler(interval):
    global scheduler
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=scan_network, trigger='interval', seconds=interval)
    scheduler.start()
    return scheduler

# Define endpoint to start scheduler
@app.route('/start')
def start():
    global scheduler
    if scheduler and scheduler.running:
        return jsonify({'success': False, 'error': 'Scheduler is already running'})
    interval = request.args.get('interval', default=60, type=int)
    scheduler = start_scheduler(interval)
    return jsonify({'success': True, 'interval': interval})

# Define endpoint to stop scheduler
@app.route('/stop')
def stop():
    global scheduler
    if scheduler:
        try:
            scheduler.shutdown()
        except apscheduler.schedulers.SchedulerNotRunningError:
            return jsonify({'success': False, 'error': 'Scheduler is not running'})
        else:
            return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Scheduler has not been started'})

if __name__ == '__main__':
    app.run(port=port)
