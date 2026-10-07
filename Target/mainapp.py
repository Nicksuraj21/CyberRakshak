from flask import Flask, render_template, jsonify, request, Response, send_from_directory
import io
import csv
import threading
import time
from datetime import datetime, timedelta
import joblib
import numpy as np
import psutil
import random
import json
import os
import sys

# Ensure UTF-8 output encoding if possible
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
nested_dir = os.path.join(BASE_DIR, "CyberRakshak-IDS-main")
model_path = os.path.join(BASE_DIR, "model.pkl")
if not os.path.exists(model_path) and os.path.exists(os.path.join(nested_dir, "model.pkl")):
    BASE_DIR = nested_dir

templates_dir = os.path.join(BASE_DIR, "templates")
app = Flask(__name__, template_folder=templates_dir)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.jinja_env.auto_reload = True

@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# 1. Load ML Model
model = None
try:
    with open(os.path.join(BASE_DIR, "model.pkl"), "rb") as f:
        model = joblib.load(f)
    print(" [*] Cyber Rakshak XGBoost ML Model loaded successfully.")
except Exception as e:
    print(f" [!] Warning loading model.pkl: {e}")

# 2. Load Input Encoders
proto_encoder = None
service_encoder = None
try:
    with open(os.path.join(BASE_DIR, "input_encoders.pkl"), "rb") as f:
        encoders = joblib.load(f)
        proto_encoder = encoders.get("proto")
        service_encoder = encoders.get("service")
    print(" [*] Input encoders (proto, service) loaded successfully.")
except Exception as e:
    print(f" [!] Input encoders fallback: {e}")
    from sklearn.preprocessing import LabelEncoder
    proto_encoder = LabelEncoder().fit(['icmp', 'tcp', 'udp'])
    service_encoder = LabelEncoder().fit(['-', 'dhcp', 'dns', 'http', 'irc', 'mqtt', 'ntp', 'radius', 'ssh', 'ssl'])

# 3. Load Output Label Encoder
label_encoder_y = None
try:
    with open(os.path.join(BASE_DIR, "label_encoder_y.pkl"), "rb") as f:
        label_encoder_y = joblib.load(f)
        attack_classes = list(label_encoder_y.classes_)
    print(" [*] Output label encoder loaded:", attack_classes)
except Exception as e:
    print(f" [!] Label encoder y fallback: {e}")
    attack_classes = [
        'ARP_poisioning', 'DDOS_Slowloris', 'DOS_SYN_Hping', 'MQTT_Publish',
        'Metasploit_Brute_Force_SSH', 'NMAP_FIN_SCAN', 'NMAP_OS_DETECTION',
        'NMAP_TCP_scan', 'NMAP_UDP_SCAN', 'NMAP_XMAS_TREE_SCAN', 'Thing_Speak', 'Wipro_bulb'
    ]

# Severity Mapping
SEVERITY_MAP = {
    'DDOS_Slowloris': 'High',
    'DOS_SYN_Hping': 'High',
    'Metasploit_Brute_Force_SSH': 'Medium',
    'SQL Injection': 'High',
    'Zero-Day': 'Critical',
    'ARP_poisioning': 'High',
    'NMAP_TCP_scan': 'Medium',
    'NMAP_UDP_SCAN': 'Medium',
    'NMAP_OS_DETECTION': 'Low',
    'NMAP_FIN_SCAN': 'Medium',
    'NMAP_XMAS_TREE_SCAN': 'Medium',
    'MQTT_Publish': 'Normal',
    'Thing_Speak': 'Normal',
    'Wipro_bulb': 'Normal'
}

# In-Memory State & Pre-seeded live metrics
system_stats = []
live_activity_logs = []
blocked_threats = []
blocked_ips = set()
blocked_domains = set(["doubleclick.net", "telemetry-track.io", "adservice.google.com"])
auto_block_enabled = True
adblock_enabled = True
total_scanned_counter = 438
total_threats_counter = 18

_now = datetime.now()
# Pre-seed 12 performance timepoints
for i in range(12, 0, -1):
    _t_str = (_now - timedelta(seconds=i*4)).strftime("%I:%M:%S %p")
    system_stats.append({
        "time": _t_str,
        "cpu": round(random.uniform(2.5, 9.4), 1),
        "mem": round(random.uniform(19.2, 22.8), 1),
        "latency": round(random.uniform(18.0, 42.0), 1)
    })

# Pre-seed rich recent flow logs
sample_clients = ["192.168.1.102", "192.168.1.105", "192.168.1.114", "192.168.1.138", "192.168.1.174", "192.168.1.201", "10.0.4.12", "172.16.0.45"]
sample_site_catalogs = [
    {"main": "https://github.com/session", "sub": "TLS: github.com", "domain": "github.com", "proto": "tcp", "service": "ssl", "risk": "Normal", "conf": 99.4, "peer": "140.82.121.4"},
    {"main": "https://google.com/search?q=cybersecurity", "sub": "Host: google.com", "domain": "google.com", "proto": "tcp", "service": "http", "risk": "Normal", "conf": 99.8, "peer": "142.250.190.46"},
    {"main": "https://aws.amazon.com/api/v2", "sub": "TLS: aws.amazon.com", "domain": "amazon.com", "proto": "tcp", "service": "ssl", "risk": "Normal", "conf": 98.9, "peer": "52.94.236.248"},
    {"main": "dns.google (8.8.8.8)", "sub": "DNS: resolve a-record", "domain": "dns.google", "proto": "udp", "service": "dns", "risk": "Normal", "conf": 99.1, "peer": "8.8.8.8"},
    {"main": "mqtt.iot-broker.local:1883", "sub": "MQTT: telemetry/publish", "domain": "iot-broker.local", "proto": "tcp", "service": "mqtt", "risk": "Normal", "conf": 97.6, "peer": "192.168.1.250"},
    {"main": "http://198.51.100.44/login.php", "sub": "Host: 198.51.100.44", "domain": "198.51.100.44", "proto": "tcp", "service": "http", "risk": "High Risk", "conf": 99.2, "peer": "198.51.100.44"},
    {"main": "http://45.33.32.156:80/flood", "sub": "Host: 45.33.32.156", "domain": "45.33.32.156", "proto": "tcp", "service": "http", "risk": "Critical Risk", "conf": 99.9, "peer": "45.33.32.156"},
    {"main": "ssh://185.220.101.5:22", "sub": "SSH: Auth password probe", "domain": "185.220.101.5", "proto": "tcp", "service": "ssh", "risk": "High Risk", "conf": 98.5, "peer": "185.220.101.5"}
]

for i in range(15, 0, -1):
    _t_str = (_now - timedelta(seconds=i*3)).strftime("%I:%M:%S %p")
    c_site = random.choice(sample_site_catalogs)
    c_client = random.choice(sample_clients)
    live_activity_logs.append({
        "time": _t_str,
        "client_ip": c_client,
        "ip": c_client,
        "peer_ip": c_site["peer"],
        "full_url": c_site["main"],
        "tls_sni": c_site["domain"],
        "dns_query": c_site["domain"] if c_site["service"] == "dns" else "",
        "http_host": c_site["domain"],
        "proto": c_site["proto"],
        "service": c_site["service"],
        "risk_level": c_site["risk"],
        "confidence": c_site["conf"],
        "cpu": f"{random.uniform(1.2, 6.5):.1f}%",
        "mem": f"{random.uniform(19.0, 22.5):.1f}MB",
        "request_type": random.choice(["GET", "POST", "PUT"]),
        "status": "Blocked" if "Risk" in c_site["risk"] else "Normal",
        "threat": c_site["risk"],
        "is_blocked": "Risk" in c_site["risk"]
    })

# Pre-seed 4 blocked threats
blocked_samples = [
    ("45.33.32.156", "DDOS_Slowloris", "Critical", "POST"),
    ("185.220.101.5", "Metasploit_Brute_Force_SSH", "High", "POST"),
    ("198.51.100.44", "SQL Injection", "High", "POST"),
    ("203.0.113.88", "DOS_SYN_Hping", "High", "POST")
]
for ip, reason, sev, method in blocked_samples:
    blocked_ips.add(ip)
    blocked_threats.append({
        "time": (_now - timedelta(minutes=random.randint(1, 10))).strftime("%I:%M:%S %p"),
        "ip": ip,
        "request_type": method,
        "severity": sev,
        "reason": reason,
        "is_blocked": True
    })

def predict_packet(proto, service, urg_flag, pkt_min, pkt_avg, iat_max, idle_min, idle_avg, init_win, last_win):
    try:
        proto_encoded = proto_encoder.transform([proto])[0] if proto_encoder else 1
    except:
        proto_encoded = 1

    try:
        service_encoded = service_encoder.transform([service])[0] if service_encoder else 3
    except:
        service_encoded = 3

    features = np.array([
        proto_encoded,
        service_encoded,
        urg_flag,
        pkt_min,
        pkt_avg,
        iat_max,
        idle_min,
        idle_avg,
        init_win,
        last_win
    ], dtype=float).reshape(1, -1)

    if model is not None:
        try:
            pred = model.predict(features)[0]
            if label_encoder_y is not None:
                return label_encoder_y.inverse_transform([int(pred)])[0]
            return attack_classes[int(pred) % len(attack_classes)]
        except Exception as e:
            return "Normal"
    return "Normal"

# Background Packet Sniffer Simulation
def packet_sniffer():
    global total_scanned_counter, total_threats_counter
    normal_services = ['http', 'mqtt', 'dns', 'ssl']
    attack_simulation_pool = [
        'Normal', 'Normal', 'Normal', 'Normal', 'Normal',
        'DDOS_Slowloris', 'DOS_SYN_Hping', 'Metasploit_Brute_Force_SSH',
        'NMAP_TCP_scan', 'SQL Injection', 'Zero-Day'
    ]

    while True:
        try:
            total_scanned_counter += 1
            client_ip = f"192.168.1.{random.randint(100, 240)}"
            c_site = random.choice(sample_site_catalogs)
            source_ip = c_site["peer"]
            if random.random() < 0.2:
                source_ip = f"{random.randint(10, 220)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

            method = random.choice(['GET', 'POST', 'PUT', 'DELETE'])
            proto = c_site["proto"]
            service = c_site["service"]
            now_str = datetime.now().strftime("%I:%M:%S %p")

            is_domain_blocked = any(d in c_site["domain"] for d in blocked_domains)
            is_ip_blocked = source_ip in blocked_ips or client_ip in blocked_ips

            if is_domain_blocked or is_ip_blocked:
                status = "Blocked"
                threat_name = "Blacklisted Website/IP" if is_domain_blocked else "Blacklisted IP Access"
                severity = "High"
                risk_level = "High Risk"
                conf_score = 99.8
                total_threats_counter += 1
            else:
                sim_choice = random.choice(attack_simulation_pool)
                if sim_choice == 'Normal':
                    status = "Normal"
                    threat_name = "Normal"
                    severity = "Low"
                    risk_level = "Normal"
                    conf_score = round(random.uniform(97.5, 99.9), 1)
                else:
                    total_threats_counter += 1
                    urg = random.randint(1, 4) if "DOS" in sim_choice or "DDOS" in sim_choice else 0
                    predicted = predict_packet(
                        proto=proto,
                        service=service,
                        urg_flag=urg,
                        pkt_min=random.uniform(0, 100),
                        pkt_avg=random.uniform(50, 1500),
                        iat_max=random.uniform(10, 1000),
                        idle_min=random.uniform(0, 500),
                        idle_avg=random.uniform(0, 500),
                        init_win=random.randint(1024, 65535),
                        last_win=random.randint(1024, 65535)
                    )
                    threat_name = sim_choice if sim_choice in ['SQL Injection', 'Zero-Day'] else predicted
                    severity = SEVERITY_MAP.get(threat_name, 'Medium')
                    risk_level = "Critical Risk" if severity == 'Critical' else ("High Risk" if severity == 'High' else "Warning")
                    conf_score = round(random.uniform(96.0, 99.9), 1)
                    
                    if auto_block_enabled and severity in ['Critical', 'High']:
                        status = "Blocked"
                        blocked_ips.add(source_ip)
                        blocked_threats.insert(0, {
                            "time": now_str,
                            "ip": source_ip,
                            "request_type": method,
                            "severity": severity,
                            "reason": threat_name,
                            "is_blocked": True
                        })
                        if len(blocked_threats) > 100:
                            blocked_threats.pop()
                    else:
                        status = "Detected" if severity in ['High', 'Critical'] else ("Suspicious" if severity == 'Medium' else "Normal")

            cpu_val = f"{random.uniform(0.8, 12.5):.1f}%"
            mem_val = f"{random.uniform(18.5, 24.0):.1f}MB"
            live_activity_logs.insert(0, {
                "time": now_str,
                "client_ip": client_ip,
                "ip": client_ip,
                "peer_ip": source_ip,
                "full_url": c_site["main"],
                "tls_sni": c_site["domain"],
                "dns_query": c_site["domain"] if service == "dns" else "",
                "http_host": c_site["domain"],
                "proto": proto,
                "service": service,
                "risk_level": risk_level,
                "confidence": conf_score,
                "cpu": cpu_val,
                "mem": mem_val,
                "request_type": method,
                "status": status,
                "threat": threat_name,
                "is_blocked": status == "Blocked"
            })
            if len(live_activity_logs) > 120:
                live_activity_logs.pop()

        except Exception as e:
            print("Sniffer thread error:", e)

        time.sleep(1.8)

# Background System Performance Monitor
def system_monitor():
    while True:
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
            latency = round(random.uniform(15.0, 180.0) + (cpu * 0.8), 1)

            stats = {
                "time": datetime.now().strftime("%I:%M:%S %p"),
                "cpu": cpu,
                "mem": mem,
                "latency": latency
            }
            system_stats.append(stats)
            if len(system_stats) > 30:
                system_stats.pop(0)
        except Exception as e:
            print("System monitor error:", e)

        time.sleep(2)

# --- Routes ---

@app.route('/dashboard')
@app.route('/dashboard/')
def view_dashboard():
    return render_template('dashboard.html')

@app.route('/api/metrics')
def get_metrics():
    return jsonify(system_stats)

@app.route('/api/logs')
def get_logs():
    return jsonify(live_activity_logs)

@app.route('/api/blocked')
def get_blocked():
    return jsonify(blocked_threats)

@app.route('/api/summary')
def get_summary():
    health = max(88.0, 100.0 - (len(blocked_ips) * 0.15))
    return jsonify({
        "total_scanned": total_scanned_counter,
        "threats_detected": total_threats_counter,
        "blocked_count": len(blocked_ips),
        "health_score": f"{health:.1f}%"
    })

@app.route('/receive_log', methods=['POST'])
def receive_log():
    global total_scanned_counter, total_threats_counter
    try:
        data = request.get_json(force=True)
        total_scanned_counter += 1
        ip = data.get("IP", f"192.168.1.{random.randint(1,254)}")
        req_type = data.get("Request Type", "Normal")
        cpu_usage = f"{data.get('CPU Usage', random.randint(1, 15))}%"
        mem_usage = f"{data.get('Memory', 20.8)}MB"
        now_str = datetime.now().strftime("%I:%M:%S %p")

        is_attack = req_type != "Normal"
        status = "Blocked" if is_attack else "Normal"
        severity = SEVERITY_MAP.get(req_type, "High") if is_attack else "Low"

        if is_attack:
            total_threats_counter += 1
            blocked_ips.add(ip)
            blocked_threats.insert(0, {
                "time": now_str,
                "ip": ip,
                "request_type": "POST",
                "severity": severity,
                "reason": req_type,
                "is_blocked": True
            })
            if len(blocked_threats) > 100:
                blocked_threats.pop()

        live_activity_logs.insert(0, {
            "time": now_str,
            "ip": ip,
            "cpu": cpu_usage,
            "mem": mem_usage,
            "request_type": "POST",
            "status": status,
            "threat": req_type
        })
        if len(live_activity_logs) > 100:
            live_activity_logs.pop()

        return jsonify({"status": "received", "action": "blocked" if is_attack else "allowed"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/simulate', methods=['POST'])
def simulate_attack_api():
    try:
        data = request.get_json(force=True)
        proto = data.get('proto', 'tcp')
        service = data.get('service', 'http')
        urg = data.get('fwd_URG_flag_count', 0)
        pkt_min = data.get('fwd_pkts_payload.min', 10.0)
        pkt_avg = data.get('fwd_pkts_payload.avg', 50.0)
        iat_max = data.get('fwd_iat.max', 100.0)
        idle_min = data.get('idle.min', 0.0)
        idle_avg = data.get('idle.avg', 0.0)
        init_win = data.get('fwd_init_window_size', 8192)
        last_win = data.get('fwd_last_window_size', 8192)

        predicted = predict_packet(proto, service, urg, pkt_min, pkt_avg, iat_max, idle_min, idle_avg, init_win, last_win)
        return jsonify({"status": "success", "predicted_attack": predicted}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/simulate_attack', methods=['POST'])
def trigger_attack_from_ui():
    global total_threats_counter
    try:
        data = request.get_json(force=True)
        attack_type = data.get('attack_type', 'DDOS_Slowloris')
        ip = data.get('ip', f'192.168.1.{random.randint(10,200)}')
        proto = data.get('proto', 'tcp')
        method = data.get('method', 'POST')
        now_str = datetime.now().strftime("%I:%M:%S %p")

        is_attack = attack_type != 'Normal'
        severity = SEVERITY_MAP.get(attack_type, 'High') if is_attack else 'Low'
        status = 'Blocked' if is_attack else 'Normal'

        if is_attack:
            total_threats_counter += 1
            blocked_ips.add(ip)
            blocked_threats.insert(0, {
                "time": now_str,
                "ip": ip,
                "request_type": method,
                "severity": severity,
                "reason": attack_type,
                "is_blocked": True
            })
            if len(blocked_threats) > 100:
                blocked_threats.pop()

        live_activity_logs.insert(0, {
            "time": now_str,
            "ip": ip,
            "cpu": f"{random.uniform(4.5, 18.0):.1f}%",
            "mem": f"{random.uniform(20.0, 32.0):.1f}MB",
            "request_type": method,
            "status": status,
            "threat": attack_type
        })
        if len(live_activity_logs) > 100:
            live_activity_logs.pop()

        return jsonify({
            "status": "success",
            "predicted_attack": attack_type,
            "ip": ip,
            "severity": severity
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/block_ip', methods=['POST'])
def block_ip():
    try:
        data = request.get_json(force=True)
        ip = data.get('ip')
        direction = data.get('direction', 'destination')
        if ip:
            blocked_ips.add(ip)
            for b in blocked_threats:
                if b['ip'] == ip:
                    b['is_blocked'] = True
            now_str = datetime.now().strftime("%I:%M:%S %p")
            blocked_threats.insert(0, {
                "time": now_str,
                "ip": ip,
                "request_type": "FIREWALL",
                "severity": "High",
                "reason": f"Manual {direction.capitalize()} Block",
                "is_blocked": True
            })
            return jsonify({"ok": True, "status": "success", "message": f"IP {ip} has been blocked ({direction})."})
        return jsonify({"ok": False, "error": "No IP provided"}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route('/api/unblock_ip', methods=['POST'])
def unblock_ip():
    try:
        data = request.get_json(force=True)
        ip = data.get('ip')
        if ip:
            blocked_ips.discard(ip)
            for b in blocked_threats:
                if b['ip'] == ip:
                    b['is_blocked'] = False
            return jsonify({"ok": True, "status": "success", "message": f"IP {ip} has been unblocked."})
        return jsonify({"ok": False, "error": "No IP provided"}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route('/api/block_domain', methods=['POST'])
def block_domain():
    try:
        data = request.get_json(force=True)
        domain = data.get('domain', '').strip().lower()
        if not domain:
            return jsonify({"ok": False, "error": "No domain provided"}), 400
        
        blocked_domains.add(domain)
        resolved_ips = []
        try:
            import socket
            _, _, ips = socket.gethostbyname_ex(domain)
            resolved_ips = ips
            for ip in ips:
                blocked_ips.add(ip)
                now_str = datetime.now().strftime("%I:%M:%S %p")
                blocked_threats.insert(0, {
                    "time": now_str,
                    "ip": ip,
                    "request_type": "DNS_BLOCK",
                    "severity": "High",
                    "reason": f"Domain Block: {domain}",
                    "is_blocked": True
                })
        except Exception:
            pass
        
        return jsonify({
            "ok": True,
            "status": "success",
            "message": f"Website domain '{domain}' has been added to blocked rules.",
            "resolved_ips": resolved_ips
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route('/api/unblock_domain', methods=['POST'])
def unblock_domain():
    try:
        data = request.get_json(force=True)
        domain = data.get('domain', '').strip().lower()
        if domain in blocked_domains:
            blocked_domains.discard(domain)
        return jsonify({"ok": True, "status": "success", "message": f"Website '{domain}' unblocked."})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route('/api/blocked_domains')
def get_blocked_domains():
    return jsonify({"domains": sorted(list(blocked_domains))})

@app.route('/api/firewall/status')
def get_firewall_status():
    return jsonify({
        "auto_block_enabled": auto_block_enabled,
        "adblock_enabled": adblock_enabled,
        "manual_blocked_ips": sorted(list(blocked_ips)),
        "blocked_domains": sorted(list(blocked_domains)),
        "blocked_domains_count": len(blocked_domains)
    })

@app.route('/api/firewall/auto_block', methods=['POST'])
def toggle_auto_block():
    global auto_block_enabled
    try:
        data = request.get_json(force=True)
        auto_block_enabled = bool(data.get('enabled', not auto_block_enabled))
        return jsonify({"ok": True, "auto_block_enabled": auto_block_enabled, "message": f"Auto-mitigation is now {'ON' if auto_block_enabled else 'OFF'}"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route('/api/firewall/recover_all', methods=['POST'])
def recover_all_firewall():
    global blocked_ips, blocked_domains
    blocked_ips.clear()
    blocked_domains.clear()
    for b in blocked_threats:
        b['is_blocked'] = False
    return jsonify({"ok": True, "status": "success", "message": "All blocked IP addresses & domains have been unblocked/recovered."})

@app.route('/api/adblock/enable', methods=['POST'])
def enable_adblock():
    global adblock_enabled
    adblock_enabled = True
    return jsonify({"ok": True, "status": "success", "message": "Ad & Tracker Blocker enabled."})

@app.route('/api/adblock/disable', methods=['POST'])
def disable_adblock():
    global adblock_enabled
    adblock_enabled = False
    return jsonify({"ok": True, "status": "success", "message": "Ad blocker disabled."})

@app.route('/api/network')
def get_network_info():
    import socket
    local_ip = "192.168.1.142"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass
    return jsonify({
        "wan_interface": "Wi-Fi (wlan0)",
        "wan_address": local_ip,
        "lan_interface": "Gigabit Ethernet (eth0)",
        "lan_address": "192.168.1.1",
        "capture_interface": "wlan0 (Promiscuous)",
        "ip_forwarding": True
    })

@app.route('/report')
def view_report():
    health = max(88.0, 100.0 - (len(blocked_ips) * 0.15))
    return render_template(
        'report.html',
        generated_at=datetime.now().strftime("%Y-%m-%d %I:%M:%S %p"),
        audit_id=f"EG-SEC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        total_scanned=total_scanned_counter,
        threats_count=total_threats_counter,
        blocked_count=len(blocked_ips),
        health_score=f"{health:.1f}%",
        blocked_threats=blocked_threats,
        activity_logs=live_activity_logs[:25]
    )

@app.route('/api/export')
def export_report():
    report_data = {
        "report_generated_at": datetime.now().strftime("%Y-%m-%d %I:%M:%S %p"),
        "audit_id": f"EG-SEC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "system": "Cyber Rakshak AI-Driven Intrusion Detection System",
        "total_scanned_flows": total_scanned_counter,
        "total_threats_detected": total_threats_counter,
        "total_blocked_ips": len(blocked_ips),
        "active_blocked_threats": blocked_threats,
        "recent_activity_logs": live_activity_logs[:25]
    }
    return Response(
        json.dumps(report_data, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment;filename=cyberrakshak_threat_report.json'}
    )

@app.route('/api/export/csv')
def export_csv_report():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Source IP", "Request Type", "Severity", "Detected Threat Vector", "Defense Action"])
    for item in blocked_threats:
        writer.writerow([
            item.get("time", ""),
            item.get("ip", ""),
            item.get("request_type", "POST"),
            item.get("severity", "High"),
            item.get("reason", "Malicious Flow"),
            "Firewall Blacklisted"
        ])
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=cyberrakshak_threat_report.csv"}
    )

@app.route('/')
@app.route('/showcase')
@app.route('/showcase/')
@app.route('/product')
@app.route('/product/')
def product_showcase():
    showcase_dir = os.path.join(BASE_DIR, 'showcase_website')
    if not os.path.exists(showcase_dir):
        showcase_dir = os.path.join(BASE_DIR, 'CyberRakshak-IDS-main', 'showcase_website')
    return send_from_directory(showcase_dir, 'index.html')

@app.route('/showcase/<path:filename>')
def showcase_static(filename):
    showcase_dir = os.path.join(BASE_DIR, 'showcase_website')
    if not os.path.exists(showcase_dir):
        showcase_dir = os.path.join(BASE_DIR, 'CyberRakshak-IDS-main', 'showcase_website')
    return send_from_directory(showcase_dir, filename)

@app.route('/styles.css')
def showcase_styles_root():
    showcase_dir = os.path.join(BASE_DIR, 'showcase_website')
    if not os.path.exists(showcase_dir):
        showcase_dir = os.path.join(BASE_DIR, 'CyberRakshak-IDS-main', 'showcase_website')
    return send_from_directory(showcase_dir, 'styles.css')

@app.route('/script.js')
def showcase_script_root():
    showcase_dir = os.path.join(BASE_DIR, 'showcase_website')
    if not os.path.exists(showcase_dir):
        showcase_dir = os.path.join(BASE_DIR, 'CyberRakshak-IDS-main', 'showcase_website')
    return send_from_directory(showcase_dir, 'script.js')

@app.route('/assets/<path:filename>')
def showcase_assets_root(filename):
    assets_dir = os.path.join(BASE_DIR, 'showcase_website', 'assets')
    if not os.path.exists(assets_dir):
        assets_dir = os.path.join(BASE_DIR, 'CyberRakshak-IDS-main', 'showcase_website', 'assets')
    return send_from_directory(assets_dir, filename)

@app.route('/<path:filename>')
def root_static_fallback(filename):
    showcase_dir = os.path.join(BASE_DIR, 'showcase_website')
    if os.path.exists(os.path.join(showcase_dir, filename)):
        return send_from_directory(showcase_dir, filename)
    if os.path.exists(os.path.join(BASE_DIR, filename)):
        return send_from_directory(BASE_DIR, filename)
    return ("Not found", 404)

# Start continuous background packet sniffer and system monitor
try:
    threading.Thread(target=packet_sniffer, daemon=True).start()
    threading.Thread(target=system_monitor, daemon=True).start()
    print(" [*] Background packet sniffer and monitor threads started.")
except Exception as _th_err:
    print(f" [!] Thread init notice: {_th_err}")

if __name__ == '__main__':
    print("=" * 60)
    print(" [*] Cyber Rakshak Real-Time IDS Dashboard is starting on http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
