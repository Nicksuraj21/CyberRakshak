import requests
import random
import time
import sys
import os

# Safe UTF-8 console output for Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

TARGET_IP = "127.0.0.1"
TARGET_PORT = 5000

ATTACK_VECTORS = [
    {
        "name": "DDOS_Slowloris",
        "category": "Denial of Service",
        "severity": "High",
        "cpu_range": (14.0, 28.5),
        "fwd_pkts": (50, 450),
        "protocol": "tcp"
    },
    {
        "name": "DOS_SYN_Hping",
        "category": "SYN Flood Exploit",
        "severity": "High",
        "cpu_range": (18.0, 35.0),
        "fwd_pkts": (120, 800),
        "protocol": "tcp"
    },
    {
        "name": "SQL Injection",
        "category": "Web Application Attack",
        "severity": "High",
        "cpu_range": (8.0, 15.0),
        "fwd_pkts": (5, 30),
        "protocol": "tcp"
    },
    {
        "name": "Metasploit_Brute_Force_SSH",
        "category": "Credential Access",
        "severity": "Medium",
        "cpu_range": (9.0, 19.0),
        "fwd_pkts": (20, 90),
        "protocol": "tcp"
    },
    {
        "name": "Zero-Day",
        "category": "Zero-Day Anomaly Payload",
        "severity": "Critical",
        "cpu_range": (22.0, 45.0),
        "fwd_pkts": (80, 500),
        "protocol": "udp"
    },
    {
        "name": "NMAP_TCP_scan",
        "category": "Port & Network Reconnaissance",
        "severity": "Medium",
        "cpu_range": (5.0, 12.0),
        "fwd_pkts": (15, 60),
        "protocol": "tcp"
    },
    {
        "name": "Normal",
        "category": "Legitimate Traffic",
        "severity": "Low",
        "cpu_range": (1.0, 6.0),
        "fwd_pkts": (2, 20),
        "protocol": "tcp"
    }
]

def generate_ip():
    # 70% simulated internal/external threats, 30% random public ranges
    if random.random() < 0.6:
        return f"192.168.1.{random.randint(2, 254)}"
    elif random.random() < 0.8:
        return f"10.0.{random.randint(1, 10)}.{random.randint(2, 250)}"
    else:
        return f"{random.randint(45, 212)}.{random.randint(10, 250)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

def send_attacks(target_ip=TARGET_IP, target_port=TARGET_PORT, delay=1.4):
    url = f"http://{target_ip}:{target_port}/receive_log"
    print("=" * 68)
    print(f" [*] Cyber Rakshak Real-Time Cyberattack Generator Active")
    print(f" [*] Targeting IDS Engine: {url}")
    print(f" [*] Firing continuous simulated multi-vector cyberattacks...")
    print("=" * 68)

    counter = 0
    while True:
        counter += 1
        # 75% attack, 25% normal traffic to show real-time contrast
        if random.random() < 0.25:
            vector = ATTACK_VECTORS[-1]  # Normal
        else:
            vector = random.choice(ATTACK_VECTORS[:-1])

        src_ip = generate_ip()
        cpu_val = round(random.uniform(*vector["cpu_range"]), 1)
        fwd_count = random.randint(*vector["fwd_pkts"])
        mem_val = round(random.uniform(19.0, 26.5), 1)

        payload = {
            "IP": src_ip,
            "Flow Duration": random.randint(150, 12500),
            "Total Fwd Packets": fwd_count,
            "Total Backward Packets": random.randint(1, fwd_count + 10),
            "Fwd Packet Length Mean": round(random.uniform(40.0, 1420.0), 2),
            "CPU Usage": cpu_val,
            "Memory": mem_val,
            "Request Type": vector["name"],
            "Protocol": vector["protocol"]
        }

        try:
            t0 = time.time()
            resp = requests.post(url, json=payload, timeout=3.0)
            lat_ms = round((time.time() - t0) * 1000, 1)

            if resp.status_code == 200:
                res_data = resp.json()
                action = res_data.get("action", "processed").upper()
                if vector["name"] != "Normal":
                    print(f" [!] #{counter:04d} | ATTACK: {vector['name']:<26} | IP: {src_ip:<15} | Action: {action} ({lat_ms}ms)")
                else:
                    print(f" [*] #{counter:04d} | NORMAL: Traffic Flow              | IP: {src_ip:<15} | Action: {action} ({lat_ms}ms)")
            else:
                print(f" [?] HTTP {resp.status_code} from IDS: {resp.text}")

        except Exception as e:
            print(f" [!] Connection error targeting {url}: {e}")

        time.sleep(delay)

if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else TARGET_IP
    port = int(sys.argv[2]) if len(sys.argv) > 2 else TARGET_PORT
    speed = float(sys.argv[3]) if len(sys.argv) > 3 else 1.3
    send_attacks(ip, port, speed)
