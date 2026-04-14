import time
import re
import subprocess
import os
from collections import defaultdict

# ================= CONFIGURATION =================
LOG_FILE = "/var/log/auth.log"
THRESHOLD = 5            # Number of failed attempts before blocking
BLOCK_DURATION = 300     # Time in seconds to stay blocked (5 minutes)
ALERT_EMAIL = "root"     # Local user to receive Postfix alerts
# =================================================

# Global dictionaries to track state
failed_attempts = defaultdict(int)
blocked_ips = {}

def send_alert(ip):
    """Sends an email alert using the local Postfix/mailutils setup."""
    subject = "SECURITY ALERT: SSH Brute Force Detected"
    body = f"The IP address {ip} has been blocked after {THRESHOLD} failed login attempts."
    try:
        # Use mailutils to send the alert
        os.system(f'echo "{body}" | mail -s "{subject}" {ALERT_EMAIL}')
        print(f"[MAIL] Alert sent to {ALERT_EMAIL}")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")

def block_ip(ip):
    """Adds the IP to UFW deny list and records the timestamp."""
    print(f"[!] THRESHOLD REACHED: Blocking {ip}...")
    try:
        subprocess.run(["sudo", "ufw", "deny", "from", ip], check=True, capture_output=True)
        blocked_ips[ip] = time.time()
        send_alert(ip)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] UFW block failed for {ip}: {e}")

def unblock_ips():
    """Checks the list of blocked IPs and removes them if time has expired."""
    current_time = time.time()
    # Use list() to avoid 'dictionary changed size during iteration' error
    for ip in list(blocked_ips.keys()):
        block_start = blocked_ips[ip]
        if current_time - block_start >= BLOCK_DURATION:
            print(f"[*] TIMEOUT: Unblocking {ip}...")
            try:
                subprocess.run(["sudo", "ufw", "delete", "deny", "from", ip], check=True, capture_output=True)
                del blocked_ips[ip]
                # Reset failure count so they can be blocked again if they retry
                failed_attempts[ip] = 0 
            except subprocess.CalledProcessError as e:
                print(f"[ERROR] UFW unblock failed for {ip}: {e}")

def monitor_logs():
    """Main loop to tail the auth.log file."""
    print(f"[*] Starting Monitoring on {LOG_FILE}")
    print(f"[*] Settings: Threshold={THRESHOLD}, Block Time={BLOCK_DURATION}s")
    
    try:
        # Open file and move pointer to the end (tail -f behavior)
        with open(LOG_FILE, "r") as f:
            f.seek(0, 2) 
            
            while True:
                # CRITICAL FIX: Run unblock check every iteration, 
                # even if no new log lines are coming in.
                unblock_ips()

                line = f.readline()
                if not line:
                    time.sleep(1) # Wait for new log entries
                    continue

                # Check for "Failed password" pattern
                if "Failed password" in line:
                    # Extract IP address using Regex
                    ip_match = re.search(r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        failed_attempts[ip] += 1
                        print(f"[ATTEMPT] {failed_attempts[ip]}/{THRESHOLD} from {ip}")

                        if failed_attempts[ip] >= THRESHOLD and ip not in blocked_ips:
                            block_ip(ip)

    except KeyboardInterrupt:
        print("\n[!] Monitor stopped by user.")
    except PermissionError:
        print("[ERROR] Access denied. Please run with 'sudo'.")
    except FileNotFoundError:
        print(f"[ERROR] Could not find {LOG_FILE}. Is SSH installed?")

if __name__ == "__main__":
    monitor_logs()
                    
