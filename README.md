# Automated-SSH-Brute-Force-Detection-IP-Blocking-System
A Python-based security automation tool that detects SSH brute-force attacks in real time, dynamically blocks malicious IP addresses using UFW firewall, and generates alert notifications via a local Postfix mail server.

# Overview
This project simulates a real-world Security Operations Center (SOC) use case by implementing automated detection, response, and alerting for SSH brute-force attacks. The system continuously monitors authentication logs (/var/log/auth.log), identifies repeated failed login attempts, and takes immediate action to mitigate threats.

# Technologies Used
Python 3
OpenSSH Server
UFW Firewall
Postfix Mail Server
mailutils
Ubuntu Server

# How It Works
Monitors /var/log/auth.log for failed SSH login attempts
Tracks number of failed attempts per IP
If threshold is exceeded:
Blocks IP using UFW
Sends alert notification via local mail server
Automatically unblocks IP after a defined duration

# Usage
Run the monitoring script:

sudo python3 ssh_monitor.py

Simulate brute-force attack:

for i in {1..6}; do ssh testuser@<target-ip>; done
