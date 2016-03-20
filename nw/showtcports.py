import sys
from scapy.all import *

pf = rdpcap(sys.argv[1])

iplist = set([p[IP].src for p in pf if p.haslayer('TCP')])

ip_sports = {}
ip_dports = {}
for p in pf:
    for ip in iplist:
        if p.haslayer('TCP') and p[IP].src == ip and p[TCP].flags == 2:
            if not ip in ip_sports:
                ip_sports[ip] = [p.sport]
            else:
                ip_sports[ip].append(p.sport)
            if not ip in ip_dports:
                ip_dports[ip] = [p.dport]
            else:
                ip_dports[ip].append(p.dport)

print("[*] src ports")
for ip, ports in ip_sports.items():
    print(ip, ports)

print("[*] dst ports")
for ip, ports in ip_dports.items():
    print(ip, ports)
