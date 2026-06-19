import scapy.all as scapy
import sys

INTERFACE = scapy.conf.iface.name

def gm(ip):
    print(f"[*] Resolving authentic MAC for gateway ({ip})...")
    try:
        ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), timeout=3, verbose=False)
        if ans:
            return ans[0][1].hwsrc
    except Exception as e:
        pass
    return None

GATEWAY_IP = scapy.conf.route.route("0.0.0.0")[2]
GATEWAY_MAC = gm(GATEWAY_IP)

if not GATEWAY_MAC:
    print("Could not resolve gateway MAC address, exiting...")
    sys.exit(1)

print(f"Starting sniffer on {INTERFACE}...")

def pp(packet):
    if packet.haslayer(scapy.ARP):
        if packet[scapy.ARP].op == 2:
            src_ip = packet[scapy.ARP].psrc
            src_mac = packet[scapy.ARP].hwsrc
            if src_mac.lower() != GATEWAY_MAC.lower() and src_ip == GATEWAY_IP:
                print(f"ARP Spoofing Detected, Source of attack: {src_mac} \n")
                print(f"Source IP of the attack: {src_ip}")

try:
    scapy.sniff(iface=INTERFACE, filter="arp", store=False, prn=pp)
except KeyboardInterrupt:
    print("Stopping sniffing")