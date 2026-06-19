import scapy.all as scapy
import sys
import copy

INTERFACE = scapy.conf.iface.name

arp_table = {}
previous_arp_table = {}


def gm(ip):
    try:
        ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip), timeout=3, verbose=False)
        if ans:
            return ans[0][1].hwsrc.lower()
    except Exception:
        pass
    return None


GATEWAY_IP = scapy.conf.route.route("0.0.0.0")[2]
GATEWAY_MAC = gm(GATEWAY_IP)

if not GATEWAY_MAC:
    print("Failed to resolve gateway MAC")
    sys.exit(1)


def fpo(mac, exclude_ip):
    for ip, known_mac in previous_arp_table.items():
        if ip != exclude_ip and known_mac == mac:
            return ip
    return None


def alert(ip, old_mac, new_mac, owner=None):
    if owner:
        print(f"ARP poisoning detected on {ip} old MAC {old_mac} new MAC {new_mac} likely attacker {owner}")
    else:
        print(f"ARP poisoning detected on {ip} old MAC {old_mac} new MAC {new_mac}")



def process_packet(packet):
    global previous_arp_table

    if not packet.haslayer(scapy.ARP):
        return
    
    arp = packet[scapy.ARP]
    if arp.op != 2:
        return
    
    ip = arp.psrc
    mac = arp.hwsrc.lower()
    previous_arp_table = copy.deepcopy(arp_table)
    if ip not in arp_table:
        arp_table[ip] = mac
        return
    
    old_mac = arp_table[ip]
    if old_mac == mac:
        return
    
    arp_table[ip] = mac
    owner = fpo(mac, ip)
    alert(ip, old_mac, mac, owner)


print(f"Starting ARP monitor on {INTERFACE}")

try:
    scapy.sniff(iface=INTERFACE, filter="arp", store=False, prn=process_packet)
except KeyboardInterrupt:
    print("Stopping ARP monitor")
    sys.exit(0)
