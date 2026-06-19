import scapy.all as scapy

INTERFACE = scapy.conf.iface.name

def gm(ip):
    print(f"[*] Resolving MAC for {ip}...")
    try:
        ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), timeout=2, verbose=False)
    except Exception:
        pass
    return ans[0][1].hwsrc if ans else None

GATEWAY_IP = scapy.conf.route.route("0.0.0.0")[2]
GATEWAY_MAC = gm(GATEWAY_IP)