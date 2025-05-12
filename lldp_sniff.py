from scapy.all import ARP, Ether, srp, sniff

# Function to resolve MAC address using ARP
def resolve_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None

# Function to sniff LLDP packets
def sniff_lldp_packets(interface):
    def lldp_filter(packet):
        return packet.haslayer(Ether) and packet[Ether].type == 0x88cc

    print("Sniffing LLDP packets...")
    sniff(iface=interface, prn=lambda x: x.summary(), lfilter=lldp_filter)

# Main function
if __name__ == "__main__":
    target_ip = "172.16.10.20"  # Replace with the IP address of the switch
    interface = "eth0"  # Replace with your network interface

    mac_address = resolve_mac(target_ip)
    if mac_address:
        print(f"MAC address of {target_ip} is {mac_address}")
        sniff_lldp_packets(interface)
    else:
        print(f"Could not resolve MAC address for {target_ip}")
