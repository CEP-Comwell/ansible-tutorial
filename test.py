from scapy.all import Ether, sendp

def generate_lldp_packet():
    lldp_packet = Ether(dst="01:80:c2:00:00:0e", type=0x88cc) / b"\x02\x07\x04\x00\x01\x02\x03\x04\x05\x06\x00\x00"
    return lldp_packet

def send_lldp_packet(interface):
    packet = generate_lldp_packet()
    sendp(packet, iface=interface)
    print(f"Sent LLDP packet on {interface}")

if __name__ == "__main__":
    interface = "eth0"  # Replace with your network interface
    send_lldp_packet(interface)
