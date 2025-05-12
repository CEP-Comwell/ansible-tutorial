from scapy.all import ARP, Ether, srp, sniff, load_contrib
import logging

# Load CDP and LLDP modules
load_contrib("cdp")
load_contrib("lldp")

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def resolve_mac(ip):
    try:
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        arp_response = srp(arp_request, timeout=2, verbose=False)[0]
        mac_address = arp_response[0][1].hwsrc if arp_response else None
        logging.info(f"Resolved MAC address for IP {ip}: {mac_address}")
        return mac_address
    except Exception as e:
        logging.error(f"Error resolving MAC address for IP {ip}: {e}")
        return None

def query_cdp_lldp():
    cdp_data = []
    lldp_data = []
    try:
        logging.info("Sniffing CDP packets")
        cdp_packets = sniff(filter="ether dst 01:00:0c:cc:cc:cc", timeout=10)
        logging.info(f"CDP packets captured: {cdp_packets}")
        for packet in cdp_packets:
            if packet.haslayer("CDP"):
                cdp_data.append({
                    "Chassis ID": packet["CDP"].addr,
                    "Port ID": packet["CDP"].portid,
                    "Device ID": packet["CDP"].deviceid
                })
        
        logging.info("Sniffing LLDP packets")
        lldp_packets = sniff(filter="ether dst 01:80:c2:00:00:0e", timeout=10)
        logging.info(f"LLDP packets captured: {lldp_packets}")
        for packet in lldp_packets:
            if packet.haslayer("LLDPDU"):
                lldp_data.append({
                    "Chassis ID": packet["LLDPDU"].chassis_id,
                    "Port ID": packet["LLDPDU"].port_id,
                    "System Name": packet["LLDPDU"].system_name
                })
        
        logging.info(f"CDP data: {cdp_data}")
        logging.info(f"LLDP data: {lldp_data}")
    except Exception as e:
        logging.error(f"Error querying CDP/LLDP: {e}")
    
    return cdp_data, lldp_data

def filter_uplink_ports(data):
    filtered_data = {}
    try:
        for chassis_id, entries in data.items():
            port_mac_count = {}
            for port_id, mac, ip in entries:
                port_mac_count.setdefault(port_id, []).append(mac)
            
            for port_id, macs in port_mac_count.items():
                if len(macs) <= 2:
                    filtered_data.setdefault(chassis_id, []).append((port_id, macs, ip))
        logging.info(f"Filtered data: {filtered_data}")
    except Exception as e:
        logging.error(f"Error filtering uplink ports: {e}")
    
    return filtered_data

def main():
    # List of static IP addresses for the switches
    switch_ips = ["172.16.10.3", "172.16.10.20"]
    
    # Resolve MAC addresses for the switches
    switch_mac_addresses = {ip: resolve_mac(ip) for ip in switch_ips}
    logging.info(f"Switch MAC addresses: {switch_mac_addresses}")
    
    # Query devices on the switches
    cdp_query_data = {}
    lldp_query_data = {}
    for ip in switch_ips:
        cdp, lldp = query_cdp_lldp()
        for entry in cdp:
            cdp_query_data.setdefault(entry["Chassis ID"], []).append(entry)
        for entry in lldp:
            lldp_query_data.setdefault(entry["Chassis ID"], []).append(entry)
    
    filtered_cdp_data = filter_uplink_ports(cdp_query_data)
    filtered_lldp_data = filter_uplink_ports(lldp_query_data)
    
    print("\nFiltered CDP Data:")
    for chassis_id, entries in filtered_cdp_data.items():
        for port_id, macs, ip in entries:
            print(f"Chassis ID: {chassis_id}, Port ID: {port_id}, MAC Addresses: {macs}, IP Address: {ip}")
    
    print("\nFiltered LLDP Data:")
    for chassis_id, entries in filtered_lldp_data.items():
        for port_id, macs, ip in entries:
            print(f"Chassis ID: {chassis_id}, Port ID: {port_id}, MAC Addresses: {macs}, IP Address: {ip}")

if __name__ == "__main__":
    main()
