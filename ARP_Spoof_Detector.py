#!usr/bin/env python
import scapy.all as scapy
import sys


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_arp_request = broadcast / arp_request
    answered_list = scapy.srp(broadcast_arp_request, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=sniffed_packet)


def sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            if real_mac != real_mac:
                print("\r[-] You are under attack ", end=""),
                sys.stdout.flush()
            else:
                print("\r[+] Everything looks good ", end=""),
                sys.stdout.flush()
        except ImportError:
            pass
        except KeyboardInterrupt:
            print("[*] Exiting")


sniff("eth0")