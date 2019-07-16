#!/usr/bin/env python
import scapy.all
import argparse

def get_armgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "-IP", dest="target", help="IP address to get the addresses.")
    options = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.all.ARP(pdst=ip)
    broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.all.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for i in answered:
        client_dict = {"ip": i[1].psrc, "mac": i[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_result(result_list):
    print("IP\t\t\tMAC\n----------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_armgs()
scan_result = scan(options.target)
print_result(scan_result)
