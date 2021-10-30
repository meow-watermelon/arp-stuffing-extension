#!/usr/bin/env python3

import ipaddress
import os
import re
from scapy.all import Ether,IP,ICMP,Raw,get_working_ifaces,hexdump,raw,sendp,sniff,srp,srp1,IPSession
import sys

def get_payload(packet, packet_payload):
    packet_payload.clear()

    # Ethernet fields
    packet_payload['ether_src'] = packet[Ether].getfieldval('src')
    packet_payload['ether_dst'] = packet[Ether].getfieldval('dst')

    # IP fields
    packet_payload['ip_src'] = packet[IP].getfieldval('src')
    packet_payload['ip_dst'] = packet[IP].getfieldval('dst')

    # ICMP fields
    packet_payload['icmp_id'] = packet[ICMP].getfieldval('id')
    packet_payload['icmp_seq'] = packet[ICMP].getfieldval('seq')

    # Raw Data Payload
    try:
        packet_payload['icmp_data'] = packet[Raw].load.decode('ascii')
    except:
        pass

    return packet_payload

def sniff_stop_callback(packet, magic_number):
    try:
        m = packet[Raw].load.decode('ascii')
    except:
        pass
    else:
        if m.split('|')[0] == magic_number:
            print('##### ARP Stuffing Extention - ICMP Echo Request Received #####')
            print('Magic Number: %s' %(magic_number))
            print()
            return True

def setup_network(packet_payload):
    pass

def build_echo_reponse_packet(packet_payload):
    pass

if __name__ == '__main__':
    # define the packet magic number
    magic_number = 'f789ea3b6958a7b09fc9e282c1a4bb44e9fc504a8bf59fc46'

    # define a dict to store ICMP Echo Request
    icmp_echo_request_dict = {}

    # scapy needs superuser permission to send packets. check EUID and exit if it's not root user
    euid = os.geteuid()
    if euid != 0:
        print('Please run this utility under root user permission.')
        sys.exit(2)

    # start sniffing(ICMP Type 8) and stop if an ICMP Echo Rquest packet with the defined magic number is received
    sniff(filter='icmp and ip[20] == 8', session=IPSession, lfilter=lambda p: get_payload(p, icmp_echo_request_dict), stop_filter=lambda p: sniff_stop_callback(p, magic_number))

    # print the ICMP Echo Request fields from the icmp_echo_request_dict
    print('##### ICMP Echo Request Packet Fields #####')
    for k,v in icmp_echo_request_dict.items():
        print(k+': '+str(v))
