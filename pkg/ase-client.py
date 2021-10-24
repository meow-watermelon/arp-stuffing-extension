#!/usr/bin/env python3

import argparse
import os
from scapy.all import Ether,IP,ICMP,Raw,get_working_ifaces,hexdump,raw,sendp
import sys

def get_identifier():
    # 65535 = 0xffff
    identifier = os.getpid() % 65535

    return identifier

def construct_data_payload(*args):
    data_payload = args
    data_payload_string = '|'.join(data_payload)

    return data_payload_string

def build_echo_request_packet(eth_hw_src, eth_hw_dst, ip_src, ip_dst, data_payload_string):
    # Ethernet frame header
    ether_type = 2048 # 0x0800

    # IP packet header
    ip_version = 4
    ip_ttl = 64
    ip_proto = 1

    # ICMP message header
    icmp_type = 8
    icmp_code = 0
    icmp_id = get_identifier()
    icmp_seq = 0

    # construct Echo Request packet
    try:
        echo_request_packet = Ether(dst=eth_hw_dst, src=eth_hw_src, type=ether_type)/IP(version=ip_version, ttl=ip_ttl, proto=ip_proto, src=ip_src, dst=ip_dst)/ICMP(type=icmp_type, code=icmp_code, id=icmp_id, seq=icmp_seq)/Raw(load=data_payload_string)
    except Exception as e:
        return False
    else:
        return echo_request_packet

def display_packet_info(packet):
    print('##### Raw Packet Bytes #####')
    print(raw(packet))
    print()
    packet.show()
    print()
    print(hexdump(packet))
    print()

def display_interfaces_info():
    interfaces_list = []

    for interface in get_working_ifaces():
        if_name = interface.name
        if_mac = interface.mac

        interfaces_list.append(if_name+'|'+if_mac)

    return ' '.join(interfaces_list)

if __name__ == '__main__':
    # set up command arguments
    parser = argparse.ArgumentParser(description='ARP Stuffing Extension Client - Scapy Version')
    parser.add_argument('--ethersrc', type=str, required=True, help='Ethernet source hardware address')
    parser.add_argument('--etherdst', type=str, required=True, help='Ethernet destination hardware address')
    parser.add_argument('--ipsrc', type=str, required=True, help='Source IP address')
    parser.add_argument('--ipdst', type=str, required=True, help='Destination IP address ')
    parser.add_argument('--dstipnetmask', type=str, required=True, help='Destination IP netmask')
    parser.add_argument('--dstbroadcastip', type=str, required=True, help='Destination broadcast IP address')
    parser.add_argument('--dstgatewayip', type=str, required=False, default='', help='Destination gateway IP address')
    parser.add_argument('--dstgatewaynetmask', type=str, required=False, default='', help='Destination gateway netmask')
    parser.add_argument('--dstdns1ip', type=str, required=False, default='', help='Destination DNS1 IP address')
    parser.add_argument('--dstdns2ip', type=str, required=False, default='', help='Destination DNS2 IP address')
    parser.add_argument('--dstdns3ip', type=str, required=False, default='', help='Destination DNS3 IP address')
    parser.add_argument('--interface', type=str, required=True, help='Interface to send ICMP request (interfaces: %s)' %(display_interfaces_info()))
    args = parser.parse_args()

    # scapy needs superuser permission to send packets. check EUID and exit if it's not root user
    euid = os.geteuid()
    if euid != 0:
        print('Please run this utility under root user permission.')
        sys.exit(2)

    # build Echo Request data payload
    # order of argeuments:
    # Target Host IP Address|Target Host IP Netmask|Target Host Broadcast IP Address|Getway IP Address|Gateway Netmask|DNS1 IP Address|DNS2 IP Address|DNS3 IP Address
    echo_request_data_payload = construct_data_payload(args.ipdst, args.dstipnetmask, args.dstbroadcastip, args.dstgatewayip, args.dstgatewaynetmask, args.dstdns1ip, args.dstdns2ip, args.dstdns3ip)

    print('##### Echo Request Data Payload #####')
    print()
    print('Data Payload String: %s\n' %(echo_request_data_payload))
    print('Target Host IP Address: %s' %(args.ipdst))
    print('Target Host IP Netmask: %s' %(args.dstipnetmask))
    print('Target Host Broadcast IP Address: %s' %(args.dstbroadcastip))
    print('Getway IP Address: %s' %(args.dstgatewayip))
    print('Gateway Netmask: %s' %(args.dstgatewaynetmask))
    print('DNS1 IP Address: %s' %(args.dstdns1ip))
    print('DNS2 IP Address: %s' %(args.dstdns2ip))
    print('DNS3 IP Address: %s' %(args.dstdns3ip))
    print()

    # build Echo Request packet
    echo_request_packet = build_echo_request_packet(args.ethersrc, args.etherdst, args.ipsrc, args.ipdst, echo_request_data_payload)

    if not echo_request_packet:
        # failed to build the Echo Request packet, exit
        print('Failed to build the Echo Request.')
        sys.exit(3)
    else:
        # display packet information
        display_packet_info(echo_request_packet)

        # send ARP request every 1 second
        sendp(echo_request_packet, iface=args.interface, count=1)
