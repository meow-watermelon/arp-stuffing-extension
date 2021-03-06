#!/usr/bin/env python3

import argparse
import ipaddress
import os
from scapy.all import Ether,IP,ICMP,Raw,get_working_ifaces,hexdump,raw,sendp,srp,srp1
import sys

def get_magic_number():
    magic_string = 'arpstuffingextension'
    magic_number_string = ''

    for c in magic_string:
        magic_number_string += str(ord(c))

    magic_number = hex(int(magic_number_string))[2:]

    return magic_number

def get_identifier():
    # 65535 = 0xffff
    identifier = os.getpid() % 65535

    return identifier

def construct_data_payload(*args):
    # order of argeuments:
    # Packet Magic Number|Target Host IP Address|Target Host IP Netmask|Target Host Broadcast IP Address|Gateway IP Address|Gateway Netmask|DNS1 IP Address|DNS2 IP Address|DNS3 IP Address
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
    print(packet.command())
    print()

def get_interfaces_info():
    interfaces_dict = {}

    for interface in get_working_ifaces():
        if_name = interface.name
        if_mac = interface.mac

        interfaces_dict[if_name] = if_mac

    return interfaces_dict

def display_interfaces_info(interfaces_dict):
    interfaces_string = ' '.join([k+'|'+v for k,v in interfaces_dict.items()])

    return interfaces_string

if __name__ == '__main__':
    # pre-set required variables
    interfaces = get_interfaces_info()

    # set up command arguments
    parser = argparse.ArgumentParser(description='ARP Stuffing Extension Client - Scapy Version')
    parser.add_argument('--ethersrc', type=str, required=True, help='Ethernet source hardware address')
    parser.add_argument('--etherdst', type=str, required=True, help='Ethernet destination hardware address')
    parser.add_argument('--ipsrc', type=str, required=True, help='Source IP address')
    parser.add_argument('--ipdst', type=str, required=True, help='Destination IP address ')
    parser.add_argument('--dstipnetmask', type=str, required=True, help='Destination IP netmask')
    parser.add_argument('--dstbroadcastip', type=str, required=False, help='Destination broadcast IP address')
    parser.add_argument('--dstgatewayip', type=str, required=False, default='', help='Destination gateway IP address')
    parser.add_argument('--dstgatewaynetmask', type=str, required=False, default='', help='Destination gateway netmask')
    parser.add_argument('--dstdns1ip', type=str, required=False, default='', help='Destination DNS1 IP address')
    parser.add_argument('--dstdns2ip', type=str, required=False, default='', help='Destination DNS2 IP address')
    parser.add_argument('--dstdns3ip', type=str, required=False, default='', help='Destination DNS3 IP address')
    parser.add_argument('--interface', type=str, required=True, help='Interface to send ICMP request (interfaces: %s)' %(display_interfaces_info(interfaces)))
    parser.add_argument('--timeout', type=int, required=False, default=30, help='Timeout to wait for Echo Response packet (default: 30 secs)')
    args = parser.parse_args()

    # scapy needs superuser permission to send packets. check EUID and exit if it's not root user
    euid = os.geteuid()
    if euid != 0:
        print('Please run this utility under root user permission.')
        sys.exit(2)

    # if destination broadcast IP address is not defined, populate it from subnet mask
    if not args.dstbroadcastip:
        args.dstbroadcastip = str(ipaddress.IPv4Network(args.ipdst+'/'+args.dstipnetmask, strict=False).broadcast_address)

    if args.interface not in interfaces:
        print('%s is not a valid interface name.' %(args.interface))
        sys.exit(3)

    # get magic number
    packet_magic_number = get_magic_number()

    # build Echo Request data payload
    echo_request_data_payload = construct_data_payload(packet_magic_number, args.ipdst, args.dstipnetmask, args.dstbroadcastip, args.dstgatewayip, args.dstgatewaynetmask, args.dstdns1ip, args.dstdns2ip, args.dstdns3ip)

    print('##### Echo Request Data Payload #####')
    print()
    print('Data Payload String: %s\n' %(echo_request_data_payload))
    print('Packet Magic Number: %s' %(packet_magic_number))
    print('Target Host IP Address: %s' %(args.ipdst))
    print('Target Host IP Netmask: %s' %(args.dstipnetmask))
    print('Target Host Broadcast IP Address: %s' %(args.dstbroadcastip))
    print('Gateway IP Address: %s' %(args.dstgatewayip))
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
        sys.exit(4)
    else:
        # display packet information
        display_packet_info(echo_request_packet)

        # send ICMP Echo Request packet
        echo_response_packet = srp1(echo_request_packet, iface=args.interface, retry=3, timeout=args.timeout)

        if echo_response_packet:
            display_packet_info(echo_response_packet)
        else:
            print('Failed to receive Echo Response from the target host.')
            sys.exit(5)
