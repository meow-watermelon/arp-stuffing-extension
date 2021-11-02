#!/usr/bin/env python3

import ipaddress
import os
import re
from scapy.all import Ether,IP,ICMP,Raw,get_working_ifaces,hexdump,raw,sendp,sniff,srp,srp1,IPSession
import signal
import sys
import time

def signal_handler(signal_number, frame):
    print('Signal %s is captured, triggering cleanup task ...' %(signal_number))
    cleanup()
    sys.exit(0)

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
        packet_payload['icmp_data'] = ""

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

def get_ethernet_interface_name(ethernet_mac_address):
    ethernet_interface_name = None

    for interface in get_working_ifaces():
        if interface.mac == ethernet_mac_address:
            ethernet_interface_name = interface.name
            break

    return ethernet_interface_name

def setup_network(packet_payload):
    pass

def backup_network_config(timestamp, config_dict):
    network_config_backup_dir = '/var/run/ase-backup'

    # if the backup directory does not exist, create one
    if not os.path.exists(network_config_backup_dir):
        try:
            os.mkdir(network_config_backup_dir)
        except:
            # return False if cannot create the backup directory
            return False

    # backup address configs, return False if failed to save
    ip_address_backup_filename = network_config_backup_dir+'/ip_address.'+str(timestamp)
    ip_address_returncode = os.system('ip address save > '+ip_address_backup_filename)

    if ip_address_returncode != 0:
        return False
    else:
        print('IP Address Configs saved at %s' %(ip_address_backup_filename))

    # backup route table configs, return False if failed to save
    ip_route_table_backup_filename = network_config_backup_dir+'/ip_route_table.'+str(timestamp)
    ip_route_table_returncode = os.system('ip route save table 0 > '+ip_route_table_backup_filename)
 
    if ip_route_table_returncode != 0:
        return False
    else:
        print('IP Route Table Configs saved at %s' %(ip_route_table_backup_filename))

    # backup rule configs, return False if failed to save
    ip_rule_backup_filename = network_config_backup_dir+'/ip_rule.'+str(timestamp)
    ip_rule_returncode = os.system('ip rule save > '+ip_rule_backup_filename)

    if ip_rule_returncode != 0:
        return False
    else:
        print('IP Rule Configs saved at %s' %(ip_rule_backup_filename))

    # update the config dict only when all backups are saved properly
    config_dict['ip_address_backup_filename'] = ip_address_backup_filename
    config_dict['ip_route_table_backup_filename'] = ip_route_table_backup_filename
    config_dict['ip_rule_backup_filename'] = ip_rule_backup_filename

    return True

def rollback_network_config():
    pass

def build_echo_reponse_packet(packet_payload):
    # Ethernet frame header
    ether_type = 2048 # 0x0800

    # IP packet header
    ip_version = 4
    ip_ttl = 64
    ip_proto = 1

    # ICMP message header
    icmp_type = 0
    icmp_code = 0
    icmp_id = packet_payload['icmp_id']
    icmp_seq = packet_payload['icmp_seq']

    # construct Echo Reply packet
    try:
        echo_reply_request = Ether(dst=packet_payload['ether_src'], src=packet_payload['ether_dst'], type=ether_type)/IP(version=ip_version, ttl=ip_ttl, proto=ip_proto, src=packet_payload['ip_dst'], dst=packet_payload['ip_src'])/ICMP(type=icmp_type, code=icmp_code, id=icmp_id, seq=icmp_seq)/Raw(load=packet_payload['icmp_data'])
    except Exception as e:
        return False
    else:
        return echo_reply_request

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

def cleanup():
    pass

if __name__ == '__main__':
    # define the packet magic number
    magic_number = 'f789ea3b6958a7b09fc9e282c1a4bb44e9fc504a8bf59fc46'

    # define a dict to store ICMP Echo Request
    icmp_echo_request_dict = {}

    # define a dict to store configs
    ase_config_dict = {}

    # initialize timestamp
    timestamp = int(time.time())

    # register the signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # scapy needs superuser permission to send packets. check EUID and exit if it's not root user
    euid = os.geteuid()
    if euid != 0:
        print('Please run this utility under root user permission.')
        sys.exit(2)

    # start sniffing(ICMP Type 8) and stop if an ICMP Echo Rquest packet with the defined magic number is received
    sniff(filter='icmp and ip[20] == 8', session=IPSession, lfilter=lambda p: get_payload(p, icmp_echo_request_dict), stop_filter=lambda p: sniff_stop_callback(p, magic_number))

    # print the ICMP Echo Request fields from the icmp_echo_request_dict
    print('##### ICMP Echo Request Packet Data Payload Fields #####')
    for k,v in icmp_echo_request_dict.items():
        print(k+': '+str(v))
    print()

    # determine the ethernet interface name from the icmp_echo_request_dict
    ethernet_interface_name = get_ethernet_interface_name(icmp_echo_request_dict['ether_dst'])
    ase_config_dict['ethernet_interface_name'] = ethernet_interface_name

    print('##### Ethernet Interface Information #####')
    print('Ethernet Interface Name: %s' %(ethernet_interface_name))
    print('Ethernet Interface MAC Address: %s' %(icmp_echo_request_dict['ether_dst']))
    print()

    # backup network configurations
    print('##### Backing up Network Configurations #####')
    backup_flag = backup_network_config(timestamp, ase_config_dict)
    print()

    # if backup_flag is True, then we can rollback the network configurations
    if backup_flag:
        ase_config_dict['rollback_availability'] = True
    else:
        ase_config_dict['rollback_availability'] = False

    # set up network configurations

    # send back Echo Reply to the Client
    echo_reply_packet = build_echo_reponse_packet(icmp_echo_request_dict)

    if not echo_reply_packet:
        # failed to build the Echo Reply packet, exit
        print('Failed to build the Echo Reply.')
        sys.ext(4)
    else:
        # display packet information
        display_packet_info(echo_reply_packet)

        # send ICMP Echo Reply packet
        # send 3 packets in case packet loss encountered
        sendp(echo_reply_packet, iface=ethernet_interface_name, count=3, inter=5)
