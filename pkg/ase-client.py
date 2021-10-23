#!/usr/bin/env python3

import argparse
import os
from scapy.all import Ether,IP,ICMP,Raw,get_working_ifaces,raw,sendp
import sys

def get_identifier():
    # 65535 = 0xffff
    identifier = os.getpid() % 65535

    return identifier

def construct_echo_request():
    pass

def display_packet_info(packet):
    print('##### Raw Packet Bytes #####')
    print(raw(packet))
    print()
    packet.show()
