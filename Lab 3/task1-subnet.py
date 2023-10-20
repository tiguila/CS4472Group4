#!/usr/bin/python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()


target_subnet = '128.230.0.0/16'
# Capture packets from or to 'target_subnet'
pkt = sniff(filter='net ' + target_subnet, prn=print_pkt)