#!/usr/bin/python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()


source_ip = '10.0.2.9'
# Capture TCP packets from 'source_ip' to destination port 23 
pkt = sniff(filter='tcp and src host ' + source_ip + ' and dst port 23', prn=print_pkt)
