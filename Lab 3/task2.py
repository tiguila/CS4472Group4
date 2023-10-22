from scapy.all import *

# Create IP packet with arbitrary source and destination IP addresses
a = IP(src='1.2.3.5', dst='10.0.2.7')

# Create ICMP echo request packet
b = ICMP()

# Stack IP and ICMP layers to form a new packet
p = a/b

# Send the packet
send(p)

ls(a)
