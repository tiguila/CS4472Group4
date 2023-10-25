from scapy.all import *

intermediate_router = True
TTL = 1
while intermediate_router:
    # destination IP we want to send a packet to (i.e., Google)
    a = IP(dst='8.8.8.8', ttl=TTL)
    response = sr1(a/ICMP(),timeout=1,verbose=0)
    if response is None:
        print(str(TTL) +  " time-to-live has exceeded")
    
    # reached restination
    elif response.type == 0:
        print("TTL: " + str(TTL) + ", Router IP: " + response.src)
        intermediate_router = False
    
    # intermediate router IP addresses
    else:
        print("TTL: " + str(TTL) + ", Rounter IP: " + response.src)
    
    TTL = TTL + 1
