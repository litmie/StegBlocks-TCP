"""Server of StegBlocks TCP Method

This script simulates the server side of the server-client telecommunication using the StegBlocks TCP method. It receives packets sent from the client and decode based on the decode table.
The script uses Scapy as the tool to manage packets, and requires Scapy be installed within Python environment.

This script listens for network traffics from the client IP address sent to the open ports of the server.

Author: Tim Lei
"""

#!/usr/bin/env python

from scapy.all import *
from collections import Counter
import time

# IP addresses, gatekeeper ports, open ports of server, and decode table
SRC_IP = '127.0.0.1'
DST_IP = '127.0.0.1'
GATEKEEPER = [65300, 65301]
PORTS = [65302, 65303, 65304, 65305, 65306, 65307, 65308]
ENDPORT = 65309
decode = {0:' ', 1:'a', 2:'e', 3:'o', 4:'i', 5:'z', 6:'n', 7:'s', 8:'r', 9:'w', 10:'c', 11:'d', 12:'y', 13:'k', 14:'l', 15:'m',
          16:'t', 17:'p', 18:'u', 19:'j', 20:'b', 21:'g', 22:'h', 23:'f', 24:'v', 25:'x', 26:'q'}

packet_counts = Counter()       # Create a Packet Counter
f = open('result.txt', 'a+')

# Define Custom Action function
def custom_action(packet):
    # Create a key of destination port
    if (packet[0][1].dport in PORTS):
        key = packet[0][1].dport
        packet_counts.update([key])

# Define Stop Filter function
def stopfilter(packet):
    global packet_counts

    if (packet['TCP'].dport == ENDPORT):
        return True

    elif (packet['TCP'].dport == GATEKEEPER[1]):
        # Sum up the number of packets send through the gatekeeper ports
        packet_sum = sum(packet_counts.values())

        # Write the decoded result to text file
        f.write(decode[packet_sum])

        # Resets the packet counter
        packet_counts = Counter()

        return False

    else:
        return False

def main():
    # Sniff until the end port receives a packet
    sniff(filter="ip host 127.0.0.1", prn=custom_action, stop_filter=stopfilter)

    # Close the opened text file
    f.close()

if __name__== "__main__":
    start_time = time.time()
    main()
    print(time.time() - start_time)
