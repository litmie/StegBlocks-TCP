"""Server of StegBlocks TCP Method

This script simulates the server side of the server-client telecommunication using the StegBlocks TCP method. It receives packets sent from the client and decode based on the decode table.
The script uses Scapy as the tool to manage packets, and requires Scapy be installed within Python environment.

This script listens for network traffics from the client IP address sent to the open ports of the server.

Author: Tim Lei
"""

#!/usr/bin/env python

from scapy.all import *
from collections import Counter

# IP addresses, gatekeeper ports, open ports of server, and decode table
SRC_IP = '127.0.0.1'
DST_IP = '127.0.0.1'
GATEKEEPER = [65300, 65301]
PORTS = [65302, 65303, 65304, 65305, 65306, 65307, 65308]
ENDPORT = 65309
decode = {0:'0', 1:'1', 2:'2', 3:'3', 4:'4', 5:'5', 6:'6', 7:'7', 8:'8', 9:'9', 10:' ', 11:'.', 12:'\n', 13:'a', 14:'b', 15:'c', 16:'d', 17:'e', 18:'f', 19:'g', 20:'h', 21:'i', 22:'j', 23:'k', 24:'l', 25:'m',
        26:'n', 27:'o', 28:'p', 29:'q', 30:'r', 31:'s', 32:'t', 33:'u', 34:'v', 35:'w', 36:'x', 37:'y', 38:'z'}

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
  main()
