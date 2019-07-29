"""Server of StegBlocks TCP Method

This script simulates the server side of the server-client telecommunication using the StegBlocks TCP method.
It receives packets sent from the clients and decode the message.
Message is decoded by counting the packets captured through the ports, one block represents one integer value of the three digit representation of the ASCII character.
The character is written into the resulting file, the process repeats until the whole message is received.
The script uses Scapy as the tool to manage packets, and requires Scapy be installed within Python environment.

This script listens for network traffics from the client IP address sent to the open ports of the server.

Author: Tim Lei
"""

#!/usr/bin/env python

import time
from scapy.all import *
from collections import Counter

# IP addresses, gatekeeper ports, open ports of server, and decode table
SRC_IP = '127.0.0.1'
DST_IP = '127.0.0.1'
GATEKEEPER1 = [65300, 65301]
GATEKEEPER2 = [65310, 65311]
GATEKEEPER3 = [65320, 65321]
PORTS1 = [65302, 65303, 65304, 65305, 65306, 65307, 65308]
PORTS2 = [65312, 65313, 65314, 65315, 65316, 65317, 65318]
PORTS3 = [65322, 65323, 65324, 65325, 65326, 65327, 65328]
ENDPORT = [65309, 65319, 65329]
end_of_client1, end_of_client2, end_of_client3 = False, False, False


# Create Packet Counters
packet_counts1 = Counter()
packet_counts2 = Counter()
packet_counts3 = Counter()

int_string1 = ''
int_string2 = ''
int_string3 = ''

f1 = open('result1.txt', 'a+')
f2 = open('result2.txt', 'a+')
f3 = open('result3.txt', 'a+')

# Define Custom Action function
def custom_action(packet):
    # Update key of destination port in Counter
    if (packet[0][1].dport in PORTS1):
        packet_counts1.update([packet[0][1].dport])
    elif (packet[0][1].dport in PORTS2):
        packet_counts2.update([packet[0][1].dport])
    elif (packet[0][1].dport in PORTS3):
        packet_counts3.update([packet[0][1].dport])

# Define Stop Filter function
def stopfilter(packet):
    global end_of_client1, end_of_client2, end_of_client3
    global packet_counts1, packet_counts2, packet_counts3
    global f1, f2, f3
    global int_string1, int_string2, int_string3

    if (packet['TCP'].dport in ENDPORT):
        if (ENDPORT.index(packet['TCP'].dport) == 0):
            f1.close()
            end_of_client1 = True
        elif (ENDPORT.index(packet['TCP'].dport) == 1):
            f2.close()
            end_of_client2 = True
        else:
            f3.close()
            end_of_client3 = True

    if (end_of_client1 == True and end_of_client2 == True and end_of_client3 == True):
        return True

    # Sum up the number of packets send through the gatekeeper ports,
    # write the result to text file and resets the packet counter
    if (packet['TCP'].dport == GATEKEEPER1[1]):
        packet_sum = sum(packet_counts1.values())
        int_string1 += str(packet_sum)
        if (len(int_string1) == 3):
            f1.write(chr(int(int_string1)))
            int_string1 = ''
        packet_counts1 = Counter()

    elif (packet['TCP'].dport == GATEKEEPER2[1]):
        packet_sum = sum(packet_counts2.values())
        int_string2 += str(packet_sum)
        if (len(int_string2) == 3):
            f2.write(chr(int(int_string2)))
            int_string2 = ''
        packet_counts2 = Counter()

    elif (packet['TCP'].dport == GATEKEEPER3[1]):
        packet_sum = sum(packet_counts3.values())
        int_string3 += str(packet_sum)
        if (len(int_string3) == 3):
            f3.write(chr(int(int_string3)))
            int_string3 = ''
        packet_counts3 = Counter()

    return False

def main():
    # Sniff until the all end ports receive a packet
    sniff(filter="ip host 127.0.0.1", prn=custom_action, stop_filter=stopfilter)


if __name__== '__main__':
    start_time = time.time()
    main()
    print(time.time() - start_time)
