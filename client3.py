"""Client of StegBlocks TCP Method

This script simulates the client side of the server-client telecommunication using the StegBlocks TCP method.
A character is selected, convert into three digit integer representation of its ASCII value, each integer value determines the number of packets to sent as a block.
The script uses Scapy as the tool to manage packets, and requires Scapy be installed within Python environment.

The script reads captured packets and opens the text file of information to be send. It reads the text file one character at a time.
It modifies the IP address and ports of the captured packets and send to the server's open ports. Two open ports of the server are selected as gatekeeper to divide the packets into blocks.
Packets send between the gatekeepers are assigned a random open port of the server to send through.

Author: Tim Lei
"""

#!/usr/bin/env python

import time
from scapy.all import *

# IP addresses, gatekeeper ports, open ports of server, and encode table
SRC_IP = '127.0.0.1'
DST_IP = '127.0.0.1'
GATEKEEPER = [65320, 65321]
PORTS = [65322, 65323, 65324, 65325, 65326, 65327, 65328]
ENDPORT = 65329

# Send packets
packets = rdpcap('testpackets6.pcap')
packet_iter = 0
with open('testcase4.txt') as f:
    while True:
        # Read one character at a time
        char = f.read(1)

        # Reach end of file, send a packet to the end-port
        if not char:
            packets[packet_iter]['IP'].dst = DST_IP
            packets[packet_iter]['TCP'].dport = ENDPORT
            packets[packet_iter]['IP'].src = SRC_IP
            del packets[packet_iter]['IP'].chksum
            del packets[packet_iter]['TCP'].chksum
            packets[packet_iter].show2(dump=True)
            send(packets[packet_iter][IP])
            packet_iter += 1
            break

        rep = str(ord(char)).zfill(3)
        for each_char in rep:
            # First gatekeeper
            packets[packet_iter]['IP'].dst = DST_IP
            packets[packet_iter]['TCP'].dport = GATEKEEPER[0]
            packets[packet_iter]['IP'].src = SRC_IP
            del packets[packet_iter]['IP'].chksum
            del packets[packet_iter]['TCP'].chksum
            packets[packet_iter].show2(dump= True)
            send(packets[packet_iter][IP])
            packet_iter += 1

            # Send the number of packets required after encoding
            packet_counter = 0
            size = int(each_char)
            while(packet_counter != size):
                packets[packet_iter]['IP'].dst = DST_IP
                i = random.randrange(len(PORTS))
                packets[packet_iter]['TCP'].dport = PORTS[i]
                packets[packet_iter]['IP'].src = SRC_IP
                del packets[packet_iter]['IP'].chksum
                del packets[packet_iter]['TCP'].chksum
                packets[packet_iter].show2(dump=True)
                send(packets[packet_iter][IP])
                packet_iter += 1
                packet_counter += 1

            # Second gatekeeper
            packets[packet_iter]['IP'].dst = DST_IP
            packets[packet_iter]['TCP'].dport = GATEKEEPER[1]
            packets[packet_iter]['IP'].src = SRC_IP
            del packets[packet_iter]['IP'].chksum
            del packets[packet_iter]['TCP'].chksum
            packets[packet_iter].show2(dump=True)
            send(packets[packet_iter][IP])
            packet_iter += 1
f.close()