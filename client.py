"""Client of StegBlocks TCP Method

This script simulates the client side of the server-client telecommunication using the StegBlocks TCP method. The number of packets sent based on the encoding of the encode table.
The script uses Scapy as the tool to manage packets, and requires Scapy be installed within Python environment.

The script reads captured packets and opens the text file of information to be send. It reads the text file one character at a time.
It modifies the IP address and ports of the captured packets and send to the server's open ports. Two open ports of the server are selected as gatekeeper to divide the packets into blocks.
Packets send between the gatekeepers are assigned a random open port of the server to send through.

Implementation based onthe article "Application of Perfectly Undetectable Network Steganography Method for Malware
Hidden Communication" by K. Szczypiorski, et al.

Author: Tim Lei
"""

#!/usr/bin/env python

import time
from scapy.all import *

# IP addresses, gatekeeper ports, open ports of server, and encode table
SRC_IP = '127.0.0.1'
DST_IP = '127.0.0.1'
GATEKEEPER = [65300, 65301]
PORTS = [65302, 65303, 65304, 65305, 65306, 65307, 65308]
ENDPORT = 65309
encode = {' ':0, 'a':1, 'e':2, 'o':3, 'i':4, 'z':5, 'n':6, 's':7, 'r':8, 'w':9, 'c':10, 'd':11, 'y':12, 'k':13, 'l':14, 'm':15,
          't':16, 'p':17, 'u':18, 'j':19, 'b':20, 'g':21, 'h':22, 'f':23, 'v':24, 'x':25, 'q':26}

# Send packets
packets = rdpcap('test.pcap')
packet_iter = 0
with open('test.txt') as f:
    while True:
        # Read one character at a time
        char = f.read(1)

        # Reach end of file
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
        size = encode[char.lower()]
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

        # Pause one second before sending the next character
        time.sleep(1)
f.close()
