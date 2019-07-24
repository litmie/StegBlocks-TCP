"""Client of StegBlocks TCP Method

This script simulates the client side of the server-client telecommunication using the StegBlocks TCP method. The number of packets sent based on the encoding of the encode table.
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
GATEKEEPER = [65300, 65301]
PORTS = [65302, 65303, 65304, 65305, 65306, 65307, 65308]
ENDPORT = 65309
encode = {'0':0, '1':1, '2':2, '3':3, '4':4, '5':5, '6':6, '7':7, '8':8, '9':9, ' ':10, '.':11, '\n':12, 'a':13, 'b':14, 'c':15, 'd':16, 'e':17, 'f':18, 'g':19, 'h':20, 'i':21, 'j':22, 'k':23, 'l':24, 'm':25,
        'n':26, 'o':27, 'p':28, 'q':29, 'r':30, 's':31, 't':32, 'u':33, 'v':34, 'w':35, 'x':36, 'y':37, 'z':38}

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
        size = encode[char]
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
