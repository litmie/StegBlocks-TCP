from scapy.all import *

sum = 0
with open("testcase1.txt") as f:
    while (True):
        char = f.read(1)
        if not char:
            break
        sum = sum + ord(char) + 2
sum += 1
print(sum)
f.close()
