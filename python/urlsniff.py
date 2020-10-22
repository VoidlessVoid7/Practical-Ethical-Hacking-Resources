from scapy.all import *
from scapy.layers import http


def process_tcp_packet(packet):
    if not packet.haslayer(http.HTTPRequest):
        return
    http_layer = packet.getlayer(http.HTTPRequest)
    ip_layer = packet.getlayer(IP)
    print '\n{0[src]} just requested a {1[Method]} {1[Host]}{1[Path]}'.format(ip_layer.fields, http_layer.fields)


sniff(offline='p1.pcap',filter='tcp', prn=process_tcp_packet)

SYN = 0x02
ACK = 0x10

print('\n\n SYN and ACK: \n\n')
pkts=sniff(offline='p1.pcap',lfilter = lambda x: x.haslayer(TCP) and x[TCP].flags & SYN and x[TCP].flags & ACK, prn=lambda x:x.summary())
print(pkts)
print('\n\nSYN:\n\n')
pkts=sniff(offline='p1.pcap',lfilter = lambda x: x.haslayer(TCP) and x[TCP].flags & SYN, prn=lambda x:x.summary())
print(pkts)
print('\n\nACK:\n\n')
pkts=sniff(offline='p1.pcap',lfilter = lambda x: x.haslayer(TCP) and x[TCP].flags & ACK, prn=lambda x:x.summary(),count=20)
print(pkts)
