from scapy.all import *

pkt=sniff(prn=lambda x:x.summary,count=40)
re=wrpcap("p11.pcap",pkt)
pkts=rdpcap("p11.pcap")
sess=pkts.sessions()

for session in sess:
    print(session)