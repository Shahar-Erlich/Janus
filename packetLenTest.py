from scapy.all import rdpcap
pkts = rdpcap("pcaps/10kPackets_3.pcap")
print(len(pkts))