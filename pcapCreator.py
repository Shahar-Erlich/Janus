from scapy.all import *

source_address = "192.168.0.10"
destination_address = "192.168.1.20"

packet1 = Ether()/IP(src=source_address, dst=destination_address)/UDP(sport=1234, dport=8080)/b"hello"
packet2 = Ether()/IP(src=source_address, dst=destination_address)/UDP(sport=1234, dport=8080)/b"test"
packet3 = Ether()/IP(src=source_address, dst=destination_address)/UDP(sport=1234, dport=8080)/b"hi"


wrpcap("Pcap_Parser/pcaps/test_pcap.pcap", [packet1, packet2, packet3])
