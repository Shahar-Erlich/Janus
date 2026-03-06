from scapy.all import *
import random

SRC = "192.168.0.13"
DST = "192.168.1.20"
PORT = 8080

TOTAL_PACKETS = 10000
packets = []

SAFE_PAYLOADS = [
    b"hello world",
    b"normal traffic",
    b"GET /index.html",
    b"user login ok",
]

DANGEROUS_PAYLOADS = [
    b"mkfs.ext4 /dev/sda",
    b"blkdiscard /dev/sda",
]

FRAGMENTED = [
    [b"mk", b"fs.ext4 /dev/sda"],
    [b"blkd", b"iscard /dev/sda"],
]

def tcp_packet(payload):
    sport = random.randint(20000, 60000)
    return IP(src=SRC, dst=DST) / TCP(sport=sport, dport=PORT) / payload

def udp_packet(payload):
    sport = random.randint(20000, 60000)
    return IP(src=SRC, dst=DST) / UDP(sport=sport, dport=PORT) / payload


for _ in range(TOTAL_PACKETS):

    category = random.random()

    # 40% safe TCP
    if category < 0.4:
        payload = random.choice(SAFE_PAYLOADS)
        packets.append(tcp_packet(payload))

    # 30% dangerous TCP
    elif category < 0.7:
        payload = random.choice(DANGEROUS_PAYLOADS)
        packets.append(tcp_packet(payload))

    # 20% fragmented TCP
    elif category < 0.9:
        parts = random.choice(FRAGMENTED)
        for chunk in parts:
            packets.append(tcp_packet(chunk))

    # 10% UDP
    else:
        payload = random.choice(SAFE_PAYLOADS)
        packets.append(udp_packet(payload))


wrpcap("pcaps/10kPackets_3.pcap", packets)

print(f"Generated {len(packets)} packets.")