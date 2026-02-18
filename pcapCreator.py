from scapy.all import *
import random

SRC = "192.168.0.10"
DST = "192.168.1.20"
PORT = 8080

packets = []

# -------------------------
# Payload categories
# -------------------------

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

# Fragmented versions (split anchors across packets)
FRAGMENTED = [
    [b"mk", b"fs.ext4 /dev/sda"],
    [b"blkd", b"iscard /dev/sda"],
]

# -------------------------
# Packet helpers
# -------------------------

def tcp_packet(payload):
    sport = random.randint(20000, 60000)
    return IP(src=SRC, dst=DST) / TCP(sport=sport, dport=PORT) / payload

def udp_packet(payload):
    sport = random.randint(20000, 60000)
    return IP(src=SRC, dst=DST) / UDP(sport=sport, dport=PORT) / payload

# -------------------------
# 1. Safe TCP traffic
# -------------------------

for _ in range(20):
    payload = random.choice(SAFE_PAYLOADS)
    packets.append(tcp_packet(payload))

# -------------------------
# 2. Dangerous TCP traffic
# -------------------------

for _ in range(20):
    payload = random.choice(DANGEROUS_PAYLOADS)
    packets.append(tcp_packet(payload))

# -------------------------
# 3. Fragmented streams
# -------------------------

for _ in range(10):
    parts = random.choice(FRAGMENTED)
    for chunk in parts:
        packets.append(tcp_packet(chunk))

# -------------------------
# 4. UDP noise
# -------------------------

for _ in range(20):
    payload = random.choice(SAFE_PAYLOADS)
    packets.append(udp_packet(payload))

# -------------------------
# Write PCAP
# -------------------------

wrpcap("test_vector_filter.pcap", packets)

print(f"Generated {len(packets)} packets.")

