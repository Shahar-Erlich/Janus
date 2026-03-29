from scapy.all import IP, TCP, UDP, wrpcap
import random

SRC = "192.168.0.13"
DST = "192.168.1.20"
PORT = 8080

TOTAL_PACKETS = 10_000
OUT_FILES = [
    "pcaps/10kPackets_1.pcap",
    "pcaps/10kPackets_2.pcap",
    "pcaps/10kPackets_3.pcap",
]
SEED = 42

random.seed(SEED)
packets = []

# ----------------------------
# Helpers
# ----------------------------

def grow(payload: bytes, target: int = 700, fill: bytes = b"X") -> bytes:
    if len(payload) >= target:
        return payload[:target]
    return payload + fill * (target - len(payload))

def tcp_packet(payload: bytes, sport: int | None = None):
    if sport is None:
        sport = random.randint(20_000, 60_000)
    return IP(src=SRC, dst=DST) / TCP(sport=sport, dport=PORT) / payload

def udp_packet(payload: bytes):
    sport = random.randint(20_000, 60_000)
    return IP(src=SRC, dst=DST) / UDP(sport=sport, dport=PORT) / payload

def tcp_flow_chunks(chunks: list[bytes], sport: int | None = None):
    if sport is None:
        sport = random.randint(20_000, 60_000)
    return [tcp_packet(chunk, sport=sport) for chunk in chunks]

def split_payload(payload: bytes, parts: int = 4) -> list[bytes]:
    size = len(payload) // parts
    out = [payload[i * size:(i + 1) * size] for i in range(parts - 1)]
    out.append(payload[(parts - 1) * size:])
    return [x for x in out if x]

# ----------------------------
# Payloads aligned to ICD/DPI
# ----------------------------

SAFE_PAYLOADS = [
    grow(b"GET /index.html HTTP/1.1\r\nHost: demo.local\r\n\r\n"),
    grow(b"normal traffic only telemetry device=edge-router cpu=31 mem=42"),
    grow(b"status=ok&message=healthy&session=abcd1234"),
    grow(b"simple telemetry payload metric=good"),
    grow(b"client_ping=1"),
]

# FLAG only
FLAG_PAYLOADS = [
    grow(bytes.fromhex("25504446") + b"-1.7 benign pdf bytes"),      # MAGIC_PDF FLAG
    grow(bytes.fromhex("52617221") + b" harmless rar marker"),       # MAGIC_RAR FLAG
    grow(bytes.fromhex("CAFEBABE") + b"\x01\x02\x03\x04classblob"),  # MAGIC_JAVA_CLASS FLAG
    grow(b"update aa11 set zz=7"),                                   # SQLI_UPDATE FLAG
    grow(b"update demo9 set x=1"),                                   # SQLI_UPDATE FLAG
    grow(b"ls -lah /tmp"),                                           # CMD_LS FLAG
]

# BLOCK only
BLOCK_PAYLOADS = [
    grow(b"union select username,password from accounts"),  # SQLI_UNION_LOWER BLOCK
    grow(b"bash -i"),                                       # CMD_BASH BLOCK
    grow(b"cat /etc/passwd"),                               # CMD_CAT BLOCK
    grow(b"delete from users where id=5"),                  # SQLI_DELETE BLOCK
]

# fragmented TCP for load / reassembly
FRAG_SAFE_TCP = [
    split_payload(grow(b"hello world and normal traffic repeated for stress"), 4),
    split_payload(grow(b"GET /index.html HTTP/1.1\r\nHost: demo.local\r\n\r\n"), 4),
]

FRAG_FLAG_TCP = [
    split_payload(grow(b"update aa11 set zz=7"), 4),
    split_payload(grow(b"update demo9 set x=1"), 4),
]

# ----------------------------
# Mix
# ----------------------------

stats = {
    "safe_tcp": 0,
    "flag_tcp": 0,
    "block_tcp": 0,
    "safe_udp": 0,
    "flag_udp": 0,
    "block_udp": 0,
    "frag_safe_tcp": 0,
    "frag_flag_tcp": 0,
    "tcp_packets": 0,
    "udp_packets": 0,
}

def pick_event():
    r = random.random()

    # 22% safe TCP
    if r < 0.22:
        stats["safe_tcp"] += 1
        built = [tcp_packet(random.choice(SAFE_PAYLOADS))]

    # 18% flag TCP (single packet, reliable)
    elif r < 0.40:
        stats["flag_tcp"] += 1
        built = [tcp_packet(random.choice(FLAG_PAYLOADS))]

    # 20% block TCP (single packet, reliable)
    elif r < 0.60:
        stats["block_tcp"] += 1
        built = [tcp_packet(random.choice(BLOCK_PAYLOADS))]

    # 10% safe UDP
    elif r < 0.70:
        stats["safe_udp"] += 1
        built = [udp_packet(random.choice(SAFE_PAYLOADS))]

    # 12% flag UDP
    elif r < 0.82:
        stats["flag_udp"] += 1
        built = [udp_packet(random.choice(FLAG_PAYLOADS))]

    # 10% block UDP
    elif r < 0.92:
        stats["block_udp"] += 1
        built = [udp_packet(random.choice(BLOCK_PAYLOADS))]

    # 4% fragmented safe TCP
    elif r < 0.96:
        stats["frag_safe_tcp"] += 1
        built = tcp_flow_chunks(random.choice(FRAG_SAFE_TCP))

    # 4% fragmented flag TCP
    else:
        stats["frag_flag_tcp"] += 1
        built = tcp_flow_chunks(random.choice(FRAG_FLAG_TCP))

    for pkt in built:
        if UDP in pkt:
            stats["udp_packets"] += 1
        else:
            stats["tcp_packets"] += 1

    return built

while len(packets) < TOTAL_PACKETS:
    built = pick_event()
    remaining = TOTAL_PACKETS - len(packets)

    if len(built) <= remaining:
        packets.extend(built)
    else:
        while len(packets) < TOTAL_PACKETS:
            pkt = tcp_packet(random.choice(SAFE_PAYLOADS))
            packets.append(pkt)
            stats["tcp_packets"] += 1

for out_file in OUT_FILES:
    wrpcap(out_file, packets)

print(f"Generated {len(packets)} packets into {', '.join(OUT_FILES)}")
for k, v in stats.items():
    print(f"{k}: {v}")