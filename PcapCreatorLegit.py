from scapy.all import IP, TCP, UDP, wrpcap
import random
from pathlib import Path

SRC = "192.168.0.13"
DST = "192.168.1.20"
PORT = 8080

TOTAL_PACKETS = 10_000
OUT_FILES = [
    "pcaps/companyTraffic_10k_1.pcap",
    "pcaps/companyTraffic_10k_2.pcap",
    "pcaps/companyTraffic_10k_3.pcap",
]

SEED = 2026
random.seed(SEED)

packets = []

# ----------------------------
# Helpers
# ----------------------------

def grow(payload: bytes, target: int = 500, fill: bytes = b" ") -> bytes:
    if len(payload) >= target:
        return payload[:target]
    return payload + fill * (target - len(payload))


def tcp_packet(payload: bytes, sport: int | None = None, dport: int = PORT):
    if sport is None:
        sport = random.randint(20_000, 60_000)
    return IP(src=SRC, dst=DST) / TCP(sport=sport, dport=dport) / payload


def udp_packet(payload: bytes, sport: int | None = None, dport: int = PORT):
    if sport is None:
        sport = random.randint(20_000, 60_000)
    return IP(src=SRC, dst=DST) / UDP(sport=sport, dport=dport) / payload


def split_payload(payload: bytes, parts: int = 4) -> list[bytes]:
    size = max(1, len(payload) // parts)
    chunks = [payload[i * size:(i + 1) * size] for i in range(parts - 1)]
    chunks.append(payload[(parts - 1) * size:])
    return [chunk for chunk in chunks if chunk]


def tcp_flow_chunks(chunks: list[bytes], sport: int | None = None, dport: int = PORT):
    if sport is None:
        sport = random.randint(20_000, 60_000)
    return [tcp_packet(chunk, sport=sport, dport=dport) for chunk in chunks]


def http_get(path: str, host: str = "intranet.company.local") -> bytes:
    return grow(
        (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: CompanyPortal/5.4\r\n"
            f"Accept: application/json\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()
    )


def http_post(path: str, body: str, host: str = "api.company.local") -> bytes:
    body_bytes = body.encode()
    header = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: CompanyPortal/5.4\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"\r\n"
    ).encode()
    return grow(header + body_bytes)


def json_event(service: str, status: str, extra: str = "") -> bytes:
    return grow(
        (
            "{"
            f"\"service\":\"{service}\","
            f"\"status\":\"{status}\","
            f"\"message\":\"normal business telemetry\","
            f"\"extra\":\"{extra}\""
            "}"
        ).encode()
    )


# ----------------------------
# Normal company traffic
# Should usually NOT hit VF.
# ----------------------------

NORMAL_HTTP = [
    http_get("/dashboard"),
    http_get("/api/status"),
    http_get("/api/employees/summary"),
    http_get("/static/app.bundle.js"),
    http_get("/static/styles.css"),
    http_get("/assets/logo.svg"),
    http_get("/health"),
    http_get("/metrics"),
    http_post("/api/timesheet/submit", '{"employee":"e1029","hours":8,"project":"janus-demo"}'),
    http_post("/api/chat/message", '{"room":"engineering","text":"daily sync moved to 10"}'),
    http_post("/api/expenses", '{"amount":42.5,"category":"travel","approved":true}'),
]

NORMAL_TELEMETRY = [
    json_event("auth-service", "ok", "login success"),
    json_event("crm-service", "ok", "customer profile fetched"),
    json_event("inventory", "ok", "stock level synced"),
    json_event("billing", "ok", "invoice generated"),
    json_event("vpn-gateway", "ok", "heartbeat"),
    json_event("mail-relay", "ok", "queue depth normal"),
    grow(b"heartbeat service=printer-floor-2 status=online toner=67"),
    grow(b"backup completed host=fileserver-7 duration=91s result=ok"),
    grow(b"calendar sync completed user=e1029 changed_events=3"),
    grow(b"meeting-room-panel status=available floor=3 room=atlas"),
]

NORMAL_DNS_LIKE = [
    grow(b"query=intranet.company.local type=A txid=1842"),
    grow(b"query=mail.company.local type=A txid=9821"),
    grow(b"query=sso.company.local type=A txid=2331"),
    grow(b"query=updates.company.local type=A txid=7732"),
]

# ----------------------------
# Benign VF collisions
# These are realistic strings that may contain short anchors
# like exec/pass/select/drop/cast/convert/document/etc,
# but should usually fail the deeper Aho/Regex signature.
# ----------------------------

BENIGN_VF_COLLISIONS = [
    http_post("/api/workflow/execute", '{"task":"execute_report","mode":"scheduled","approved":true}'),
    http_post("/api/password-policy", '{"passcodeRequired":true,"rotationDays":90,"note":"policy update"}'),
    http_post("/api/search", '{"query":"select department from directory view","limit":25}'),
    http_post("/api/documents", '{"title":"document.cookie policy review","classification":"internal"}'),
    http_post("/api/data/export", '{"format":"gzip","dataset":"sales_q1","reason":"finance archive"}'),
    http_post("/api/conversion", '{"operation":"convert currency report","from":"EUR","to":"USD"}'),
    http_post("/api/training", '{"topic":"shell scripting basics","audience":"devops interns"}'),
    http_post("/api/status", '{"service":"executor","message":"exec queue empty, no action required"}'),
    grow(b"normal text: employee asked to update profile settings, not database command"),
    grow(b"normal text: cast list for training video uploaded by HR"),
    grow(b"normal text: document cookie policy was reviewed by legal"),
    grow(b"normal text: shell training agenda includes echo variables and aliases"),
]

# ----------------------------
# True suspicious payloads
# Keep this LOW.
# These should prove Aho/Regex still work sometimes.
# ----------------------------

SUSPICIOUS_PAYLOADS = [
    grow(b"union select username,password from accounts"),
    grow(b"delete from users where id=5"),
    grow(b"cat /etc/passwd"),
    grow(b"bash -i"),
    grow(b"<script>alert(1)</script>"),
    grow(b"../../../../etc/passwd"),
]

# Magic/exact file-like payloads.
# Also keep this LOW. These may trigger VF with no regex.
FILE_LIKE_PAYLOADS = [
    grow(bytes.fromhex("25504446") + b"-1.7 internal quarterly report pdf"),
    grow(bytes.fromhex("52617221") + b" internal archive marker"),
    grow(bytes.fromhex("504B0304") + b" zipped attachment payload"),
]

# Some TCP stream split payloads.
# Mostly safe, tiny suspicious.
FRAG_NORMAL_TCP = [
    split_payload(http_post("/api/chat/message", '{"text":"normal split tcp stream across chunks"}'), 4),
    split_payload(http_post("/api/report", '{"name":"monthly report","status":"generated"}'), 4),
]

FRAG_SUSPICIOUS_TCP = [
    split_payload(grow(b"union select username,password from accounts"), 4),
]

stats = {
    "normal_tcp": 0,
    "normal_udp": 0,
    "benign_vf_collision_tcp": 0,
    "benign_vf_collision_udp": 0,
    "suspicious_tcp": 0,
    "suspicious_udp": 0,
    "file_like_tcp": 0,
    "frag_normal_tcp": 0,
    "frag_suspicious_tcp": 0,
    "tcp_packets": 0,
    "udp_packets": 0,
}


def add_stats(pkts):
    for pkt in pkts:
        if UDP in pkt:
            stats["udp_packets"] += 1
        else:
            stats["tcp_packets"] += 1


def pick_event():
    r = random.random()

    # 58% normal TCP business traffic
    if r < 0.58:
        stats["normal_tcp"] += 1
        built = [tcp_packet(random.choice(NORMAL_HTTP + NORMAL_TELEMETRY))]

    # 17% normal UDP telemetry/DNS-ish traffic
    elif r < 0.75:
        stats["normal_udp"] += 1
        built = [udp_packet(random.choice(NORMAL_TELEMETRY + NORMAL_DNS_LIKE))]

    # 12% benign TCP payloads that may trigger VF but usually fail Aho/Regex
    elif r < 0.87:
        stats["benign_vf_collision_tcp"] += 1
        built = [tcp_packet(random.choice(BENIGN_VF_COLLISIONS))]

    # 4% benign UDP payloads that may trigger VF but usually fail Aho/Regex
    elif r < 0.91:
        stats["benign_vf_collision_udp"] += 1
        built = [udp_packet(random.choice(BENIGN_VF_COLLISIONS))]

    # 3% real suspicious TCP
    elif r < 0.94:
        stats["suspicious_tcp"] += 1
        built = [tcp_packet(random.choice(SUSPICIOUS_PAYLOADS))]

    # 1% real suspicious UDP
    elif r < 0.95:
        stats["suspicious_udp"] += 1
        built = [udp_packet(random.choice(SUSPICIOUS_PAYLOADS))]

    # 2% exact/magic file-like payloads
    elif r < 0.97:
        stats["file_like_tcp"] += 1
        built = [tcp_packet(random.choice(FILE_LIKE_PAYLOADS))]

    # 2.5% normal split TCP streams
    elif r < 0.995:
        stats["frag_normal_tcp"] += 1
        built = tcp_flow_chunks(random.choice(FRAG_NORMAL_TCP))

    # 0.5% suspicious split TCP streams
    else:
        stats["frag_suspicious_tcp"] += 1
        built = tcp_flow_chunks(random.choice(FRAG_SUSPICIOUS_TCP))

    add_stats(built)
    return built


while len(packets) < TOTAL_PACKETS:
    built = pick_event()
    remaining = TOTAL_PACKETS - len(packets)

    if len(built) <= remaining:
        packets.extend(built)
    else:
        while len(packets) < TOTAL_PACKETS:
            pkt = tcp_packet(random.choice(NORMAL_HTTP + NORMAL_TELEMETRY))
            packets.append(pkt)
            stats["tcp_packets"] += 1

Path("pcaps").mkdir(parents=True, exist_ok=True)

for out_file in OUT_FILES:
    wrpcap(out_file, packets)

print(f"Generated {len(packets)} packets into {', '.join(OUT_FILES)}")
print()
print("Traffic profile:")
print("  mostly normal company traffic")
print("  small amount of benign VF collisions")
print("  tiny amount of real suspicious traffic")
print()
for k, v in stats.items():
    print(f"{k}: {v}")