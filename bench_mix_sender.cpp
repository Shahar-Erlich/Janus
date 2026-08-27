#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <random>
#include <string>
#include <thread>
#include <vector>

struct Config
{
    std::string destIp = "192.168.1.30";
    int portBase = 8080;
    int portCount = 16;

    int threads = 4;
    int tcpConnectionsPerThread = 64;
    int udpSocketsPerThread = 32;

    int durationSec = 45;
    int payloadSize = 700;
    int fragParts = 4;
    int pauseUs = 0;

    bool tcpNoDelay = true;
    int sndBufBytes = 1 << 20;

    // mix weights (sum doesn't have to be 100)
    int wTcpSafe = 22;
    int wTcpFlag = 18;
    int wTcpBlock = 20;
    int wUdpSafe = 10;
    int wUdpFlag = 12;
    int wUdpBlock = 8;
    int wFragSafe = 5;
    int wFragFlag = 3;
    int wFragBlock = 2;
};

static std::string getEnvStr(const char *name, const std::string &defVal)
{
    const char *v = std::getenv(name);
    return (v && *v) ? std::string(v) : defVal;
}

static int getEnvInt(const char *name, int defVal)
{
    const char *v = std::getenv(name);
    if (!v || !*v)
        return defVal;

    try
    {
        return std::stoi(v);
    }
    catch (...)
    {
        return defVal;
    }
}

static bool getEnvBool(const char *name, bool defVal)
{
    const char *v = std::getenv(name);
    if (!v || !*v)
        return defVal;

    std::string s(v);
    for (char &c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (s == "1" || s == "true" || s == "yes" || s == "on")
        return true;
    if (s == "0" || s == "false" || s == "no" || s == "off")
        return false;
    return defVal;
}

static Config loadConfig()
{
    Config cfg;
    cfg.destIp = getEnvStr("DEST_IP", cfg.destIp);
    cfg.portBase = getEnvInt("PORT_BASE", cfg.portBase);
    cfg.portCount = getEnvInt("PORT_COUNT", cfg.portCount);

    cfg.threads = getEnvInt("THREADS", cfg.threads);
    cfg.tcpConnectionsPerThread = getEnvInt("TCP_CONNECTIONS_PER_THREAD", cfg.tcpConnectionsPerThread);
    cfg.udpSocketsPerThread = getEnvInt("UDP_SOCKETS_PER_THREAD", cfg.udpSocketsPerThread);

    cfg.durationSec = getEnvInt("DURATION_SEC", cfg.durationSec);
    cfg.payloadSize = getEnvInt("PAYLOAD_SIZE", cfg.payloadSize);
    cfg.fragParts = std::max(2, getEnvInt("FRAG_PARTS", cfg.fragParts));
    cfg.pauseUs = getEnvInt("PAUSE_US", cfg.pauseUs);

    cfg.tcpNoDelay = getEnvBool("TCP_NODELAY", cfg.tcpNoDelay);
    cfg.sndBufBytes = getEnvInt("SNDBUF_BYTES", cfg.sndBufBytes);

    cfg.wTcpSafe = getEnvInt("W_TCP_SAFE", cfg.wTcpSafe);
    cfg.wTcpFlag = getEnvInt("W_TCP_FLAG", cfg.wTcpFlag);
    cfg.wTcpBlock = getEnvInt("W_TCP_BLOCK", cfg.wTcpBlock);
    cfg.wUdpSafe = getEnvInt("W_UDP_SAFE", cfg.wUdpSafe);
    cfg.wUdpFlag = getEnvInt("W_UDP_FLAG", cfg.wUdpFlag);
    cfg.wUdpBlock = getEnvInt("W_UDP_BLOCK", cfg.wUdpBlock);
    cfg.wFragSafe = getEnvInt("W_FRAG_SAFE", cfg.wFragSafe);
    cfg.wFragFlag = getEnvInt("W_FRAG_FLAG", cfg.wFragFlag);
    cfg.wFragBlock = getEnvInt("W_FRAG_BLOCK", cfg.wFragBlock);

    return cfg;
}

static std::string grow(const std::string &seed, std::size_t target, char fill = 'X')
{
    if (seed.size() >= target)
        return seed.substr(0, target);

    std::string out = seed;
    out.resize(target, fill);
    return out;
}

static std::string fromHex(const std::string &hex)
{
    std::string out;
    out.reserve(hex.size() / 2);

    auto nyb = [](char c) -> int
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F')
            return 10 + (c - 'A');
        return -1;
    };

    for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
    {
        int hi = nyb(hex[i]);
        int lo = nyb(hex[i + 1]);
        if (hi < 0 || lo < 0)
            continue;
        out.push_back(static_cast<char>((hi << 4) | lo));
    }

    return out;
}

struct PayloadCatalog
{
    std::vector<std::string> safe;
    std::vector<std::string> flag;
    std::vector<std::string> block;
};

static PayloadCatalog buildCatalog(const Config &cfg)
{
    PayloadCatalog c;

    c.safe = {
        grow("GET /index.html HTTP/1.1\r\nHost: demo.local\r\n\r\n", cfg.payloadSize),
        grow("normal traffic only telemetry device=edge-router cpu=31 mem=42", cfg.payloadSize),
        grow("status=ok&message=healthy&session=abcd1234", cfg.payloadSize),
        grow("simple telemetry payload metric=good", cfg.payloadSize),
        grow("client_ping=1", cfg.payloadSize),
    };

    c.flag = {
        grow(fromHex("25504446") + std::string("-1.7 benign pdf bytes"), cfg.payloadSize),
        grow(fromHex("52617221") + std::string(" harmless rar marker"), cfg.payloadSize),
        grow(fromHex("CAFEBABE") + std::string("\x01\x02\x03\x04classblob", 13), cfg.payloadSize),
        grow("update aa11 set zz=7", cfg.payloadSize),
        grow("update demo9 set x=1", cfg.payloadSize),
        grow("ls -lah /tmp", cfg.payloadSize),
    };

    c.block = {
        grow("union select username,password from accounts", cfg.payloadSize),
        grow("bash -i", cfg.payloadSize),
        grow("cat /etc/passwd", cfg.payloadSize),
        grow("delete from users where id=5", cfg.payloadSize),
    };

    return c;
}

static std::vector<std::string> splitPayload(const std::string &payload, int parts)
{
    std::vector<std::string> out;
    parts = std::max(2, parts);

    std::size_t chunk = payload.size() / static_cast<std::size_t>(parts);
    if (chunk == 0)
        chunk = 1;

    std::size_t offset = 0;
    for (int i = 0; i < parts - 1 && offset < payload.size(); ++i)
    {
        out.push_back(payload.substr(offset, chunk));
        offset += chunk;
    }

    if (offset < payload.size())
        out.push_back(payload.substr(offset));

    return out;
}

static bool sendAll(int fd, const char *data, std::size_t len)
{
    std::size_t total = 0;

    while (total < len)
    {
        ssize_t sent = ::send(fd, data + total, len - total, MSG_NOSIGNAL);
        if (sent < 0)
        {
            if (errno == EINTR)
                continue;
            return false;
        }

        if (sent == 0)
            return false;

        total += static_cast<std::size_t>(sent);
    }

    return true;
}

static int connectTcp(const Config &cfg, int port)
{
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    timeval tv{};
    tv.tv_sec = 2;
    tv.tv_usec = 0;

    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (fd < 0)
        return -1;

    if (cfg.tcpNoDelay)
    {
        int one = 1;
        ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }

    if (cfg.sndBufBytes > 0)
    {
        ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &cfg.sndBufBytes, sizeof(cfg.sndBufBytes));
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(static_cast<uint16_t>(port));

    if (::inet_pton(AF_INET, cfg.destIp.c_str(), &dst.sin_addr) != 1)
    {
        ::close(fd);
        return -1;
    }

    if (::connect(fd, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)) < 0)
    {
        ::close(fd);
        return -1;
    }

    return fd;
}

static int openUdp()
{
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    return fd;
}

struct TcpConn
{
    int fd = -1;
    int port = 0;
};

struct UdpSock
{
    int fd = -1;
    int port = 0;
    sockaddr_in dst{};
};

enum class EventKind
{
    TCP_SAFE,
    TCP_FLAG,
    TCP_BLOCK,
    UDP_SAFE,
    UDP_FLAG,
    UDP_BLOCK,
    FRAG_SAFE,
    FRAG_FLAG,
    FRAG_BLOCK
};

struct WorkerStats
{
    uint64_t tcpConnectOk = 0;
    uint64_t tcpConnectFail = 0;
    uint64_t tcpReconnectOk = 0;
    uint64_t tcpReconnectFail = 0;

    uint64_t tcpMessagesOk = 0;
    uint64_t tcpSendFail = 0;

    uint64_t udpMessagesOk = 0;
    uint64_t udpSendFail = 0;

    uint64_t bytesOk = 0;

    uint64_t evTcpSafe = 0;
    uint64_t evTcpFlag = 0;
    uint64_t evTcpBlock = 0;
    uint64_t evUdpSafe = 0;
    uint64_t evUdpFlag = 0;
    uint64_t evUdpBlock = 0;
    uint64_t evFragSafe = 0;
    uint64_t evFragFlag = 0;
    uint64_t evFragBlock = 0;
};

static EventKind pickEvent(const Config &cfg, std::mt19937 &rng)
{
    const int total =
        cfg.wTcpSafe + cfg.wTcpFlag + cfg.wTcpBlock +
        cfg.wUdpSafe + cfg.wUdpFlag + cfg.wUdpBlock +
        cfg.wFragSafe + cfg.wFragFlag + cfg.wFragBlock;

    std::uniform_int_distribution<int> dist(1, std::max(1, total));
    int r = dist(rng);

    auto take = [&](int w) -> bool
    {
        if (r <= w)
            return true;
        r -= w;
        return false;
    };

    if (take(cfg.wTcpSafe))
        return EventKind::TCP_SAFE;
    if (take(cfg.wTcpFlag))
        return EventKind::TCP_FLAG;
    if (take(cfg.wTcpBlock))
        return EventKind::TCP_BLOCK;
    if (take(cfg.wUdpSafe))
        return EventKind::UDP_SAFE;
    if (take(cfg.wUdpFlag))
        return EventKind::UDP_FLAG;
    if (take(cfg.wUdpBlock))
        return EventKind::UDP_BLOCK;
    if (take(cfg.wFragSafe))
        return EventKind::FRAG_SAFE;
    if (take(cfg.wFragFlag))
        return EventKind::FRAG_FLAG;
    return EventKind::FRAG_BLOCK;
}

static std::string pickOne(const std::vector<std::string> &v, std::mt19937 &rng)
{
    std::uniform_int_distribution<std::size_t> dist(0, v.size() - 1);
    return v[dist(rng)];
}
static void closeTcpPool(std::vector<TcpConn> &pool)
{
    for (auto &c : pool)
    {
        if (c.fd >= 0)
        {
            ::shutdown(c.fd, SHUT_RDWR);
            ::close(c.fd);
            c.fd = -1;
        }
    }
}

static void closeUdpPool(std::vector<UdpSock> &pool)
{
    for (auto &s : pool)
    {
        if (s.fd >= 0)
        {
            ::close(s.fd);
            s.fd = -1;
        }
    }
}

static bool sendTcpMessage(TcpConn &conn, const std::string &msg)
{
    return sendAll(conn.fd, msg.data(), msg.size());
}

static bool sendTcpFragments(TcpConn &conn, const std::vector<std::string> &parts)
{
    for (const auto &p : parts)
    {
        if (!sendAll(conn.fd, p.data(), p.size()))
            return false;
    }
    return true;
}

static bool sendUdpMessage(UdpSock &sock, const std::string &msg)
{
    ssize_t sent = ::sendto(
        sock.fd,
        msg.data(),
        msg.size(),
        0,
        reinterpret_cast<sockaddr *>(&sock.dst),
        sizeof(sock.dst));

    return sent >= 0;
}

static void workerRun(
    int workerId,
    const Config &cfg,
    const PayloadCatalog &catalog,
    std::atomic<bool> &startFlag,
    WorkerStats &stats)
{
    std::mt19937 rng(
        static_cast<unsigned int>(
            std::chrono::high_resolution_clock::now().time_since_epoch().count() ^
            (0x9e3779b9u + static_cast<unsigned int>(workerId * 7919))));

    std::vector<TcpConn> tcpPool;
    tcpPool.reserve(static_cast<std::size_t>(cfg.tcpConnectionsPerThread));

    for (int i = 0; i < cfg.tcpConnectionsPerThread; ++i)
    {
        int globalIdx = workerId * cfg.tcpConnectionsPerThread + i;
        int port = cfg.portBase + (globalIdx % std::max(1, cfg.portCount));

        int fd = -1;
        for (int attempt = 0; attempt < 20; ++attempt)
        {
            fd = connectTcp(cfg, port);
            if (fd >= 0)
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (fd >= 0)
            stats.tcpConnectOk++;
        else
            stats.tcpConnectFail++;

        tcpPool.push_back({fd, port});
    }

    std::vector<UdpSock> udpPool;
    udpPool.reserve(static_cast<std::size_t>(cfg.udpSocketsPerThread));

    for (int i = 0; i < cfg.udpSocketsPerThread; ++i)
    {
        int globalIdx = workerId * cfg.udpSocketsPerThread + i;
        int port = cfg.portBase + (globalIdx % std::max(1, cfg.portCount));

        int fd = openUdp();
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_port = htons(static_cast<uint16_t>(port));
        ::inet_pton(AF_INET, cfg.destIp.c_str(), &dst.sin_addr);

        udpPool.push_back({fd, port, dst});
    }

    while (!startFlag.load(std::memory_order_acquire))
        std::this_thread::yield();

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(cfg.durationSec);

    std::size_t rrTcp = 0;
    std::size_t rrUdp = 0;

    while (std::chrono::steady_clock::now() < deadline)
    {
        EventKind ev = pickEvent(cfg, rng);

        switch (ev)
        {
        case EventKind::TCP_SAFE:
        case EventKind::TCP_FLAG:
        case EventKind::TCP_BLOCK:
        case EventKind::FRAG_SAFE:
        case EventKind::FRAG_FLAG:
        case EventKind::FRAG_BLOCK:
        {
            TcpConn &c = tcpPool[rrTcp++ % tcpPool.size()];

            if (c.fd < 0)
            {
                if (std::chrono::steady_clock::now() >= deadline)
                    break;

                c.fd = connectTcp(cfg, c.port);
                if (c.fd >= 0)
                    stats.tcpReconnectOk++;
                else
                {
                    stats.tcpReconnectFail++;
                    continue;
                }
            }

            std::string msg;
            if (ev == EventKind::TCP_SAFE || ev == EventKind::FRAG_SAFE)
                msg = pickOne(catalog.safe, rng);
            else if (ev == EventKind::TCP_FLAG || ev == EventKind::FRAG_FLAG)
                msg = pickOne(catalog.flag, rng);
            else
                msg = pickOne(catalog.block, rng);

            bool ok = false;
            if (ev == EventKind::FRAG_SAFE || ev == EventKind::FRAG_FLAG || ev == EventKind::FRAG_BLOCK)
            {
                auto parts = splitPayload(msg, cfg.fragParts);
                ok = sendTcpFragments(c, parts);
            }
            else
            {
                ok = sendTcpMessage(c, msg);
            }

            if (ok)
            {
                stats.tcpMessagesOk++;
                stats.bytesOk += msg.size();

                if (ev == EventKind::TCP_SAFE)
                    stats.evTcpSafe++;
                else if (ev == EventKind::TCP_FLAG)
                    stats.evTcpFlag++;
                else if (ev == EventKind::TCP_BLOCK)
                    stats.evTcpBlock++;
                else if (ev == EventKind::FRAG_SAFE)
                    stats.evFragSafe++;
                else if (ev == EventKind::FRAG_FLAG)
                    stats.evFragFlag++;
                else
                    stats.evFragBlock++;
            }
            else
            {
                stats.tcpSendFail++;
                ::close(c.fd);
                c.fd = -1;
            }

            break;
        }

        case EventKind::UDP_SAFE:
        case EventKind::UDP_FLAG:
        case EventKind::UDP_BLOCK:
        {
            UdpSock &s = udpPool[rrUdp++ % udpPool.size()];
            if (s.fd < 0)
            {
                s.fd = openUdp();
                if (s.fd < 0)
                {
                    stats.udpSendFail++;
                    break;
                }
            }

            std::string msg;
            if (ev == EventKind::UDP_SAFE)
                msg = pickOne(catalog.safe, rng);
            else if (ev == EventKind::UDP_FLAG)
                msg = pickOne(catalog.flag, rng);
            else
                msg = pickOne(catalog.block, rng);

            if (sendUdpMessage(s, msg))
            {
                stats.udpMessagesOk++;
                stats.bytesOk += msg.size();

                if (ev == EventKind::UDP_SAFE)
                    stats.evUdpSafe++;
                else if (ev == EventKind::UDP_FLAG)
                    stats.evUdpFlag++;
                else
                    stats.evUdpBlock++;
            }
            else
            {
                stats.udpSendFail++;
                ::close(s.fd);
                s.fd = -1;
            }

            break;
        }
        }

        if (cfg.pauseUs > 0)
        {
            std::this_thread::sleep_for(std::chrono::microseconds(cfg.pauseUs));
        }
    }

    closeTcpPool(tcpPool);
    closeUdpPool(udpPool);
}

int main()
{
    Config cfg = loadConfig();
    PayloadCatalog catalog = buildCatalog(cfg);

    std::cout
        << "[bench_mix_sender] dest=" << cfg.destIp
        << " ports=" << cfg.portBase << "-" << (cfg.portBase + cfg.portCount - 1)
        << " threads=" << cfg.threads
        << " tcp_conns/thread=" << cfg.tcpConnectionsPerThread
        << " udp_socks/thread=" << cfg.udpSocketsPerThread
        << " duration_sec=" << cfg.durationSec
        << " payload_size=" << cfg.payloadSize
        << " frag_parts=" << cfg.fragParts
        << std::endl;

    std::atomic<bool> startFlag{false};
    std::vector<std::thread> threads;
    std::vector<WorkerStats> stats(static_cast<std::size_t>(cfg.threads));

    for (int i = 0; i < cfg.threads; ++i)
    {
        threads.emplace_back(workerRun, i, std::cref(cfg), std::cref(catalog), std::ref(startFlag), std::ref(stats[static_cast<std::size_t>(i)]));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    startFlag.store(true, std::memory_order_release);

    for (auto &t : threads)
        t.join();

    WorkerStats total{};
    for (const auto &s : stats)
    {
        total.tcpConnectOk += s.tcpConnectOk;
        total.tcpConnectFail += s.tcpConnectFail;
        total.tcpReconnectOk += s.tcpReconnectOk;
        total.tcpReconnectFail += s.tcpReconnectFail;

        total.tcpMessagesOk += s.tcpMessagesOk;
        total.tcpSendFail += s.tcpSendFail;
        total.udpMessagesOk += s.udpMessagesOk;
        total.udpSendFail += s.udpSendFail;
        total.bytesOk += s.bytesOk;

        total.evTcpSafe += s.evTcpSafe;
        total.evTcpFlag += s.evTcpFlag;
        total.evTcpBlock += s.evTcpBlock;
        total.evUdpSafe += s.evUdpSafe;
        total.evUdpFlag += s.evUdpFlag;
        total.evUdpBlock += s.evUdpBlock;
        total.evFragSafe += s.evFragSafe;
        total.evFragFlag += s.evFragFlag;
        total.evFragBlock += s.evFragBlock;
    }

    const uint64_t totalEvents =
        total.evTcpSafe + total.evTcpFlag + total.evTcpBlock +
        total.evUdpSafe + total.evUdpFlag + total.evUdpBlock +
        total.evFragSafe + total.evFragFlag + total.evFragBlock;

    const double eps =
        cfg.durationSec > 0 ? static_cast<double>(totalEvents) / static_cast<double>(cfg.durationSec) : 0.0;

    const double mbps =
        cfg.durationSec > 0 ? (static_cast<double>(total.bytesOk) * 8.0) / (1024.0 * 1024.0 * static_cast<double>(cfg.durationSec)) : 0.0;

    std::cout
        << "[bench_mix_sender] tcp_connect_ok=" << total.tcpConnectOk
        << " tcp_connect_fail=" << total.tcpConnectFail
        << " tcp_reconnect_ok=" << total.tcpReconnectOk
        << " tcp_reconnect_fail=" << total.tcpReconnectFail
        << " tcp_messages_ok=" << total.tcpMessagesOk
        << " tcp_send_fail=" << total.tcpSendFail
        << " udp_messages_ok=" << total.udpMessagesOk
        << " udp_send_fail=" << total.udpSendFail
        << " bytes_ok=" << total.bytesOk
        << " events_per_sec=" << eps
        << " mbps=" << mbps
        << std::endl;

    std::cout
        << "[bench_mix_sender] mix"
        << " tcp_safe=" << total.evTcpSafe
        << " tcp_flag=" << total.evTcpFlag
        << " tcp_block=" << total.evTcpBlock
        << " udp_safe=" << total.evUdpSafe
        << " udp_flag=" << total.evUdpFlag
        << " udp_block=" << total.evUdpBlock
        << " frag_safe=" << total.evFragSafe
        << " frag_flag=" << total.evFragFlag
        << " frag_block=" << total.evFragBlock
        << std::endl;

    return 0;
}