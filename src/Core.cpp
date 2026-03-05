#include "Core.hpp"
#include "PacketPolicy.hpp"
#include "BlacklistHandler.hpp"
#include "PcapParser.hpp"
#include "TcpStreamHandler.hpp"
#include "VectorFilteringEngine.hpp"
#include <print>
#include <pcapplusplus/PayloadLayer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include "IcdLoader.hpp"

Core::Core(uint16_t queueNum, AhoCorasick &ac)
    : m_queueNum{queueNum},
      m_buffer(MNL_SOCKET_BUFFER_SIZE),
      m_verdictBuffer(MNL_SOCKET_BUFFER_SIZE),
      m_ahoCorasick(ac),
      packetPolicy(std::make_unique<PacketPolicy>(ac))
{
}
Core::~Core() noexcept
{
    if (m_nlSocket)
    {
        mnl_socket_close(m_nlSocket);
    }
}

void Core::bindIPV4()
{
    auto *netLinkMsgHdr = nfq_nlmsg_put(reinterpret_cast<char *>(m_buffer.data()), NFQNL_MSG_CONFIG, m_queueNum);
    nfq_nlmsg_cfg_put_cmd(netLinkMsgHdr, AF_INET, NFQNL_CFG_CMD_BIND);      // bind to ipv4
    mnl_socket_sendto(m_nlSocket, netLinkMsgHdr, netLinkMsgHdr->nlmsg_len); // send config message to kernel
}
void Core::configPacketCopy()
{
    nlmsghdr *netlinkHeader = nfq_nlmsg_put(reinterpret_cast<char *>(m_buffer.data()), NFQNL_MSG_CONFIG, m_queueNum);
    nfq_nlmsg_cfg_put_params(netlinkHeader, NFQNL_COPY_PACKET, IP_MAXPACKET); // NFQNL_COPY_PACKET -> kernel will send full packet and not parts
    mnl_socket_sendto(m_nlSocket, netlinkHeader, netlinkHeader->nlmsg_len);
}

int Core::mnlCallback(const nlmsghdr *netLinkHeader, void *data)
{
    auto *self = static_cast<Core *>(data);
    self->packetCounter.fetch_add(1, std::memory_order_relaxed);
    self->handlePacket(netLinkHeader);
    return MNL_CB_OK;
}

void Core::sendVerdict(uint32_t id, std::size_t verdict)
{
    verdictCounter.fetch_add(1, std::memory_order_relaxed);
    nlmsghdr *nlh = nfq_nlmsg_put(reinterpret_cast<char *>(m_verdictBuffer.data()), NFQNL_MSG_VERDICT, m_queueNum);
    nfq_nlmsg_verdict_put(nlh, id, verdict);
    mnl_socket_sendto(m_nlSocket, nlh, nlh->nlmsg_len);
    if (verdict == NF_ACCEPT)
    {
        //("Packet approved");
        return;
    }
    else
    {
        // Logger::log("Packet Denied");
        return;
    }
}

void Core::handlePacket(const nlmsghdr *netLinkHeader)
{
    // NFQUEUE netlink attribute indices (NFQA_*)
    //
    // Each index refers to a specific netlink attribute parsed from the kernel.
    // After nfq_nlmsg_parse(), attr[X] is either nullptr or points to that attribute.

    // NFQA_PACKET_HDR      - Per-packet metadata (packet_id, hw_protocol, hook)
    //                        REQUIRED to send a verdict back to the kernel

    // NFQA_PAYLOAD         - Raw packet bytes (L3/L4 depending on mode)
    //                        Used for IP/TCP/UDP/application parsing

    nlattr *attr[NFQA_MAX + 1]{};

    if (nfq_nlmsg_parse(netLinkHeader, attr) < 0)
    {
        Logger::error("Error while parsing netlink header");
        return;
    }
    if (!attr[NFQA_PACKET_HDR])
    {
        Logger::error("No NFQA packet header");
        return;
    }
    auto *packetHeader = reinterpret_cast<nfqnl_msg_packet_hdr *>(mnl_attr_get_payload(attr[NFQA_PACKET_HDR]));
    uint32_t packetID = ntohl(packetHeader->packet_id);

    auto *rawPayloadBytes = static_cast<const uint8_t *>(mnl_attr_get_payload(attr[NFQA_PAYLOAD]));
    auto payloadLength = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    struct timeval time;
    gettimeofday(&time, NULL);
    pcpp::RawPacket packet = pcpp::RawPacket(rawPayloadBytes, payloadLength, time, false, pcpp::LINKTYPE_IPV4);
    pcpp::Packet parsedPacket = pcpp::Packet(&packet);
    // Logger::log(parsedPacket.toString());
    auto ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    // if (ipLayer)
    // {

    //     if (BlacklistHandler::isIPBlacklisted(parsedPacket))
    //     {
    //         Logger::error("Blocked blacklisted IP: " + ipLayer->getSrcIPAddress().toString());
    //         sendVerdict(packetID, NF_DROP);
    //         return;
    //     }
    // }
    // std::println("THREAD {} GOT MESSAGE!!!!!!!", m_queueNum);
    auto decision = packetPolicy->evaluate(parsedPacket);

    if (decision.verdict == FinalVerdict::DROP)
        sendVerdict(packetID, NF_DROP);
    else
        sendVerdict(packetID, NF_ACCEPT);
}

void Core::init()
{
    m_nlSocket = mnl_socket_open(NETLINK_NETFILTER);
    if (!m_nlSocket)
    {
        Logger::error("MNL Socket creating failed");
        return;
    }

    if (mnl_socket_bind(m_nlSocket, 0, MNL_SOCKET_AUTOPID) < 0)
    {
        Logger::error("MNL Socker bind failed");
        return;
    }

    bindIPV4();
    configPacketCopy();

    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;

    nlh = nfq_nlmsg_put(buf,
                        NFQNL_MSG_CONFIG,
                        m_queueNum); // your queue number here

    // Add maxlen attribute
    uint32_t maxlen = htonl(50000);

    mnl_attr_put_u32(nlh,
                     NFQA_CFG_QUEUE_MAXLEN,
                     maxlen);

    // Send config to kernel
    if (mnl_socket_sendto(m_nlSocket, nlh, nlh->nlmsg_len) < 0)
    {
        perror("Failed to set queue maxlen");
    }

    Logger::log("Finished setup. Starting core");
    run();
}

void Core::run()
{
    packetPolicy->readPolicyLists();
    std::thread([this]()
                {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        const auto pps = packetCounter.exchange(0, std::memory_order_relaxed);
        const auto vps = verdictCounter.exchange(0, std::memory_order_relaxed);

        std::println("[PPS][Q{}] packets={} verdicts={}", m_queueNum, pps, vps);
    } })
        .detach();
    bool running = true;
    while (running)
    {
        // Logger::log("Waiting for message");
        std::size_t receivedMessageLength = mnl_socket_recvfrom(m_nlSocket, m_buffer.data(), m_buffer.size());
        if (receivedMessageLength <= 0)
        {
            continue;
        }
        // TODO: change the 0 magic number (SEQ NUMBER)
        mnl_cb_run(m_buffer.data(), receivedMessageLength, 0, mnl_socket_get_portid(m_nlSocket), Core::mnlCallback, this);
    }
}
