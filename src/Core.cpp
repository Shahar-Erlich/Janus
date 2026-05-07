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
#include "RuleLoader.hpp"
#include "janus_common.pb.h"
#include "janus_packet.pb.h"
#include <chrono>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>
#include <atomic>

Core::Core(uint16_t queueNum, AhoCorasick &ac, SystemEventSender &ses)
    : m_queueNum{queueNum},
      m_buffer(MNL_SOCKET_BUFFER_SIZE),
      m_verdictBuffer(MNL_SOCKET_BUFFER_SIZE),
      m_ahoCorasick(ac),
      packetPolicy(std::make_unique<PacketPolicy>(ac)),
      systemSender(ses)
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
    nfq_nlmsg_cfg_put_cmd(netLinkMsgHdr, AF_INET, NFQNL_CFG_CMD_BIND);
    mnl_socket_sendto(m_nlSocket, netLinkMsgHdr, netLinkMsgHdr->nlmsg_len);
}

void Core::configPacketCopy()
{
    nlmsghdr *netlinkHeader = nfq_nlmsg_put(reinterpret_cast<char *>(m_buffer.data()), NFQNL_MSG_CONFIG, m_queueNum);
    nfq_nlmsg_cfg_put_params(netlinkHeader, NFQNL_COPY_PACKET, IP_MAXPACKET);
    mnl_socket_sendto(m_nlSocket, netlinkHeader, netlinkHeader->nlmsg_len);
}

int Core::mnlCallback(const nlmsghdr *netLinkHeader, void *data)
{
    auto *self = static_cast<Core *>(data);
    self->handlePacket(netLinkHeader);
    return MNL_CB_OK;
}

void Core::sendVerdict(uint32_t id, std::size_t verdict)
{
    nlmsghdr *nlh = nfq_nlmsg_put(reinterpret_cast<char *>(m_verdictBuffer.data()), NFQNL_MSG_VERDICT, m_queueNum);
    nfq_nlmsg_verdict_put(nlh, id, verdict);
    mnl_socket_sendto(m_nlSocket, nlh, nlh->nlmsg_len);
}

static uint64_t nowUnixMs()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(
               system_clock::now().time_since_epoch())
        .count();
}

void finishDecisionStamp(Decision &decision,
                         janus::packet::PacketDecisionEvent &packetDecision,
                         TimePoint start,
                         int packetID,
                         std::size_t payloadLength,
                         pcpp::Packet &parsedPacket,
                         int queueNum,
                         pcpp::IPv4Layer &ipLayer)
{

    for (const auto &stamp : decision.trace)
    {
        packetDecision.add_processing_trace()->CopyFrom(stamp);
    }

    packetDecision.set_flagged(decision.flagged);
    packetDecision.set_inspected(decision.inspected);

    uint64_t endToEndTime =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();

    packetDecision.set_end_to_end_processing_us(endToEndTime);
    packetDecision.set_verdict(
        decision.verdict == FinalVerdict::ALLOW
            ? janus::common::Verdict::VERDICT_ALLOW
            : janus::common::Verdict::VERDICT_DROP);

    auto *meta = packetDecision.mutable_metadata();
    meta->set_packet_id(packetID);
    meta->set_queue_id(queueNum);
    meta->set_ts_unix_ms(nowUnixMs());
    meta->set_payload_length(payloadLength);

    if (parsedPacket.isPacketOfType(pcpp::TCP))
        meta->set_protocol(janus::common::PROTOCOL_TCP);
    else if (parsedPacket.isPacketOfType(pcpp::UDP))
        meta->set_protocol(janus::common::PROTOCOL_UDP);
    else
        meta->set_protocol(janus::common::PROTOCOL_OTHER);

    meta->mutable_source()->set_ip(ipLayer.getSrcIPAddress().toString());
    meta->mutable_destination()->set_ip(ipLayer.getDstIPAddress().toString());

    if (auto *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>())
    {
        meta->mutable_source()->set_port(tcpLayer->getTcpHeader()->portSrc);
        meta->mutable_destination()->set_port(tcpLayer->getTcpHeader()->portDst);
    }
    else if (auto *udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>())
    {
        meta->mutable_source()->set_port(udpLayer->getUdpHeader()->portSrc);
        meta->mutable_destination()->set_port(udpLayer->getUdpHeader()->portDst);
    }

    packetDecision.set_match_info(decision.ahoInfo);

    for (int rid : decision.vfHits)
    {
        auto *hit = packetDecision.add_rule_hits();
        hit->set_rule_id(rid);
    }
}
void Core::handlePacket(const nlmsghdr *netLinkHeader)
{
    janus::packet::PacketDecisionEvent packetDecision;

    auto *preProcessingStamp = packetDecision.add_processing_trace();
    preProcessingStamp->set_stage(janus::common::ENGINE_STAGE_PREPROCESS);
    preProcessingStamp->set_started_unix_ms(nowUnixMs());

    auto start = std::chrono::steady_clock::now();

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

    if (!attr[NFQA_PAYLOAD])
    {
        Logger::error("No NFQA payload");
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
    auto ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

    auto end = std::chrono::steady_clock::now();
    uint64_t durationUs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    preProcessingStamp->set_finished_unix_ms(nowUnixMs());
    preProcessingStamp->set_duration_us(durationUs);
    preProcessingStamp->set_status("ok");

    auto decision = packetPolicy->evaluate(parsedPacket);
    finishDecisionStamp(decision, packetDecision, start, packetID, payloadLength, parsedPacket, m_queueNum, *ipLayer);
    bool queued = systemSender.enqueue(packetDecision);
    if (!queued)
    {
        Logger::error("SystemEventSender enqueue failed (queue full)");
    }
    if (decision.verdict == FinalVerdict::DROP)
        sendVerdict(packetID, NF_DROP);
    else
        sendVerdict(packetID, NF_ACCEPT);
}

void Core::init()
{
    GOOGLE_PROTOBUF_VERIFY_VERSION;

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

    char buffer[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;

    nlh = nfq_nlmsg_put(buffer, NFQNL_MSG_CONFIG, m_queueNum);

    uint32_t maxlen = htonl(50000);
    mnl_attr_put_u32(nlh, NFQA_CFG_QUEUE_MAXLEN, maxlen);

    if (mnl_socket_sendto(m_nlSocket, nlh, nlh->nlmsg_len) < 0)
    {
        perror("Failed to set queue maxlen");
    }

    run();
}

void Core::run()
{
    packetPolicy->readPolicyLists();

    bool running = true;
    while (running)
    {
        std::size_t receivedMessageLength = mnl_socket_recvfrom(m_nlSocket, m_buffer.data(), m_buffer.size());

        if (receivedMessageLength <= 0)
        {
            continue;
        }

        mnl_cb_run(
            m_buffer.data(),
            receivedMessageLength,
            0,
            mnl_socket_get_portid(m_nlSocket),
            Core::mnlCallback,
            this);
    }

    google::protobuf::ShutdownProtobufLibrary();
}