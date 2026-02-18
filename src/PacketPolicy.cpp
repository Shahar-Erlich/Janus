#include "PacketPolicy.hpp"
#include "Logger.hpp"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcapplusplus/Packet.h>
#include "PcapParser.hpp"
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <libmnl/libmnl.h>
#include "TcpStreamHandler.hpp"

Verdict PacketPolicy::evaluatePacket(const pcpp::Packet &packet)
{
    if (BlacklistHandler::isIPBlacklisted(packet) ||
        BlacklistHandler::isPortBlacklisted(packet) ||
        !BlacklistHandler::isProtocolAllowed(packet)
        //||
        // !PacketPolicy::hasPayload(packet)
    )
    {
        Logger::log("Dropping");
        return Verdict::DROP;
    }

    return PacketPolicy::checkForInspection(packet) ? Verdict::INSPECT : Verdict::ALLOW;
}

bool PacketPolicy::hasPayload(pcpp::Packet packet)
{
    // if (packet.getPacketPayload().size() > 0)
    // {
    //     return true;
    // }
    // Logger::error("Packet has no payload");
    // return false;
    return true;
}
void PacketPolicy::readPolicyLists()
{
    BlacklistHandler::initializeIPList();
    BlacklistHandler::initializePortList();
}
bool PacketPolicy::checkForInspection(pcpp::Packet packet)
{
    auto proto = PcapParser::getTransportProtocol(packet);

    if (proto == pcpp::TCP)
    {
        return TcpStreamHandler::instance().processPacket(packet);
    }

    auto payload = PcapParser::extractPacketPayload(packet);
    auto candidates = VectorFilteringEngine::instance().scanPayload(payload);
    if (!candidates.empty())
    {
        Logger::error("UDP VectorFilter HIT");

        for (int id : candidates)
            Logger::log("Rule " + std::to_string(id));

        return true;
    }
    else
    {
        return false;
    }
}
