#include "../include/PacketPolicy.hpp"
#include "../include/Logger.hpp"
#include <netinet/in.h>
#include <arpa/inet.h>

Verdict PacketPolicy::evaluatePacket(ParsedPacket packet)
{
    if (BlacklistHandler::isIPBlacklisted(packet) ||
        BlacklistHandler::isPortBlacklisted(packet) ||
        !BlacklistHandler::isProtocolAllowed(packet) //||
        // !PacketPolicy::hasPayload(packet)
    )
    {
        return Verdict::DROP;
    }

    return PacketPolicy::checkForInspection(packet) ? Verdict::INSPECT : Verdict::ALLOW;
}

bool PacketPolicy::hasPayload(ParsedPacket packet)
{
    if (packet.getPacketPayload().size() > 0)
    {
        return true;
    }
    Logger::error("Packet has no payload");
    return false;
}
void PacketPolicy::readPolicyLists()
{
    BlacklistHandler::initializeIPList();
    BlacklistHandler::initializePortList();
}
bool PacketPolicy::checkForInspection(ParsedPacket packet)
{
    return false;
}
