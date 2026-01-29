#include "Packet_Policy.hpp"
#include "../Logger/Logger.hpp"
#include <netinet/in.h>
#include <arpa/inet.h>

Verdict packetPolicy::evaluatePacket(ParsedPacket packet)
{
    if (BlacklistHandler::isIPBlacklisted(packet) ||
        BlacklistHandler::isPortBlacklisted(packet) ||
        !BlacklistHandler::isProtocolAllowed(packet) //||
        // !packetPolicy::hasPayload(packet)
    )
    {
        return Verdict::DROP;
    }

    return packetPolicy::checkForInspection(packet) ? Verdict::INSPECT : Verdict::ALLOW;
}

bool packetPolicy::hasPayload(ParsedPacket packet)
{
    if (packet.getPacketPayload().size() > 0)
    {
        return true;
    }
    Logger::error("Packet has no payload");
    return false;
}
void packetPolicy::readPolicyLists()
{
    BlacklistHandler::initializeIPList();
    BlacklistHandler::initializePortList();
}
bool packetPolicy::checkForInspection(ParsedPacket packet)
{
    return false;
}
