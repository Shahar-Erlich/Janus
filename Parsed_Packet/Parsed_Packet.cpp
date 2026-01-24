#include "Parsed_Packet.hpp"
#include "../Pcap_Parser/Pcap_Parser.hpp"

ParsedPacket::ParsedPacket(pcpp::Packet &packet)
    : m_sourceAddress(Parser::extractSourceAddress(Parser::extractIPv4Layer(packet))),
      m_destionationAddress(Parser::extractDestinationAddress(Parser::extractIPv4Layer(packet))),
      m_packetPayload(Parser::extractPacketPayload(Parser::extractIPv4Layer(packet))),
      m_protocol(Parser::extractIPv4Layer(packet).getNextLayer()->getProtocol()),
      m_destinationPort(Parser::extractPacketPort(packet))
{
}
ParsedPacket::ParsedPacket(const struct iphdr *ip, std::span<const uint8_t> applicationBytes)
    : m_sourceAddress(ip->saddr),
      m_destionationAddress(ip->daddr),
      m_packetPayload(applicationBytes.begin(), applicationBytes.end()),
      m_protocol(Parser::mapIpProtocol(ip->protocol))
{
}

pcpp::IPv4Address ParsedPacket::getSourceAddress() const
{
    return m_sourceAddress;
}

pcpp::IPv4Address ParsedPacket::getDestinationAddress() const
{
    return m_destionationAddress;
}

pcpp::ProtocolType ParsedPacket::getProtocol() const
{
    return m_protocol;
}
std::vector<uint8_t> ParsedPacket::getPacketPayload() const
{
    return m_packetPayload;
}
std::size_t ParsedPacket::getDestinationPort() const
{
    return m_destinationPort;
}