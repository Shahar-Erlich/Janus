#include "Parsed_Packet.hpp"
#include "../Pcap_Parser/Pcap_Parser.hpp"

ParsedPacket::ParsedPacket(pcpp::Packet &packet)
    : m_sourceAddress(Parser::extractSourceAddress(Parser::extractIPv4Layer(packet))),
      m_destionationAddress(Parser::extractDestinationAddress(Parser::extractIPv4Layer(packet))),
      m_packetPayload(Parser::extractPacketPayload(Parser::extractIPv4Layer(packet))),
      m_protocol(Parser::extractIPv4Layer(packet).getNextLayer()->getProtocol())
{
}

ParsedPacket::~ParsedPacket()
{
    m_packetPayload.empty();
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