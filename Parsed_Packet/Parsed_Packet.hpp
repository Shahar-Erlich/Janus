#pragma once
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IPv4Layer.h>

class ParsedPacket
{
public:
    /**
     * @brief Construct a new ParsedPacket object
     *
     * @param packet
     */
    ParsedPacket(pcpp::Packet &packet);
    /**
     * @brief Destroy the ParsedPacket object
     *
     */
    ~ParsedPacket();

    /**
     * @brief Get the parsed packet's source address
     *
     * @return the packet's source parsed address
     */
    pcpp::IPv4Address getSourceAddress() const;
    /**
     * @brief Get the parsed packet's destination address
     *
     * @return the destination address of the parsed packet
     */
    pcpp::IPv4Address getDestinationAddress() const;
    /**
     * @brief Get the parsed packet's protocol
     *
     * @return The protocol of the parsed packet(TCP/UDP/ICMP)
     */
    pcpp::ProtocolType getProtocol() const;
    /**
     * @brief Get the parsed packet's payload
     *
     * @return a vector containing the parsed packet's payload bytes
     */
    std::vector<uint8_t> getPacketPayload() const;

private:
    pcpp::IPv4Address m_sourceAddress;
    pcpp::IPv4Address m_destionationAddress;
    pcpp::ProtocolType m_protocol;
    std::vector<uint8_t> m_packetPayload;
};