#pragma once
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IPv4Layer.h>
#include <netinet/ip.h>
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
     * @brief Construct a new ParsedPacket object
     *
     * @param packet
     */
    ParsedPacket(const struct iphdr *ip, std::span<const uint8_t> applicationBytes);
    /**
     * @brief Destroy the ParsedPacket object
     *
     */
    ~ParsedPacket() = default;

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
    /**
     * @brief Get the packet's destination port
     *
     * @return std::size_t the packet's destination port
     */
    std::size_t getDestinationPort() const;

private:
    pcpp::IPv4Address m_sourceAddress;
    pcpp::IPv4Address m_destionationAddress;
    pcpp::ProtocolType m_protocol;
    std::vector<uint8_t> m_packetPayload;
    std::size_t m_destinationPort;
};