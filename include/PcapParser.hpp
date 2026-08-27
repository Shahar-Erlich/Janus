#pragma once
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IPv4Layer.h>

#include <memory>

#include <vector>

#include <span>

#include <netinet/ip.h>
struct Packet_s
{
    const struct iphdr *ip;
    std::span<const uint8_t> transportBytes;
    std::span<const uint8_t> applicationBytes;
    uint16_t destination_port;
};

namespace PcapParser
{

    /**
     * @brief Extract the pcpp packet's source address
     *
     * @return the packet's source address
     */
    pcpp::IPv4Address extractSourceAddress(const pcpp::Packet &packet);
    /**
     * @brief Extract the pcpp packet's destination address
     *
     * @return the packet's destination address
     */
    pcpp::IPv4Address extractDestinationAddress(const pcpp::Packet &packet);
    /**
     * @brief Extract the IPv4Layer of the pcpp packet
     *
     * @param packet pcpp packet
     * @return the IPv4Layer object
     */
    pcpp::IPv4Layer &extractIPv4Layer(const pcpp::Packet &packet);
    /**
     * @brief Extract the pcpp packet payload
     *
     * @return vector containing the pcpp package's payload bytes
     */
    std::vector<uint8_t> extractPacketPayload(const pcpp::Packet &packet);
    /**
     * @brief Extract the destination port from the packet
     *
     * @param packet to extract port from
     * @return std::uint16_t the port
     */
    std::uint16_t extractPorts(const pcpp::Packet &packet);
    /**
     * @brief Get the packets protocol
     *
     * @param packet packet to get protocol from
     * @return pcpp::ProtocolType the protocol
     */
    pcpp::ProtocolType getTransportProtocol(const pcpp::Packet &packet);
};

/**
 * @brief Sends a packet to the packet's internal destination
 *
 * @param parsed pcpp::Packet object to send that includes the destination
 * @return true if packet was sent successfully
 * @return false if packet sending has failed
 */
bool sendPacket(const pcpp::Packet &packet);
/**
 * @brief send a TCP packet
 *
 * @param packet packet to send
 * @return true if sending succeeded
 * @return false if sending failed
 */
bool sendTcpPacket(const pcpp::Packet &packet);
/**
 * @brief send a UDP packet
 *
 * @param packet packet to send
 * @return true if sending succeeded
 * @return false if sending failed
 */
bool sendUdpPacket(const pcpp::Packet &packet);