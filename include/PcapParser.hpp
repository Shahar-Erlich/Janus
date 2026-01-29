#pragma once
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IPv4Layer.h>

#include <memory>

#include <vector>

#include "ParsedPacket.hpp"
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
     * @brief parse a PcapPlusPlus packet into a ParsedPacket object
     *
     * @param packet PcapPlusPlus packet to parse
     * @return pointer to a ParsedPacket object
     */
    std::unique_ptr<ParsedPacket> parsePacket(pcpp::Packet packet);
    std::unique_ptr<ParsedPacket> parsePacket(struct Packet_s packet);
    /**
     * @brief Extract the pcpp packet's source address
     *
     * @param ipv4 the IPv4Layer object of the sent packet
     * @return the packet's source address
     */
    pcpp::IPv4Address extractSourceAddress(pcpp::IPv4Layer &ipv4);
    /**
     * @brief Extract the pcpp packet's destination address
     *
     * @param ipv4 the IPv4Layer object of the sent packet
     * @return the packet's destination address
     */
    pcpp::IPv4Address extractDestinationAddress(pcpp::IPv4Layer &ipv4);
    /**
     * @brief Extract the IPv4Layer of the pcpp packet
     *
     * @param packet pcpp packet
     * @return the IPv4Layer object
     */
    pcpp::IPv4Layer &extractIPv4Layer(pcpp::Packet &packet);
    /**
     * @brief Extract the pcpp packet payload
     *
     * @param ipv4 the pcpp packet's IPv4Layer object
     * @return vector containing the pcpp package's payload bytes
     */
    std::vector<uint8_t> extractPacketPayload(pcpp::IPv4Layer &ipv4);
    std::uint16_t extractPacketPort(pcpp::Packet &packet);
    extern pcpp::ProtocolType mapIpProtocol(uint8_t proto);
};

/**
 * @brief Sends a packet to the packet's internal destination
 *
 * @param parsed ParsedPacket object to send that includes the destination
 * @return true if packet was sent successfully
 * @return false if packet sending has failed
 */
bool sendPacket(ParsedPacket &parsed);
/**
 * @brief send TCP packet to destination
 *
 * @param parsed ParsedPacket object to send that includes the destination
 */
void sendTcpPacket(ParsedPacket &parsed);
/**
 * @brief send UDP packet to destination
 *
 * @param parsed ParsedPacket object to send that includes the destination
 */
void sendUdpPacket(ParsedPacket &parsed);
/**
 * @brief send ICMP packet to destination
 *
 * @param parsed ParsedPacket object to send that includes the destination
 */
void sendIcmpPacket(ParsedPacket &parsed);