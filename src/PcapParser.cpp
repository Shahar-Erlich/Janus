#include "../include/PcapParser.hpp"
#include <pcapplusplus/RawPacket.h>
#include <sys/socket.h>
#include "../include/Logger.hpp"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <netinet/ip.h>

pcpp::IPv4Address PcapParser::extractSourceAddress(pcpp::IPv4Layer &ipv4)
{
    return ipv4.getSrcIPv4Address();
}

pcpp::IPv4Address PcapParser::extractDestinationAddress(pcpp::IPv4Layer &ipv4)
{
    return ipv4.getDstIPv4Address();
}

pcpp::IPv4Layer &PcapParser::extractIPv4Layer(pcpp::Packet &packet)
{
    return dynamic_cast<pcpp::IPv4Layer &>(*packet.getLayerOfType(pcpp::IPv4));
}

std::vector<uint8_t> PcapParser::extractPacketPayload(pcpp::IPv4Layer &ipv4)
{
    auto *payload = ipv4.getNextLayer()->getLayerPayload();
    auto size = ipv4.getNextLayer()->getLayerPayloadSize();
    return std::vector<uint8_t>(payload, payload + size);
}

std::unique_ptr<ParsedPacket> PcapParser::parsePacket(pcpp::Packet packet)
{
    return std::make_unique<ParsedPacket>(packet);
}
std::unique_ptr<ParsedPacket> PcapParser::parsePacket(struct Packet_s packet)
{
    return std::make_unique<ParsedPacket>(packet);
}

std::uint16_t PcapParser::extractPacketPort(pcpp::Packet &packet)
{
    Logger::log("Extracting packet port");
    auto &ipv4 = PcapParser::extractIPv4Layer(packet);
    auto transport = ipv4.getNextLayer();
    auto protocol = transport->getProtocol();
    std::uint16_t port;
    switch (protocol)
    {
    case pcpp::TCP:
    {
        auto *tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
        port = tcpLayer ? tcpLayer->getDstPort() : 0;
        return port;
    }

    case pcpp::UDP:
    {
        auto *udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
        port = udpLayer ? udpLayer->getDstPort() : 0;
        return port;
    }

    default:
        Logger::error("Port not found");
        return 0;
    }
}
extern pcpp::ProtocolType PcapParser::mapIpProtocol(uint8_t proto)
{
    switch (proto)
    {
    case IPPROTO_TCP:
        return pcpp::TCP;
    case IPPROTO_UDP:
        return pcpp::UDP;
    case IPPROTO_ICMP:
        return pcpp::ICMP;
    default:
        return pcpp::UnknownProtocol;
    }
}

bool sendPacket(ParsedPacket &parsed)
{
    auto protocol = parsed.getProtocol();
    bool success = true;
    switch (protocol)
    {
    case pcpp::TCP:
        sendTcpPacket(parsed);
        break;
    case pcpp::UDP:
        sendUdpPacket(parsed);
        break;
    case pcpp::ICMP:
        sendIcmpPacket(parsed);
        break;
    default:
        Logger::error("Unexpected protocol");
        success = false;
        break;
    }
    return success;
}
void sendTcpPacket(ParsedPacket &parsed)
{
    std::size_t clientSocket;
    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        Logger::error("Socket creation failed");
        return;
    }

    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = parsed.getDestinationPort();
    destination.sin_addr.s_addr = parsed.getDestinationAddress().toInt();

    if (connect(clientSocket, (sockaddr *)&destination, sizeof(destination)) < 0)
    {
        Logger::error("Socket connection failed");
        close(clientSocket);
        return;
    }
    ssize_t sent;

    if ((sent = send(clientSocket,
                     parsed.getPacketPayload().data(),
                     parsed.getPacketPayload().size(),
                     0)) < 0)
        Logger::error("Package sending failed");

    close(clientSocket);
}

void sendUdpPacket(ParsedPacket &parsed)
{
    std::size_t clientSocket;
    if ((clientSocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        Logger::error("Socket creation failed");
        return;
    }

    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = parsed.getDestinationPort();
    destination.sin_addr.s_addr = parsed.getDestinationAddress().toInt();

    ssize_t sent;

    if ((sent = sendto(
             clientSocket,
             parsed.getPacketPayload().data(),
             parsed.getPacketPayload().size(),
             0,
             reinterpret_cast<sockaddr *>(&destination),
             sizeof(destination))) < 0)
        Logger::error("Package sending failed");

    close(clientSocket);
}

void sendIcmpPacket(ParsedPacket &parsed)
{
    int clientSocket;
    if ((clientSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        Logger::error("Socket creation failed");
        return;
    }
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_addr.s_addr = parsed.getDestinationAddress().toInt();

    icmphdr icmp{};
    icmp.type = ICMP_ECHO;
    icmp.code = 0;
    icmp.un.echo.id = 1;
    icmp.un.echo.sequence = 1;
    icmp.checksum = 0;

    uint16_t *p = (uint16_t *)&icmp;
    uint32_t sum = 0;
    for (int i = 0; i < sizeof(icmp) / 2; i++)
        sum += p[i];
    icmp.checksum = ~((sum & 0xFFFF) + (sum >> 16));

    sendto(clientSocket, &icmp, sizeof(icmp), 0,
           (sockaddr *)&destination, sizeof(destination));

    close(clientSocket);
}
