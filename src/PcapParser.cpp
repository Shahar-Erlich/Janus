#include "PcapParser.hpp"
#include <pcapplusplus/RawPacket.h>
#include <sys/socket.h>
#include "Logger.hpp"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <netinet/ip.h>
#include "TcpStreamHandler.hpp"
#include "TcpSessionTracker.hpp"
#include <mutex>

static auto sessionTracker = std::make_unique<TcpSessionTracker>();
std::mutex sessionTrackerMutex;

namespace PcapParser
{
    pcpp::IPv4Address extractSourceAddress(const pcpp::Packet &packet)
    {
        return extractIPv4Layer(packet).getSrcIPv4Address();
    }

    pcpp::IPv4Address extractDestinationAddress(const pcpp::Packet &packet)
    {
        return extractIPv4Layer(packet).getDstIPv4Address();
    }

    pcpp::IPv4Layer &extractIPv4Layer(const pcpp::Packet &packet)
    {
        return dynamic_cast<pcpp::IPv4Layer &>(*packet.getLayerOfType(pcpp::IPv4));
    }

    std::vector<uint8_t> extractPacketPayload(const pcpp::Packet &packet)
    {
        auto &ipv4 = extractIPv4Layer(packet);
        //  Logger::log("Got IPV4");
        auto *payload = ipv4.getNextLayer()->getLayerPayload();
        // Logger::log("Got payload");
        auto size = ipv4.getNextLayer()->getLayerPayloadSize();
        // Logger::log("Got payload size");
        return std::vector<uint8_t>(payload, payload + size);
    }

    std::uint16_t extractPorts(const pcpp::Packet &packet)
    {
        if (auto *tcp = packet.getLayerOfType<pcpp::TcpLayer>())
            return tcp->getDstPort();

        if (auto *udp = packet.getLayerOfType<pcpp::UdpLayer>())
            return udp->getDstPort();

        return 0;
    }

    pcpp::ProtocolType getTransportProtocol(const pcpp::Packet &packet)
    {
        if (packet.getLayerOfType<pcpp::TcpLayer>())
        {

            return pcpp::TCP;
        }

        if (packet.getLayerOfType<pcpp::UdpLayer>())
        {
            return pcpp::UDP;
        }
        return pcpp::UnknownProtocol;
    }

}
bool sendPacket(const pcpp::Packet &packet)
{
    auto protocol = PcapParser::getTransportProtocol(packet);

    if (protocol == pcpp::TCP)
    {
        sendTcpPacket(packet);
        return true;
    }

    if (protocol == pcpp::UDP)
    {
        sendUdpPacket(packet);
        return true;
    }
    Logger::log("Unknown Protocol");
    return false;
}
void sendTcpPacket(const pcpp::Packet &packet)
{
    int clientSocket;

    auto *tcp = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcp)
        return;

    pcpp::ConnectionData connection;
    connection.srcIP = PcapParser::extractSourceAddress(packet);
    connection.dstIP = PcapParser::extractDestinationAddress(packet);
    connection.srcPort = tcp->getSrcPort();
    connection.dstPort = tcp->getDstPort();

    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(connection.dstPort);
    destination.sin_addr.s_addr = connection.dstIP.getIPv4().toInt();
    std::lock_guard<std::mutex> lock(sessionTrackerMutex);
    if (sessionTracker->sessionExists(connection))
    {
        Logger::log("Session already exists");
        clientSocket = sessionTracker->getSession(connection.flowKey).socket;
    }
    else
    {
        clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (clientSocket < 0)
        {
            Logger::log("Socket creation failed");
            return;
        }
        Logger::log("Session doesnt exist, created socket");

        if (connect(clientSocket,
                    (sockaddr *)&destination,
                    sizeof(destination)) < 0)
        {
            Logger::log("Socket connection failed");
            close(clientSocket);
            return;
        }
        Logger::log("Connected socket");

        if (sessionTracker->addSession(connection, clientSocket))
        {
            Logger::log("Added connection to Tracker");
        }
    }
    Logger::log("Moving to payload Extraction");
    auto payload = PcapParser::extractPacketPayload(packet);

    if (send(clientSocket,
             payload.data(),
             payload.size(),
             0) < 0)
    {
        Logger::log("Package sending failed");
    }
    else
    {
        Logger::log("Sent TCP package successfully");
    }
}

void sendUdpPacket(const pcpp::Packet &packet)
{
    std::size_t clientSocket;
    if ((clientSocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        Logger::error("Socket creation failed");
        return;
    }
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(PcapParser::extractPorts(packet));
    destination.sin_addr.s_addr = PcapParser::extractDestinationAddress(packet).toInt();

    ssize_t sent;
    auto payload = PcapParser::extractPacketPayload(packet);
    if ((sent = sendto(
             clientSocket,
             payload.data(),
             payload.size(),
             0,
             reinterpret_cast<sockaddr *>(&destination),
             sizeof(destination))) < 0)
    {
        Logger::error("Package sending failed");
    }
    Logger::log("Sent udp package");

    close(clientSocket);
}

// void sendIcmpPacket(pcpp::Packet &parsed)
// {
//     int clientSocket;
//     if ((clientSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
//     {
//         Logger::error("Socket creation failed");
//         return;
//     }
//     sockaddr_in destination{};
//     destination.sin_family = AF_INET;
//     destination.sin_addr.s_addr = parsed.getDestinationAddress().toInt();

//     icmphdr icmp{};
//     icmp.type = ICMP_ECHO;
//     icmp.code = 0;
//     icmp.un.echo.id = 1;
//     icmp.un.echo.sequence = 1;
//     icmp.checksum = 0;

//     uint16_t *p = (uint16_t *)&icmp;
//     uint32_t sum = 0;
//     for (int i = 0; i < sizeof(icmp) / 2; i++)
//         sum += p[i];
//     icmp.checksum = ~((sum & 0xFFFF) + (sum >> 16));

//     sendto(clientSocket, &icmp, sizeof(icmp), 0,
//            (sockaddr *)&destination, sizeof(destination));

//     close(clientSocket);
// }
