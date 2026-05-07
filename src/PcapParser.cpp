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
#include <netinet/tcp.h>
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
        auto *transportLayer = ipv4.getNextLayer();
        auto *payload = transportLayer->getLayerPayload();
        auto size = transportLayer->getLayerPayloadSize();
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
        return sendTcpPacket(packet);
    }

    if (protocol == pcpp::UDP)
    {
        return sendUdpPacket(packet);
    }
    return false;
}

bool sendTcpPacket(const pcpp::Packet &packet)
{
    int clientSocket;

    auto *tcp = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcp)
        return false;

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
        clientSocket = sessionTracker->getSession(connection.flowKey).socket;
    }
    else
    {
        clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (clientSocket < 0)
        {
            return false;
        }

        if (connect(clientSocket,
                    (sockaddr *)&destination,
                    sizeof(destination)) < 0)
        {
            close(clientSocket);
            return false;
        }

        sessionTracker->addSession(connection, clientSocket);
    }

    auto payload = PcapParser::extractPacketPayload(packet);

    if (payload.empty())
    {
        return false;
    }

    if (send(clientSocket,
             payload.data(),
             payload.size(),
             0) < 0)
    {
        return false;
    }

    return true;
}

bool sendUdpPacket(const pcpp::Packet &packet)
{
    int clientSocket;

    if ((clientSocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        Logger::error("Socket creation failed");
        return false;
    }

    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(PcapParser::extractPorts(packet));
    destination.sin_addr.s_addr = PcapParser::extractDestinationAddress(packet).toInt();

    auto payload = PcapParser::extractPacketPayload(packet);
    if (payload.empty())
    {
        Logger::error("UDP payload empty");
        close(clientSocket);
        return false;
    }

    ssize_t sent = sendto(
        clientSocket,
        payload.data(),
        payload.size(),
        0,
        reinterpret_cast<sockaddr *>(&destination),
        sizeof(destination));

    if (sent < 0)
    {
        Logger::error("Package sending failed");
        close(clientSocket);
        return false;
    }

    close(clientSocket);
    return true;
}
