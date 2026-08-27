#include "BlacklistHandler.hpp"
#include <iostream>
#include <fstream>
#include "Logger.hpp"
#include "PcapParser.hpp"
#include <mutex>

std::unordered_set<uint32_t> BlacklistHandler::m_ipBlacklist{};
std::unordered_set<uint32_t> BlacklistHandler::m_portBlacklist{};
std::mutex blacklistMutex;

const std::unordered_set<pcpp::ProtocolType>
    BlacklistHandler::m_allowedProtocols{
        pcpp::TCP,
        pcpp::UDP,
        pcpp::ICMP};

void BlacklistHandler::initializeIPList()
{
    std::ifstream listFile(IP_BLACKLIST_PATH);
    if (!listFile)
        Logger::error("Failed to open ip blacklist file");

    m_ipBlacklist.reserve(DEFAULT_SET_SIZE);

    std::string line;
    while (std::getline(listFile, line))
    {
        if (line.empty())
            continue;

        in_addr addr{};
        if (inet_pton(AF_INET, line.c_str(), &addr) == 1)
        {
            m_ipBlacklist.insert(ntohl(addr.s_addr));
        }
    }
    listFile.close();
}
void BlacklistHandler::initializePortList()
{
    std::ifstream listFile(PORT_BLACKLIST_PATH);
    if (!listFile)
        Logger::error("Failed to open port blacklist file");

    m_portBlacklist.reserve(DEFAULT_SET_SIZE);

    std::string line;
    while (std::getline(listFile, line))
    {
        if (line.empty())
            continue;
        m_portBlacklist.insert(std::stoul(line));
    }
    listFile.close();
}

void BlacklistHandler::addToIPBlacklist(const std::string &ip)
{
    in_addr addr{};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1)
    {
        Logger::error(std::format("Invalid IPv4 address: {}", ip));
        return;
    }

    if (!m_ipBlacklist.insert(addr.s_addr).second)
    {
        Logger::error(std::format("{} is already blacklisted", ip));
        return;
    }

    std::ofstream ipBlacklistFile(IP_BLACKLIST_PATH, std::ios::app);
    if (!ipBlacklistFile)
    {
        Logger::error("Failed to open ip blacklist file");
        return;
    }
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    ipBlacklistFile << buf << '\n';
}

void BlacklistHandler::addToPortBlacklist(const std::string &port)
{
    char *end = nullptr;
    long value = std::strtol(port.c_str(), &end, 10);

    if (*end != '\0' || value < 1 || value > 65535)
    {
        Logger::error(std::format("Invalid port: {}", port));
        return;
    }

    std::uint16_t p = static_cast<std::uint16_t>(value);

    if (!m_portBlacklist.insert(p).second)
        return;

    std::ofstream portBlacklistFile(PORT_BLACKLIST_PATH, std::ios::app);
    if (!portBlacklistFile)
    {
        Logger::error("Failed to open port blacklist file");
        return;
    }

    portBlacklistFile << p << '\n';
}

void BlacklistHandler::flushIPBlacklistToFile()
{
    std::ofstream ipBlacklistFile(IP_BLACKLIST_PATH, std::ios::trunc);
    if (!ipBlacklistFile)
    {
        Logger::error("Failed to open ip blacklist file");
        return;
    }

    char ipString[INET_ADDRSTRLEN];
    for (auto ip : m_ipBlacklist)
    {
        in_addr addr{};
        addr.s_addr = ip;
        inet_ntop(AF_INET, &addr, ipString, sizeof(ipString));
        ipBlacklistFile << ipString << '\n';
    }
}

void BlacklistHandler::flushPortBlacklistToFile()
{
    std::ofstream portBLacklistFile(PORT_BLACKLIST_PATH, std::ios::trunc);
    if (!portBLacklistFile)
    {
        Logger::error("Failed to open port blacklist file");
        return;
    }

    for (auto port : m_portBlacklist)
    {
        portBLacklistFile << port << '\n';
    }
}

void BlacklistHandler::removeFromIPBlacklist(const std::string &ip)
{
    in_addr addr{};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1)
    {
        Logger::error(std::format("Invalid IPv4 address: ", ip));
        return;
    }
    if (m_ipBlacklist.erase(addr.s_addr) > 0)
    {
        flushIPBlacklistToFile();
    }
}

void BlacklistHandler::removeFromPortBlacklist(const std::string &port)
{
    char *end = nullptr;

    long value = std::strtol(port.c_str(), &end, 10);

    if (*end != '\0' || value < 1 || value > 65535)
    {
        Logger::error(std::format("Invalid port: ", port));
        return;
    }

    std::uint16_t p = static_cast<std::uint16_t>(value);

    if (m_portBlacklist.erase(p) > 0)
    {
        flushPortBlacklistToFile();
    }
}

bool BlacklistHandler::isIPBlacklisted(const pcpp::Packet &packet)
{
    auto *ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (!ipLayer)
        return false;

    uint32_t srcIP = ipLayer->getSrcIPv4Address().toInt();

    if (m_ipBlacklist.contains(srcIP))
    {
        Logger::error("IP is blacklisted");
        return true;
    }

    return false;
}

bool BlacklistHandler::isPortBlacklisted(const pcpp::Packet &packet)
{
    auto port = PcapParser::extractPorts(packet);
    if (!port)
        return false;
    if (m_portBlacklist.contains(port))
    {
        Logger::error("Port is blacklisted");
        return true;
    }

    return false;
}

bool BlacklistHandler::isProtocolAllowed(const pcpp::Packet &packet)
{
    if (!m_allowedProtocols.contains(PcapParser::getTransportProtocol(packet)))
    {
        Logger::error("Protocol not allowed");
        return false;
    }
    return true;
}