#pragma once
#include <arpa/inet.h>
#include <unordered_set>
#include <pcapplusplus/ProtocolType.h>
#include <string>
#include <pcapplusplus/Packet.h>

#define IP_BLACKLIST_PATH "/blacklists/ip_blacklist.txt"
#define PORT_BLACKLIST_PATH "/blacklists/port_blacklist.txt"
#define ALLOWED_PROTOCOLS "/blacklists/allowed_protocols.txt"

#define DEFAULT_SET_SIZE 4096

namespace BlacklistHandler
{
    extern std::unordered_set<uint32_t> m_ipBlacklist;
    extern std::unordered_set<uint32_t> m_portBlacklist;
    extern const std::unordered_set<pcpp::ProtocolType> m_allowedProtocols;

    /**
     * @brief add IP to blacklist
     *
     * @param ip ip to blacklist
     */
    void addToIPBlacklist(const std::string &ip);
    /**
     * @brief add port to blacklist
     *
     * @param port port to blacklist
     */
    void addToPortBlacklist(const std::string &port);
    /**
     * @brief remove IP from blacklist
     *
     * @param ip ip to remove
     */
    void removeFromIPBlacklist(const std::string &ip);
    /**
     * @brief remove port from blacklist
     *
     * @param port port to remove
     */
    void removeFromPortBlacklist(const std::string &port);
    /**
     * @brief write the current in memory IP blacklist to file
     *
     */
    void flushIPBlacklistToFile();
    /**
     * @brief write the current in memory port blacklist to file
     *
     */
    void flushPortBlacklistToFile();
    /**
     * @brief read and initialize the ip blacklist to memory
     *
     */
    void initializeIPList();
    /**
     * @brief read and initialize the port blacklist to memory
     *
     */
    void initializePortList();
    /**
     * @brief check if packet ip is blacklisted
     *
     * @param packet packet to check
     * @return true ip is blacklisted
     * @return false ip is not blacklisted
     */
    bool isIPBlacklisted(const pcpp::Packet &packet);
    /**
     * @brief check if packet protocol is allowed
     *
     * @param packet packet to check
     * @return true protocol is allowed
     * @return false protocol isn't allowed
     */
    bool isProtocolAllowed(const pcpp::Packet &packet);
    /**
     * @brief check if packet source port is blacklisted
     *
     * @param packet packet to check
     * @return true port is blacklisted
     * @return false port isn't blacklisted
     */
    bool isPortBlacklisted(const pcpp::Packet &packet);
}