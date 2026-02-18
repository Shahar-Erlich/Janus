#pragma once

/* C++ Headers*/
#include <iostream>
#include <vector>
#include <memory>
#include <span>

/*Network Headers*/
#include <netinet/ip.h>      // iphdr
#include <netinet/tcp.h>     // tcphdr
#include <netinet/udp.h>     // udphdr
#include <netinet/ip_icmp.h> // icmphdr

#include <arpa/inet.h>

/* Netfilter/Netfilter_Queue Headers*/
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <libmnl/libmnl.h>

#include "Logger.hpp"

#define QUEUE_NUM 0
#define WORD_BYTE 4

struct Packet_s;

class Core
{
public:
    /**
     * @brief Construct a new Core object
     *
     * @param queueNum NFQ queue number to use
     */
    explicit Core(uint16_t queueNum);
    /**
     * @brief Destroy the Core object
     *
     */
    ~Core() noexcept;

    /**
     * @brief initialize the Core
     *
     */
    void init();

private:
    mnl_socket *m_nlSocket = nullptr;
    uint16_t m_queueNum;
    std::vector<uint8_t> m_buffer;

private:
    /**
     * @brief start the core loop
     *
     */
    void run();
    /**
     * @brief bind netlink to handle IPV4 packets
     *
     */
    void bindIPV4();
    /**
     * @brief configure kernel to send a copy of the entire packet
     *
     */
    void configPacketCopy();

    /**
     * @brief sends received packets to inpsection.
     *
     * @param netLinkHeader network link header recieved from NFQUEUE
     * @param data current object instance
     * @return int success/fail
     */
    static int mnlCallback(const nlmsghdr *netLinkHeader, void *data);
    /**
     * @brief vWalidate and parse packets
     *
     * @param netLinkHeader network link header recieved from NFQUEUE
     */
    void handlePacket(const nlmsghdr *netLinkHeader);
    /**
     * @brief parse packet to TCP/UDP/ICMP/HTTP format
     *
     * @param attr netlink attribute array parsed from header
     * @return Packet parsed packet in correct format
     */
    struct Packet_s parsePacket(nlattr *const attr[]);
    /**
     * @brief sends verdict to kernel about package
     *
     * @param id package to accept/drop
     * @param drop tell the kernel whether to drop or accepe the package
     */
    void sendVerdict(uint32_t id, std::size_t drop);
};
