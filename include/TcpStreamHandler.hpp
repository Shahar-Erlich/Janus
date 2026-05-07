#pragma once

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpReassembly.h>
#include <unordered_map>
#include <vector>
#include <string>
#include <mutex>

#include "AhoCorasick.hpp"
#include "VectorFilteringEngine.hpp"
#include "RegexEngine.hpp"
#include "RuleLoader.hpp"
#include "janus_common.pb.h"
#include "janus_packet.pb.h"
struct ConnectionState
{
    std::vector<uint8_t> clientBuffer;
    std::vector<uint8_t> serverBuffer;
    int sessionId = 0;
    bool flowFlagged = false;
    bool flowConfirmed = false;
    std::vector<int> confirmedRuleIds;
    std::string confirmedAhoInfo;
};

struct TcpPacketScanResult
{
    bool vfHit = false;
    std::vector<int> vfRuleIds;
    bool ahoHit = false;
    std::string ahoInfo;
    std::vector<janus::common::ProcessingStamp> trace;
};

class TcpStreamHandler
{
public:
    /**
     * @brief Construct a new Tcp Stream Handler object
     *
     * @param ac ahocorasick engine
     * @param ve vector filtering engine
     * @param re regex engine
     */
    TcpStreamHandler(AhoCorasick &ac, VectorFilteringEngine &ve, RegexEngine &re);
    TcpStreamHandler(const TcpStreamHandler &) = delete;
    TcpStreamHandler &operator=(const TcpStreamHandler &) = delete;

    /**
     * @brief process packet, add it to the correct session's buffer and scan it
     *
     * @param packet packet to process and scan
     * @return TcpPacketScanResult the results of the DPI scans
     */
    TcpPacketScanResult processPacket(pcpp::Packet &packet);
    /**
     * @brief Set a rule meta id in the metadata map
     *
     * @param meta metadata of a rule
     */
    void setRuleMeta(std::unordered_map<int, RuleHelper::RuleHelper::RuleMeta> *meta) { m_metaMap = meta; }
    /**
     * @brief shutdown the TCP state machine
     *
     */
    void shutdown();

private:
    static constexpr std::size_t MAX_ANCHOR_LEN = 4;
    static constexpr std::size_t MAX_STREAM_KEEP = 4096;
    static constexpr std::size_t AHO_TAIL = 64;

    /**
     * @brief callback to call when a TCP connection starts
     *
     * @param connectionData new connection established
     * @param userCookie the unique user identifier
     */
    static void onConnectionStart(const pcpp::ConnectionData &connectionData, void *userCookie);
    /**
     * @brief callback to call when data is entered to the connection
     *
     * @param side which side sent the data
     * @param tcpData the data
     * @param userCookie the unique use ID
     */
    static void onDataReady(int8_t side, const pcpp::TcpStreamData &tcpData, void *userCookie);
    /**
     * @brief callback to call when TCP connection ends
     *
     * @param connData the connection data
     * @param reason the reason for closing (error/shutdown etc...)
     * @param userCookie the unique user ID
     */
    static void onConnectionEnd(const pcpp::ConnectionData &connData,
                                pcpp::TcpReassembly::ConnectionEndReason reason,
                                void *userCookie);

private:
    pcpp::TcpReassembly reassembly;
    std::unordered_map<uint32_t, ConnectionState> connections;
    std::mutex mutex;
    std::unordered_map<int, RuleHelper::RuleHelper::RuleMeta> *m_metaMap = nullptr;
    AhoCorasick &ahoCorasick;
    VectorFilteringEngine &vectorEngine;
    RegexEngine &regexEngine;
    TcpPacketScanResult *currentScan = nullptr;
};