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
#include "IcdLoader.hpp"
struct ConnectionState
{
    std::vector<uint8_t> clientBuffer;
    std::vector<uint8_t> serverBuffer;
    int sessionId = 0;
    bool flowFlagged = false; // אם תרצה בעתיד drop-fast על כל הסשן
};

struct TcpPacketScanResult
{
    bool vfHit = false;
    std::vector<int> vfRuleIds; // ruleIds (מה-VF)
    bool ahoHit = false;
    std::string ahoInfo; // מה ש-Aho מחזיר (אם יש)
};

class TcpStreamHandler
{
public:
    TcpStreamHandler(AhoCorasick &ac, VectorFilteringEngine &ve, RegexEngine &re);
    TcpStreamHandler(const TcpStreamHandler &) = delete;
    TcpStreamHandler &operator=(const TcpStreamHandler &) = delete;

    // מחזיר תוצאה פר פאקטה (סינכרוני מבחינת PacketPolicy)
    TcpPacketScanResult processPacket(pcpp::Packet &packet);
    void setRuleMeta(const std::unordered_map<int, IcdRuleMeta> *meta) { m_metaMap = meta; }
    void shutdown();

private:
    static constexpr std::size_t MAX_ANCHOR_LEN = 4;     // VF anchor limit
    static constexpr std::size_t MAX_STREAM_KEEP = 4096; // keep last bytes
    static constexpr std::size_t AHO_TAIL = 64;          // tail for aho window

    static void onConnectionStart(const pcpp::ConnectionData &connectionData, void *userCookie);
    static void onDataReady(int8_t side, const pcpp::TcpStreamData &tcpData, void *userCookie);
    static void onConnectionEnd(const pcpp::ConnectionData &connData,
                                pcpp::TcpReassembly::ConnectionEndReason reason,
                                void *userCookie);

private:
    pcpp::TcpReassembly reassembly;
    std::unordered_map<uint32_t, ConnectionState> connections;
    std::mutex mutex;
    const std::unordered_map<int, IcdRuleMeta> *m_metaMap = nullptr;
    AhoCorasick &ahoCorasick;
    VectorFilteringEngine &vectorEngine;
    RegexEngine &regexEngine;
    TcpPacketScanResult *currentScan = nullptr;
};