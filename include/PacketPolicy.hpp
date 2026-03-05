#pragma once
#include <unordered_map>
#include <vector>
#include <span>
#include <string>

#include <pcapplusplus/Packet.h>

#include "AhoCorasick.hpp"
#include "VectorFilteringEngine.hpp"
#include "TcpStreamHandler.hpp"
#include "IcdLoader.hpp"

enum class FinalVerdict
{
    ALLOW,
    DROP
};

struct Decision
{
    FinalVerdict verdict = FinalVerdict::ALLOW;

    bool inspected = false;  // האם הופעל deep inspection
    bool flagged = false;    // חשוד (גם אם allowed)
    std::vector<int> vfHits; // ruleIds
    std::string ahoInfo;     // מה Aho החזיר (אם יש)
};

class PacketPolicy
{
public:
    explicit PacketPolicy(AhoCorasick &ac);

    void readPolicyLists();

    // זה הפונקציה שה-Core יקרא
    Decision evaluate(const pcpp::Packet &packet);

private:
    // UDP scanning (shift + hits)
    std::vector<int> scanUdpVf(std::span<const uint8_t> payload) const;

    // מחליט action חמור ביותר בין ה-hits (BLOCK > FLAG > ALLOW), עם בדיקת proto
    IcdRuleMeta::Action worstActionForHits(const std::vector<int> &hits, IcdRuleMeta::Proto proto) const;

private:
    AhoCorasick &ahoCorasick;

    VectorFilteringEngine vectorEngine;
    std::unordered_map<int, IcdRuleMeta> metaByRuleId;
    int maxScanShiftBytes = 64;

    TcpStreamHandler tcpHandler;
};