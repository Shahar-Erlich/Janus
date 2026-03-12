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
#include "RegexEngine.hpp"

enum class FinalVerdict
{
    ALLOW,
    DROP
};

struct Decision
{
    FinalVerdict verdict = FinalVerdict::ALLOW;

    bool inspected = false;
    bool flagged = false;
    std::vector<int> vfHits;
    std::string ahoInfo;
    std::vector<janus::common::ProcessingStamp> trace;
};

class PacketPolicy
{
public:
    explicit PacketPolicy(AhoCorasick &ac);

    void readPolicyLists();

    Decision evaluate(const pcpp::Packet &packet);

private:
    std::vector<int> scanUdpVf(std::span<const uint8_t> payload) const;

    IcdRuleMeta::Action worstActionForHits(const std::vector<int> &hits, IcdRuleMeta::Proto proto) const;

private:
    AhoCorasick &ahoCorasick;
    RegexEngine regexEngine;
    VectorFilteringEngine vectorEngine;
    std::unordered_map<int, IcdRuleMeta> metaByRuleId;
    int maxScanShiftBytes = 64;

    TcpStreamHandler tcpHandler;
};