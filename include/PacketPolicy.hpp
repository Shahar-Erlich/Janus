#pragma once
#include <filesystem>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include <pcapplusplus/Packet.h>

#include "AhoCorasick.hpp"
#include "IcdLoader.hpp"
#include "RegexEngine.hpp"
#include "TcpStreamHandler.hpp"
#include "VectorFilteringEngine.hpp"

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

    void reloadRulesFromDisk();
    void reloadRulesIfChanged();

private:
    AhoCorasick &ahoCorasick;
    RegexEngine regexEngine;
    VectorFilteringEngine vectorEngine;
    std::unordered_map<int, IcdRuleMeta> metaByRuleId;
    int maxScanShiftBytes = 64;

    TcpStreamHandler tcpHandler;

    std::string icdPath = "/app/icd.json";
    std::filesystem::file_time_type icdLastWriteTime{};
    bool icdWriteTimeKnown = false;
};