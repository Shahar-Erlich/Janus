#pragma once
#include <filesystem>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>

#include <pcapplusplus/Packet.h>

#include "AhoCorasick.hpp"
#include "RuleLoader.hpp"
#include "RegexEngine.hpp"
#include "TcpStreamHandler.hpp"
#include "VectorFilteringEngine.hpp"

#define MAX_BYTE_SHIFT 64

using TimePoint = std::chrono::steady_clock::time_point;

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
    /**
     * @brief Construct a new Packet Policy object
     *
     * @param ac golbal Ahocorasick engine
     */
    explicit PacketPolicy(AhoCorasick &ac);

    /**
     * @brief load the blacklists into the system
     *
     */
    void readPolicyLists();

    /**
     * @brief decide if packet should be allowed/dropped
     *
     * @param packet packet to check
     * @return Decision if the packet should be allowed/dropped, also returns the stamps from each engine
     */
    Decision evaluate(const pcpp::Packet &packet);
    bool addRule(const RuleHelper::RuleMeta &meta);

private:
    /**
     * @brief scan UDP packet with vector filtering
     *
     * @param payload payload packet to scan
     * @return std::vector<int> rules found in payload
     */
    std::vector<int> scanUdpVf(std::span<const uint8_t> payload) const;

    /**
     * @brief determine the most severe action for the given matching rules
     *
     * @param hits rule IDs that matched
     * @param proto packet protocol
     * @return RuleHelper::RuleMeta::Action The most severe applicable action
     */
    RuleHelper::RuleMeta::Action worstActionForHits(const std::vector<int> &hits, RuleHelper::RuleMeta::Proto proto) const;

    /**
     * @brief reload rules from disk if the ICD file was modified
     */
    void reloadRulesFromDisk();
    /**
     * @brief reload the new rules from the disk into the vector filter system
     *
     */
    void reloadRulesIfChanged();
    Decision evaluateTCP(const pcpp::Packet &packet,
                         Decision finalDecision,
                         TimePoint start,
                         janus::common::ProcessingStamp policyStamp);
    Decision evaluateUDP(const pcpp::Packet &packet,
                         Decision finalDecision,
                         TimePoint start,
                         janus::common::ProcessingStamp policyStamp);
    bool udpHasAhoHits(Decision &finalDecision,
                       std::span<const uint8_t> &payload,
                       janus::common::ProcessingStamp &policyStamp,
                       std::string &data);
    void scanRegexUDP(bool &blockPacket,
                      Decision &finalDecision,
                      janus::common::ProcessingStamp &policyStamp,
                      std::string &data);

private:
    AhoCorasick &ahoCorasick;
    RegexEngine regexEngine;
    VectorFilteringEngine vectorEngine;
    std::unordered_map<int, RuleHelper::RuleMeta> metaByRuleId;
    mutable std::mutex policyMutex;
    TcpStreamHandler tcpHandler;
};