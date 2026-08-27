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
static constexpr std::string_view rulesPath = "/app/rules.json";

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

    /**
     * @brief add a new rule dynamically to the policy engines
     *
     * @param meta rule metadata to add
     * @return true if the rule was added successfully, false otherwise
     */
    bool addRule(RuleHelper::RuleMeta &meta);

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
     * @brief evaluate a TCP packet using the TCP stream handler
     *
     * @param packet packet to evaluate
     * @param finalDecision current decision object
     * @param start packet processing start time
     * @param policyStamp processing stamp for the policy stage
     * @return Decision final decision after TCP evaluation
     */
    Decision evaluateTCP(const pcpp::Packet &packet,
                         Decision finalDecision,
                         TimePoint start,
                         janus::common::ProcessingStamp policyStamp);
    /**
     * @brief evaluate a UDP packet directly through the filtering engines
     *
     * @param packet packet to evaluate
     * @param finalDecision current decision object
     * @param start packet processing start time
     * @param policyStamp processing stamp for the policy stage
     * @return Decision final decision after UDP evaluation
     */
    Decision evaluateUDP(const pcpp::Packet &packet,
                         Decision &finalDecision,
                         TimePoint start,
                         janus::common::ProcessingStamp policyStamp);
    /**
     * @brief check if UDP payload has Aho-Corasick matches
     *
     * @param finalDecision current decision object
     * @param payload UDP payload to scan
     * @param policyStamp processing stamp for the policy stage
     * @param data payload data as text
     * @return true if Aho-Corasick found a match, false otherwise
     */
    bool udpHasAhoHits(Decision &finalDecision,
                       std::span<const uint8_t> payload,
                       janus::common::ProcessingStamp &policyStamp,
                       std::string_view data);
    /**
     * @brief scan UDP payload with regex rules
     *
     * @param blockPacket set to true if regex requires the packet to be blocked
     * @param finalDecision current decision object
     * @param policyStamp processing stamp for the policy stage
     * @param data payload data as text
     */
    void scanRegexUDP(bool &blockPacket,
                      Decision &finalDecision,
                      janus::common::ProcessingStamp &policyStamp,
                      std::string_view data);

private:
    AhoCorasick &ahoCorasick;
    RegexEngine regexEngine;
    VectorFilteringEngine vectorEngine;
    std::unordered_map<int, RuleHelper::RuleMeta> metaByRuleId;
    mutable std::mutex policyMutex;
    TcpStreamHandler tcpHandler;
};