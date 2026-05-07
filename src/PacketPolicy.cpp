#include "PacketPolicy.hpp"
#include "BlacklistHandler.hpp"
#include "PcapParser.hpp"

#include "janus_common.pb.h"
#include "janus_packet.pb.h"
#include <pcapplusplus/UdpLayer.h>
#include <print>
#include <chrono>
#include "Logger.hpp"
#include <filesystem>

PacketPolicy::PacketPolicy(AhoCorasick &ac)
    : ahoCorasick(ac),
      vectorEngine(),
      regexEngine(),
      tcpHandler(ac, vectorEngine, regexEngine)
{
    auto loaded = RuleLoader::loadFromFile("/app/icd.json");
    vectorEngine.build(loaded.rules);

    for (const auto &[rid, meta] : loaded.metaByRuleId)
    {

        if (!meta.regex_pattern.empty())
        {
            regexEngine.addRule(rid, meta.regex_pattern, meta.desc);
        }
    }
    metaByRuleId = std::move(loaded.metaByRuleId);
    tcpHandler.setRuleMeta(&metaByRuleId);
}

void PacketPolicy::readPolicyLists()
{
    BlacklistHandler::initializeIPList();
    BlacklistHandler::initializePortList();
}

static bool protoMatches(RuleHelper::RuleMeta::Proto ruleProto, RuleHelper::RuleMeta::Proto pktProto)
{
    return (ruleProto == RuleHelper::RuleMeta::Proto::ANY) || (ruleProto == pktProto);
}

static const char *actionName(RuleHelper::RuleMeta::Action a)
{
    switch (a)
    {
    case RuleHelper::RuleMeta::Action::ALLOW:
        return "ALLOW";
    case RuleHelper::RuleMeta::Action::FLAG:
        return "FLAG";
    case RuleHelper::RuleMeta::Action::BLOCK:
        return "BLOCK";
    default:
        return "?";
    }
}

RuleHelper::RuleMeta::Action PacketPolicy::worstActionForHits(const std::vector<int> &hits, RuleHelper::RuleMeta::Proto pktProto) const
{
    RuleHelper::RuleMeta::Action worst = RuleHelper::RuleMeta::Action::ALLOW;

    for (int rid : hits)
    {
        auto it = metaByRuleId.find(rid);
        if (it == metaByRuleId.end())
            continue;

        const auto &meta = it->second;
        if (!protoMatches(meta.proto, pktProto))
            continue;

        if (meta.action == RuleHelper::RuleMeta::Action::BLOCK)
            return RuleHelper::RuleMeta::Action::BLOCK;

        if (meta.action == RuleHelper::RuleMeta::Action::FLAG)
            worst = RuleHelper::RuleMeta::Action::FLAG;
    }

    return worst;
}
std::vector<int> PacketPolicy::scanUdpVf(std::span<const uint8_t> payload) const
{
    std::vector<int> rulesHit;
    if (payload.empty())
        return rulesHit;

    const int maxShift = std::min<int>(MAX_BYTE_SHIFT, (int)payload.size());

    for (int shift = 0; shift <= maxShift; ++shift)
    {
        std::span<const uint8_t> window(payload.data() + shift, payload.size() - shift);
        auto hits = vectorEngine.scanPayload(window);

        for (int ruleId : hits)
        {
            auto iterator = metaByRuleId.find(ruleId);
            if (iterator != metaByRuleId.end())
            {
                if (iterator->second.offset_mode == "EXACT" && shift != 0)
                {
                    continue;
                }
                rulesHit.push_back(ruleId);
            }
        }
    }

    std::sort(rulesHit.begin(), rulesHit.end());
    rulesHit.erase(std::unique(rulesHit.begin(), rulesHit.end()), rulesHit.end());
    return rulesHit;
}
static janus::common::ProcessingStamp makeTraceEntry(
    janus::common::EngineStage stage,
    uint64_t startedUnixMs,
    uint64_t finishedUnixMs,
    uint64_t durationUs,
    std::string status)
{
    janus::common::ProcessingStamp e;
    e.set_stage(stage);
    e.set_started_unix_ms(startedUnixMs);
    e.set_finished_unix_ms(finishedUnixMs);
    e.set_duration_us(durationUs);
    e.set_status(status);
    return e;
}
static uint64_t nowUnixMs()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(
               system_clock::now().time_since_epoch())
        .count();
}
static void finishPolicy(const std::string &status,
                         const TimePoint start,
                         janus::common::ProcessingStamp &policyStamp,
                         Decision &finalDecision)
{
    auto end = std::chrono::steady_clock::now();
    uint64_t durationUs =
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    policyStamp.set_finished_unix_ms(nowUnixMs());
    policyStamp.set_duration_us(durationUs);
    policyStamp.set_status(status);
    finalDecision.trace.push_back(policyStamp);
};

Decision PacketPolicy::evaluateTCP(const pcpp::Packet &packet,
                                   Decision finalDecision,
                                   TimePoint start,
                                   janus::common::ProcessingStamp policyStamp)
{
    auto res = tcpHandler.processPacket(const_cast<pcpp::Packet &>(packet));

    finalDecision.vfHits = res.vfRuleIds;
    finalDecision.ahoInfo = res.ahoInfo;
    finalDecision.trace.insert(finalDecision.trace.end(), res.trace.begin(), res.trace.end());
    const auto worst = worstActionForHits(finalDecision.vfHits, RuleHelper::RuleMeta::Proto::TCP);

    if (!res.vfHit)
    {
        finalDecision.verdict = FinalVerdict::ALLOW;
        finishPolicy("packet Approved", start, policyStamp, finalDecision);
        return finalDecision;
    }

    finalDecision.flagged = (worst != RuleHelper::RuleMeta::Action::ALLOW);

    finalDecision.inspected = true;

    if (res.ahoHit && worst == RuleHelper::RuleMeta::Action::BLOCK)
    {
        finalDecision.verdict = FinalVerdict::DROP;
        finishPolicy("packet Denied", start, policyStamp, finalDecision);
        return finalDecision;
    }

    finalDecision.verdict = FinalVerdict::ALLOW;

    finishPolicy(finalDecision.verdict == FinalVerdict::DROP ? "packet Denied" : "packet Approved", start, policyStamp, finalDecision);
    return finalDecision;
}

bool PacketPolicy::udpHasAhoHits(Decision &finalDecision,
                                 std::span<const uint8_t> &payload,
                                 janus::common::ProcessingStamp &policyStamp,
                                 std::string &data)
{
    bool confirmedHit = false;
    uint64_t ahoStartMs = nowUnixMs();
    auto ahoStart = std::chrono::steady_clock::now();
    auto ahoResult = ahoCorasick.search(data);
    auto ahoEnd = std::chrono::steady_clock::now();
    uint64_t ahoEndMs = nowUnixMs();
    uint64_t ahoDurationUs =
        std::chrono::duration_cast<std::chrono::microseconds>(ahoEnd - ahoStart).count();
    finalDecision.trace.push_back(makeTraceEntry(
        janus::common::ENGINE_STAGE_AHO,
        ahoStartMs,
        ahoEndMs,
        ahoDurationUs,
        ahoResult.has_value() ? "aho hit" : "no aho hit"));
    if (ahoResult.has_value())
    {
        confirmedHit = true;
        policyStamp.set_status("packet Denied Aho Corasick");
        finalDecision.ahoInfo = ahoResult.value();
    }
    return confirmedHit;
}
void PacketPolicy::scanRegexUDP(bool &blockPacket,
                                Decision &finalDecision,
                                janus::common::ProcessingStamp &policyStamp,
                                std::string &data)
{
    uint64_t regexStartMs = 0;
    uint64_t regexEndMs = 0;
    uint64_t regexDurationUs = 0;
    bool regexHit = false;
    auto regexStart = std::chrono::steady_clock::now();
    regexStartMs = nowUnixMs();

    for (int rid : finalDecision.vfHits)
    {
        auto it = metaByRuleId.find(rid);
        if (it != metaByRuleId.end())
        {
            if (!it->second.regex_pattern.empty())
            {
                if (regexEngine.matchRule(rid, data))
                {
                    regexHit = true;
                    policyStamp.set_status("packet Denied REGEX");
                    finalDecision.ahoInfo = "Regex Hit [Rule " + std::to_string(rid) + "]: " + it->second.desc;
                    blockPacket = true;
                    break;
                }
            }
        }
    }

    auto regexEnd = std::chrono::steady_clock::now();
    regexEndMs = nowUnixMs();
    regexDurationUs =
        std::chrono::duration_cast<std::chrono::microseconds>(regexEnd - regexStart).count();
    finalDecision.trace.push_back(makeTraceEntry(
        janus::common::ENGINE_STAGE_REGEX,
        regexStartMs,
        regexEndMs,
        regexDurationUs,
        regexHit ? "regex hit" : "no regex hit"));
}

Decision PacketPolicy::evaluateUDP(const pcpp::Packet &packet,
                                   Decision finalDecision,
                                   TimePoint start,
                                   janus::common::ProcessingStamp policyStamp)
{
    bool blockPacket = false;
    auto *udp = packet.getLayerOfType<pcpp::UdpLayer>();

    std::span<const uint8_t> payload(udp->getLayerPayload(), udp->getLayerPayloadSize());
    uint64_t vfStartMs = nowUnixMs();
    auto vectorFilteringStart = std::chrono::steady_clock::now();

    finalDecision.vfHits = scanUdpVf(payload);

    auto vectorFilteringEnd = std::chrono::steady_clock::now();
    uint64_t vectorFilterEndMs = nowUnixMs();
    uint64_t vectorFilterDurationUs =
        std::chrono::duration_cast<std::chrono::microseconds>(vectorFilteringEnd - vectorFilteringStart).count();

    finalDecision.trace.push_back(makeTraceEntry(
        janus::common::ENGINE_STAGE_VECTOR_FILTER,
        vfStartMs,
        vectorFilterEndMs,
        vectorFilterDurationUs,
        finalDecision.vfHits.empty() ? "no hits" : "vf hits found"));

    if (finalDecision.vfHits.empty())
    {
        finalDecision.verdict = FinalVerdict::ALLOW;
        finishPolicy("packet Approved", start, policyStamp, finalDecision);
        return finalDecision;
    }

    const auto worst = worstActionForHits(finalDecision.vfHits, RuleHelper::RuleMeta::Proto::UDP);
    finalDecision.flagged = (worst != RuleHelper::RuleMeta::Action::ALLOW);

    finalDecision.inspected = true;
    std::string data(reinterpret_cast<const char *>(payload.data()), payload.size());
    blockPacket = udpHasAhoHits(finalDecision, payload, policyStamp, data);
    if (!blockPacket)
    {
        scanRegexUDP(blockPacket, finalDecision, policyStamp, data);
    }
    if (blockPacket && worst == RuleHelper::RuleMeta::Action::BLOCK)
        finalDecision.verdict = FinalVerdict::DROP;
    else
        finalDecision.verdict = FinalVerdict::ALLOW;

    finishPolicy(finalDecision.verdict == FinalVerdict::DROP ? "packet Denied" : "packet Approved",
                 start, policyStamp, finalDecision);
    return finalDecision;
}

Decision PacketPolicy::evaluate(const pcpp::Packet &packet)
{

    janus::common::ProcessingStamp policyStamp;
    policyStamp.set_stage(janus::common::ENGINE_STAGE_POLICY);
    auto start = std::chrono::steady_clock::now();
    policyStamp.set_started_unix_ms(nowUnixMs());

    Decision finalDecision{};

    if (BlacklistHandler::isIPBlacklisted(packet) ||
        BlacklistHandler::isPortBlacklisted(packet) ||
        !BlacklistHandler::isProtocolAllowed(packet))
    {
        finalDecision.verdict = FinalVerdict::DROP;
        finishPolicy("packet denied by blacklist/policy", start, policyStamp, finalDecision);
        return finalDecision;
    }

    auto proto = PcapParser::getTransportProtocol(packet);

    if (proto == pcpp::TCP)
    {
        return evaluateTCP(packet, finalDecision, start, policyStamp);
    }

    if (proto == pcpp::UDP)
    {
        return evaluateUDP(packet, finalDecision, start, policyStamp);
    }

    finalDecision.verdict = FinalVerdict::ALLOW;

    finishPolicy("packet Approved", start, policyStamp, finalDecision);
    return finalDecision;
}