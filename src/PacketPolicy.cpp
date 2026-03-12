#include "PacketPolicy.hpp"
#include "BlacklistHandler.hpp"
#include "PcapParser.hpp"

#include "janus_common.pb.h"
#include "janus_packet.pb.h"
#include <pcapplusplus/UdpLayer.h>
#include <print>
#include <chrono>

PacketPolicy::PacketPolicy(AhoCorasick &ac)
    : ahoCorasick(ac),
      vectorEngine(),
      regexEngine(),
      tcpHandler(ac, vectorEngine, regexEngine)
{
    auto loaded = IcdLoader::loadFromFile("/app/icd.json");
    vectorEngine.build(loaded.rules);
    metaByRuleId = std::move(loaded.metaByRuleId);
    tcpHandler.setRuleMeta(&metaByRuleId);
    maxScanShiftBytes = loaded.maxScanShiftBytes;
    for (const auto &[rid, meta] : metaByRuleId)
    {
        if (!meta.regex_pattern.empty())
        {
            regexEngine.addRule(rid, meta.regex_pattern, meta.desc);
        }
    }
    std::println("PacketPolicy ready. ICD loaded rules={}", loaded.rules.size());
    std::println("PacketPolicy: maxScanShiftBytes={}", maxScanShiftBytes);
}

void PacketPolicy::readPolicyLists()
{
    BlacklistHandler::initializeIPList();
    BlacklistHandler::initializePortList();
}

static bool protoMatches(IcdRuleMeta::Proto ruleProto, IcdRuleMeta::Proto pktProto)
{
    return (ruleProto == IcdRuleMeta::Proto::ANY) || (ruleProto == pktProto);
}
static const char *actionName(IcdRuleMeta::Action a)
{
    switch (a)
    {
    case IcdRuleMeta::Action::ALLOW:
        return "ALLOW";
    case IcdRuleMeta::Action::FLAG:
        return "FLAG";
    case IcdRuleMeta::Action::BLOCK:
        return "BLOCK";
    default:
        return "?";
    }
}

IcdRuleMeta::Action PacketPolicy::worstActionForHits(const std::vector<int> &hits, IcdRuleMeta::Proto pktProto) const
{
    IcdRuleMeta::Action worst = IcdRuleMeta::Action::ALLOW;

    for (int rid : hits)
    {
        auto it = metaByRuleId.find(rid);
        if (it == metaByRuleId.end())
            continue;

        const auto &meta = it->second;
        if (!protoMatches(meta.proto, pktProto))
            continue;

        if (meta.action == IcdRuleMeta::Action::BLOCK)
            return IcdRuleMeta::Action::BLOCK;

        if (meta.action == IcdRuleMeta::Action::FLAG)
            worst = IcdRuleMeta::Action::FLAG;
    }

    return worst;
}
std::vector<int> PacketPolicy::scanUdpVf(std::span<const uint8_t> payload) const
{
    std::vector<int> out;
    if (payload.empty())
        return out;

    const int maxShift = std::min<int>(maxScanShiftBytes, (int)payload.size());

    for (int shift = 0; shift <= maxShift; ++shift)
    {
        std::span<const uint8_t> win(payload.data() + shift, payload.size() - shift);
        auto hits = vectorEngine.scanPayload(win);

        for (int rid : hits)
        {
            auto it = metaByRuleId.find(rid);
            if (it != metaByRuleId.end())
            {
                if (it->second.offset_mode == "EXACT" && shift != 0)
                {
                    continue;
                }
                out.push_back(rid);
            }
        }

        if (!out.empty())
        {
            return out;
        }
    }

    return out;
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

Decision PacketPolicy::evaluate(const pcpp::Packet &packet)
{
    janus::common::ProcessingStamp policyStamp;
    policyStamp.set_stage(janus::common::ENGINE_STAGE_POLICY);
    auto start = std::chrono::steady_clock::now();
    policyStamp.set_started_unix_ms(nowUnixMs());
    Decision d{};
    auto finishPolicy = [&](const std::string &status)
    {
        auto end = std::chrono::steady_clock::now();
        uint64_t durationUs =
            std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

        policyStamp.set_finished_unix_ms(nowUnixMs());
        policyStamp.set_duration_us(durationUs);
        policyStamp.set_status(status);
        d.trace.push_back(policyStamp);
    };
    if (BlacklistHandler::isIPBlacklisted(packet) ||
        BlacklistHandler::isPortBlacklisted(packet) ||
        !BlacklistHandler::isProtocolAllowed(packet))
    {
        d.verdict = FinalVerdict::DROP;
        finishPolicy("packet denied by blacklist/policy");
        return d;
    }

    auto proto = PcapParser::getTransportProtocol(packet);

    if (proto == pcpp::TCP)
    {
        auto res = tcpHandler.processPacket(const_cast<pcpp::Packet &>(packet));

        d.vfHits = res.vfRuleIds;
        d.ahoInfo = res.ahoInfo;
        d.trace.insert(d.trace.end(), res.trace.begin(), res.trace.end());
        const auto worst = worstActionForHits(d.vfHits, IcdRuleMeta::Proto::TCP);

        if (!res.vfHit)
        {
            d.verdict = FinalVerdict::ALLOW;
            finishPolicy("packet Approved");
            return d;
        }

        d.flagged = (worst != IcdRuleMeta::Action::ALLOW);

        d.inspected = true;

        if (res.ahoHit && worst == IcdRuleMeta::Action::BLOCK)
        {
            d.verdict = FinalVerdict::DROP;
            finishPolicy("packet Denied");
            return d;
        }

        d.verdict = FinalVerdict::ALLOW;
        if (!d.vfHits.empty())
        {
            const int rid = d.vfHits[0];
            auto it = metaByRuleId.find(rid);
            if (it != metaByRuleId.end())
            {
                const auto &m = it->second;
                std::println("VF hit: rid={} id={} action={} flagged={} inspected={} verdict={}",
                             rid, m.id, actionName(m.action),
                             d.flagged ? 1 : 0,
                             d.inspected ? 1 : 0,
                             (d.verdict == FinalVerdict::DROP ? "DROP" : "ALLOW"));
            }
            else
            {
                std::println("VF hit: rid={} (no-meta) hits={} flagged={} inspected={} verdict={}",
                             rid, (int)d.vfHits.size(),
                             d.flagged ? 1 : 0,
                             d.inspected ? 1 : 0,
                             (d.verdict == FinalVerdict::DROP ? "DROP" : "ALLOW"));
            }
        }
        if (!d.ahoInfo.empty())
        {

            std::println("AHO hit: {}", d.ahoInfo);
            finishPolicy("packet Denied");
        }
        finishPolicy(d.verdict == FinalVerdict::DROP ? "packet Denied" : "packet Approved");
        return d;
    }

    if (proto == pcpp::UDP)
    {
        auto *udp = packet.getLayerOfType<pcpp::UdpLayer>();
        if (!udp)
        {
            d.verdict = FinalVerdict::ALLOW;
            finishPolicy("packet Approved");
            return d;
        }

        std::span<const uint8_t> pl(udp->getLayerPayload(), udp->getLayerPayloadSize());
        uint64_t vfStartMs = nowUnixMs();
        auto vfStart = std::chrono::steady_clock::now();

        d.vfHits = scanUdpVf(pl);

        auto vfEnd = std::chrono::steady_clock::now();
        uint64_t vfEndMs = nowUnixMs();
        uint64_t vfDurationUs =
            std::chrono::duration_cast<std::chrono::microseconds>(vfEnd - vfStart).count();

        d.trace.push_back(makeTraceEntry(
            janus::common::ENGINE_STAGE_VECTOR_FILTER,
            vfStartMs,
            vfEndMs,
            vfDurationUs,
            d.vfHits.empty() ? "no hits" : "vf hits found"));

        if (d.vfHits.empty())
        {
            d.verdict = FinalVerdict::ALLOW;
            finishPolicy("packet Approved");
            return d;
        }

        const auto worst = worstActionForHits(d.vfHits, IcdRuleMeta::Proto::UDP);
        d.flagged = (worst != IcdRuleMeta::Action::ALLOW);

        d.inspected = true;
        std::string data(reinterpret_cast<const char *>(pl.data()), pl.size());
        bool confirmedHit = false;

        uint64_t ahoStartMs = nowUnixMs();
        auto ahoStart = std::chrono::steady_clock::now();

        auto ahoRes = ahoCorasick.search(data);

        auto ahoEnd = std::chrono::steady_clock::now();
        uint64_t ahoEndMs = nowUnixMs();
        uint64_t ahoDurationUs =
            std::chrono::duration_cast<std::chrono::microseconds>(ahoEnd - ahoStart).count();

        d.trace.push_back(makeTraceEntry(
            janus::common::ENGINE_STAGE_AHO,
            ahoStartMs,
            ahoEndMs,
            ahoDurationUs,
            ahoRes.has_value() ? "aho hit" : "no aho hit"));
        if (ahoRes.has_value())
        {
            confirmedHit = true;
            policyStamp.set_status("packet Denied Aho Corasick");
            d.ahoInfo = ahoRes.value();
        }
        uint64_t regexStartMs = 0;
        uint64_t regexEndMs = 0;
        uint64_t regexDurationUs = 0;
        bool regexRan = false;
        bool regexHit = false;
        if (!confirmedHit)
        {

            auto regexStart = std::chrono::steady_clock::now();
            regexStartMs = nowUnixMs();
            regexRan = true;

            for (int rid : d.vfHits)
            {
                auto it = metaByRuleId.find(rid);
                if (it != metaByRuleId.end())
                {
                    if (!it->second.regex_pattern.empty())
                    {
                        if (regexEngine.matchRule(rid, data))
                        {
                            confirmedHit = true;
                            regexHit = true;
                            policyStamp.set_status("packet Denied REGEX");
                            d.ahoInfo = "Regex Hit [Rule " + std::to_string(rid) + "]: " + it->second.desc;
                            break;
                        }
                    }
                }
            }

            auto regexEnd = std::chrono::steady_clock::now();
            regexEndMs = nowUnixMs();
            regexDurationUs =
                std::chrono::duration_cast<std::chrono::microseconds>(regexEnd - regexStart).count();
        }
        if (regexRan)
        {
            d.trace.push_back(makeTraceEntry(
                janus::common::ENGINE_STAGE_REGEX,
                regexStartMs,
                regexEndMs,
                regexDurationUs,
                regexHit ? "regex hit" : "no regex hit"));
        }
        if (confirmedHit && worst == IcdRuleMeta::Action::BLOCK)
            d.verdict = FinalVerdict::DROP;
        else
            d.verdict = FinalVerdict::ALLOW;

        if (!d.vfHits.empty())
        {
            const int rid = d.vfHits[0];
            auto it = metaByRuleId.find(rid);
            if (it != metaByRuleId.end())
            {
                const auto &m = it->second;
                std::println("VF hit: rid={} id={} action={} flagged={} inspected={} verdict={}",
                             rid, m.id, actionName(m.action),
                             d.flagged ? 1 : 0,
                             d.inspected ? 1 : 0,
                             (d.verdict == FinalVerdict::DROP ? "DROP" : "ALLOW"));
            }
            else
            {
                std::println("VF hit: rid={} (no-meta) hits={} flagged={} inspected={} verdict={}",
                             rid, (int)d.vfHits.size(),
                             d.flagged ? 1 : 0,
                             d.inspected ? 1 : 0,
                             (d.verdict == FinalVerdict::DROP ? "DROP" : "ALLOW"));
            }
        }
        if (!d.ahoInfo.empty())
        {

            std::println("AHO hit: {}", d.ahoInfo);
        }
        finishPolicy(d.verdict == FinalVerdict::DROP ? "packet Denied" : "packet Approved");
        return d;
    }

    d.verdict = FinalVerdict::ALLOW;

    finishPolicy("packet Approved");
    return d;
}