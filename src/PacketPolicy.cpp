#include "PacketPolicy.hpp"
#include "BlacklistHandler.hpp"
#include "PcapParser.hpp"

#include <pcapplusplus/UdpLayer.h>
#include <print>

PacketPolicy::PacketPolicy(AhoCorasick &ac)
    : ahoCorasick(ac),
      vectorEngine(),
      tcpHandler(ac, vectorEngine)
{
    auto loaded = IcdLoader::loadFromFile("/app/icd.json");
    vectorEngine.build(loaded.rules);
    metaByRuleId = std::move(loaded.metaByRuleId);
    maxScanShiftBytes = loaded.maxScanShiftBytes;

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
        if (!hits.empty())
        {
            out = std::move(hits);
            return out;
        }
    }

    return out;
}

Decision PacketPolicy::evaluate(const pcpp::Packet &packet)
{
    Decision d{};

    // 1) Blacklists / allowlist
    if (BlacklistHandler::isIPBlacklisted(packet) ||
        BlacklistHandler::isPortBlacklisted(packet) ||
        !BlacklistHandler::isProtocolAllowed(packet))
    {
        d.verdict = FinalVerdict::DROP;
        return d;
    }

    // 2) Protocol branch
    auto proto = PcapParser::getTransportProtocol(packet);

    if (proto == pcpp::TCP)
    {
        // TCP: handler עושה VF gate + Aho confirm על window
        auto res = tcpHandler.processPacket(const_cast<pcpp::Packet &>(packet));

        d.vfHits = res.vfRuleIds;
        d.ahoInfo = res.ahoInfo;

        const auto worst = worstActionForHits(d.vfHits, IcdRuleMeta::Proto::TCP);

        // אם אין VF hit בכלל -> allow
        if (!res.vfHit)
        {
            d.verdict = FinalVerdict::ALLOW;
            return d;
        }

        d.flagged = (worst != IcdRuleMeta::Action::ALLOW);

        // Deep inspection כבר קרה (Aho), אז נסמן inspected
        d.inspected = true;

        // Drop רק אם:
        // - יש Aho hit (confirmed)
        // - והחומרה דורשת BLOCK
        if (res.ahoHit && worst == IcdRuleMeta::Action::BLOCK)
        {
            d.verdict = FinalVerdict::DROP;
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
        }
        return d;
    }

    if (proto == pcpp::UDP)
    {
        auto *udp = packet.getLayerOfType<pcpp::UdpLayer>();
        if (!udp)
        {
            d.verdict = FinalVerdict::ALLOW;
            return d;
        }

        std::span<const uint8_t> pl(udp->getLayerPayload(), udp->getLayerPayloadSize());
        d.vfHits = scanUdpVf(pl);

        if (d.vfHits.empty())
        {
            d.verdict = FinalVerdict::ALLOW;
            return d;
        }

        const auto worst = worstActionForHits(d.vfHits, IcdRuleMeta::Proto::UDP);
        d.flagged = (worst != IcdRuleMeta::Action::ALLOW);

        // Deep inspection only when VF hit exists
        d.inspected = true;
        std::string data(reinterpret_cast<const char *>(pl.data()), pl.size());
        auto ahoRes = ahoCorasick.search(data);
        if (ahoRes.has_value())
            d.ahoInfo = ahoRes.value();

        // confirmed block only if Aho hit AND rule severity BLOCK
        if (ahoRes.has_value() && worst == IcdRuleMeta::Action::BLOCK)
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
        return d;
    }

    // other protocols: allow
    d.verdict = FinalVerdict::ALLOW;
    return d;
}