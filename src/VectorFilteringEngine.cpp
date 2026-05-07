#include "VectorFilteringEngine.hpp"

#include <algorithm>
#include <stdexcept>

static inline void bitmapSet(std::array<uint64_t, 4> &bitMap, uint8_t bitToCheck)
{
    bitMap[bitToCheck / BITS_IN_MAP_BUCKET] |= (1ull << (bitToCheck % BITS_IN_MAP_BUCKET));
}
static inline bool bitmapHas(const std::array<uint64_t, 4> &bitMap, uint8_t bitToCheck)
{
    return (bitMap[bitToCheck / BITS_IN_MAP_BUCKET] >> (bitToCheck % BITS_IN_MAP_BUCKET)) & 1ull;
}
VFRule VFRule::fromASCII(int id, std::size_t offset, const std::string &ruleString)
{
    VFRule rule{};
    rule.ruleId = id;
    rule.offset = offset;

    const std::size_t anchorLength = std::min<std::size_t>(4, ruleString.size());
    rule.length = static_cast<std::uint8_t>(anchorLength);
    rule.bytes = {0, 0, 0, 0};

    for (std::size_t i = 0; i < anchorLength; ++i)
        rule.bytes[i] = static_cast<std::uint8_t>(ruleString[i]);
    rule.description = ruleString;

    return rule;
}
const std::string &VectorFilteringEngine::describe(int id) const
{
    static const std::string unknown = "<unknown>";
    auto iterator = m_ruleDescriptions.find(id);
    return (iterator != m_ruleDescriptions.end())
               ? iterator->second
               : unknown;
}
void VectorFilteringEngine::build(const std::vector<VFRule> &rules)
{
    std::unordered_map<GroupKey, std::vector<VFRule>, GroupKeyHash> buckets;

    for (const auto &rule : rules)
    {
        if (rule.length < 1 || rule.length > 4)
            throw std::invalid_argument("VFRule.length must be 1..4");

        buckets[{rule.offset, rule.length}].push_back(rule);
        m_ruleDescriptions[rule.ruleId] = rule.description;
    }

    m_groups.clear();
    m_groups.reserve(buckets.size());

    for (auto &[key, bucket] : buckets)
    {
        Group group;
        group.offset = key.offset;
        group.length = key.length;
        padAndPack(group, bucket);
        m_groups[key] = group;
    }
}

void VectorFilteringEngine::addRule(RuleHelper::RuleMeta &newRule)
{
    VFRule rule{};
    rule.ruleId = newRule.ruleId;
    rule.offset = (std::size_t)newRule.exact_offset;
    rule.length = (std::uint8_t)newRule.length;
    rule.bytes = newRule.bytes;
    rule.description = newRule.desc;

    addRuleToVectorEngine(rule);
    int ruleId = RuleHelper::idToRuleID(newRule);
    metaByRuleId->at(ruleId) = std::move(newRule);
}

bool VectorFilteringEngine::addRuleToVectorEngine(VFRule newRule)
{
    GroupKey key{newRule.offset, newRule.length};

    auto it = m_groups.find(key);
    if (it == m_groups.end())
    {
        Group group{};
        group.offset = newRule.offset;
        group.length = newRule.length;
        group.groupRuleCount = 0;
        group.lanesPadded = simd_u8::size();
        group.anchorBytes.assign(group.length, std::vector<std::uint8_t>(group.lanesPadded, 0));
        group.ruleIDs.assign(group.lanesPadded, -1);

        auto inserted = m_groups.emplace(key, std::move(group));
        it = inserted.first;
    }

    Group *groupToInsert = &it->second;
    if (groupToInsert)
    {
        if (groupToInsert->groupRuleCount + 1 > groupToInsert->lanesPadded)
        {
            groupToInsert->lanesPadded += simd_u8::size();
            groupToInsert->ruleIDs.resize(groupToInsert->lanesPadded, -1);
        }

        groupToInsert->ruleIDs.at(groupToInsert->groupRuleCount) = newRule.ruleId;
        for (auto &byteVector : groupToInsert->anchorBytes)
        {
            byteVector.resize(groupToInsert->lanesPadded, 0);
        }

        for (int i = 0; i < groupToInsert->length; ++i)
        {
            groupToInsert->anchorBytes.at(i).at(groupToInsert->groupRuleCount) = newRule.bytes.at(i);
        }

        bitmapSet(groupToInsert->firstByteBitmap, newRule.bytes.at(0));
        m_ruleDescriptions[newRule.ruleId] = newRule.description;
        groupToInsert->groupRuleCount++;
        return true;
    }
    return false;
}

void VectorFilteringEngine::padAndPack(Group &group, const std::vector<VFRule> &rulesInGroup)
{
    constexpr std::size_t width = simd_u8::size();

    const std::size_t size = rulesInGroup.size();
    const std::size_t padded = ((size + width - 1) / width) * width;
    group.anchorBytes.assign(
        group.length,
        std::vector<std::uint8_t>(padded, 0));
    group.lanesPadded = padded;
    group.groupRuleCount = rulesInGroup.size();

    group.firstByteBitmap = {0, 0, 0, 0};
    for (std::size_t i = 0; i < size; ++i)
    {
        bitmapSet(group.firstByteBitmap, rulesInGroup[i].bytes[0]);
    }

    group.ruleIDs.assign(padded, -1);

    for (std::size_t currentRule = 0; currentRule < size; ++currentRule)
    {
        const auto &rule = rulesInGroup[currentRule];
        for (std::size_t anchorByteNumber = 0; anchorByteNumber < group.length; anchorByteNumber++)
        {
            std::size_t &ruleByteNumber = anchorByteNumber;
            group.anchorBytes.at(anchorByteNumber).at(currentRule) = rule.bytes[ruleByteNumber];
        }
        group.ruleIDs[currentRule] = rule.ruleId;
    }
}

static simd_u8::mask_type compareVectors(simd_u8 payloadVector, simd_u8 anchorVector)
{
    return payloadVector == anchorVector;
}

std::vector<int> VectorFilteringEngine::scanPayload(std::span<const std::uint8_t> payload) const
{
    std::vector<int> hits;
    hits.reserve(16);

    constexpr std::size_t width = simd_u8::size();

    for (const auto &g : m_groups)
    {
        auto &group = g.second;
        if (payload.size() < group.offset + group.length)
            continue;
        std::vector<simd_u8> payloadVectors;
        for (int i = 0; i < group.length; i++)
        {
            payloadVectors.emplace_back(payload[group.offset + i]);
        }
        if (!bitmapHas(group.firstByteBitmap, payload[group.offset]))
            continue;
        for (std::size_t base = 0; base < group.lanesPadded; base += width)
        {
            const simd_u8 vectorAnchor0(&group.anchorBytes.at(0)[base], simd_ns::element_aligned);
            mask_t mask = compareVectors(payloadVectors.at(0), vectorAnchor0);
            for (int i = 1; i < group.length; i++)
            {
                const simd_u8 vectorAnchor(&group.anchorBytes.at(i)[base], simd_ns::element_aligned);
                mask &= compareVectors(payloadVectors.at(i), vectorAnchor);
            }

            if (!any_of(mask))
                continue;

            for (std::size_t lane = 0; lane < width; ++lane)
            {
                if (!mask[lane])
                    continue;
                const int id = group.ruleIDs[base + lane];
                if (id != -1)
                    hits.push_back(id);
            }
        }
    }

    std::sort(hits.begin(), hits.end());
    hits.erase(std::unique(hits.begin(), hits.end()), hits.end());

    return hits;
}
