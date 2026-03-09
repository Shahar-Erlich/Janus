#include "VectorFilteringEngine.hpp"

#include <algorithm>
#include <stdexcept>
#include <print>
static inline void bitmapSet(std::array<uint64_t, 4> &bm, uint8_t b)
{
    bm[b >> 6] |= (1ull << (b & 63));
}
static inline bool bitmapHas(const std::array<uint64_t, 4> &bm, uint8_t b)
{
    return (bm[b >> 6] >> (b & 63)) & 1ull;
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
        m_groups.push_back(std::move(group));
    }

    std::sort(m_groups.begin(), m_groups.end(), [](const Group &groupA, const Group &groupB)
              {
        if (groupA.offset != groupB.offset) return groupA.offset < groupB.offset;
        return groupA.length < groupB.length; });
}

void VectorFilteringEngine::padAndPack(Group &group, const std::vector<VFRule> &rulesInGroup)
{
    constexpr std::size_t width = simd_u8::size();
    std::println("SMD WIDTH IS: {}", width);

    const std::size_t size = rulesInGroup.size();
    const std::size_t padded = ((size + width - 1) / width) * width;

    group.lanesPadded = padded;

    group.anbchorByte0.assign(padded, 0);
    group.firstByteBitmap = {0, 0, 0, 0};
    for (std::size_t i = 0; i < size; ++i)
    {
        bitmapSet(group.firstByteBitmap, rulesInGroup[i].bytes[0]);
    }
    group.anbchorByte1.assign(padded, 0);
    group.anbchorByte2.assign(padded, 0);
    group.anbchorByte3.assign(padded, 0);
    group.ruleIDs.assign(padded, -1);

    for (std::size_t i = 0; i < size; ++i)
    {
        const auto &rule = rulesInGroup[i];
        group.anbchorByte0[i] = rule.bytes[0];
        group.anbchorByte1[i] = rule.bytes[1];
        group.anbchorByte2[i] = rule.bytes[2];
        group.anbchorByte3[i] = rule.bytes[3];
        group.ruleIDs[i] = rule.ruleId;
    }
}
bool VectorFilteringEngine::anyHit(std::span<const std::uint8_t> payload) const
{
    constexpr std::size_t width = simd_u8::size();

    for (const auto &group : m_groups)
    {
        if (payload.size() < group.offset + group.length)
            continue;

        const std::uint8_t b0 = payload[group.offset + 0];
        const std::uint8_t b1 = (group.length >= 2) ? payload[group.offset + 1] : 0;
        const std::uint8_t b2 = (group.length >= 3) ? payload[group.offset + 2] : 0;
        const std::uint8_t b3 = (group.length >= 4) ? payload[group.offset + 3] : 0;

        const simd_u8 vp0(b0), vp1(b1), vp2(b2), vp3(b3);
        if (!bitmapHas(group.firstByteBitmap, b0))
            continue;
        for (std::size_t base = 0; base < group.lanesPadded; base += width)
        {
            const simd_u8 va0(&group.anbchorByte0[base], simd_ns::element_aligned);
            mask_t m = (va0 == vp0);

            if (group.length >= 2)
            {
                const simd_u8 va1(&group.anbchorByte1[base], simd_ns::element_aligned);
                m &= (va1 == vp1);
            }
            if (group.length >= 3)
            {
                const simd_u8 va2(&group.anbchorByte2[base], simd_ns::element_aligned);
                m &= (va2 == vp2);
            }
            if (group.length >= 4)
            {
                const simd_u8 va3(&group.anbchorByte3[base], simd_ns::element_aligned);
                m &= (va3 == vp3);
            }

            if (any_of(m))
                return true;
        }
    }
    return false;
}

std::vector<int> VectorFilteringEngine::scanPayload(std::span<const std::uint8_t> payload) const
{
    std::vector<int> hits;
    hits.reserve(16);

    constexpr std::size_t width = simd_u8::size();

    for (const auto &group : m_groups)
    {
        if (payload.size() < group.offset + group.length)
            continue;

        const std::uint8_t payloadByte0 = payload[group.offset + 0];
        const std::uint8_t payloadByte1 = (group.length >= 2) ? payload[group.offset + 1] : 0;
        const std::uint8_t payloadByte2 = (group.length >= 3) ? payload[group.offset + 2] : 0;
        const std::uint8_t payloadByte3 = (group.length >= 4) ? payload[group.offset + 3] : 0;

        const simd_u8 vectorPayload0(payloadByte0);
        const simd_u8 vectorPayload1(payloadByte1);
        const simd_u8 vectorPayload2(payloadByte2);
        const simd_u8 vectorPayload3(payloadByte3);
        if (!bitmapHas(group.firstByteBitmap, payloadByte0))
            continue;
        for (std::size_t base = 0; base < group.lanesPadded; base += width)
        {
            const simd_u8 vectorAnchor0(&group.anbchorByte0[base], simd_ns::element_aligned);
            mask_t mask = (vectorAnchor0 == vectorPayload0);

            if (group.length >= 2)
            {
                const simd_u8 vectorAnchor1(&group.anbchorByte1[base], simd_ns::element_aligned);
                mask &= (vectorAnchor1 == vectorPayload1);
            }
            if (group.length >= 3)
            {
                const simd_u8 vectorAnchor2(&group.anbchorByte2[base], simd_ns::element_aligned);
                mask &= (vectorAnchor2 == vectorPayload2);
            }
            if (group.length >= 4)
            {
                const simd_u8 vectorAnchor3(&group.anbchorByte3[base], simd_ns::element_aligned);
                mask &= (vectorAnchor3 == vectorPayload3);
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
