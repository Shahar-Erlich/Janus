#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "SimdCompatability.hpp"

struct VFRule
{
    int ruleId;                        // unique ID for logging/verdict
    std::size_t offset;                // offset into the payload buffer
    std::uint8_t length;               // anchor length
    std::array<std::uint8_t, 4> bytes; // anchor bytes
    std::string description;

    static VFRule fromASCII(int id, std::size_t off, const std::string &s);
};

class VectorFilteringEngine
{
public:
    void build(const std::vector<VFRule> &rules);

    std::vector<int> scanPayload(std::span<const std::uint8_t> payload) const;
    const std::string &describe(int id) const;
    bool anyHit(std::span<const std::uint8_t> payload) const;

private:
    std::unordered_map<int, std::string> m_ruleDescriptions;

    // using simd_u8 = simd_ns::native_simd<std::uint8_t>;
    using mask_t = typename simd_u8::mask_type;

    struct GroupKey
    {
        std::size_t offset;
        std::uint8_t length;

        bool operator==(const GroupKey &other) const
        {
            return offset == other.offset && length == other.length;
        }
    };

    struct GroupKeyHash
    {
        std::size_t operator()(const GroupKey &key) const
        {
            return std::hash<std::size_t>{}(key.offset) ^ (std::hash<int>{}(key.length) << 1);
        }
    };

    struct Group
    {
        std::size_t offset = 0;
        std::uint8_t length = 0;

        std::vector<std::uint8_t> anbchorByte0, anbchorByte1, anbchorByte2, anbchorByte3;
        std::vector<int> ruleIDs;

        std::size_t lanesPadded = 0;
        std::array<uint64_t, 4> firstByteBitmap{};
    };

    std::vector<Group> m_groups;

    static void padAndPack(Group &group, const std::vector<VFRule> &rulesInGroup);
};
