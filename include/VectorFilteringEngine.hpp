#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>
#include <bitset>
#include "RuleHelper.hpp"

#include "SimdCompatability.hpp"

#define BITS_IN_MAP_BUCKET 64

constexpr int maxRuleLength = 4;

struct VFRule
{
    int ruleId;
    std::size_t offset;
    std::uint8_t length;
    std::array<std::uint8_t, maxRuleLength> bytes;
    std::string description;

    /**
     * @brief translate ASCII to vector filter rule
     *
     * @param id rule id to add
     * @param off offset into the data where it exists
     * @param s the ASCII string
     * @return VFRule vector filter rule created from ASCII
     */
    static VFRule fromASCII(int id, std::size_t off, const std::string &s);
};

class VectorFilteringEngine
{
public:
    /**
     * @brief build the vector filtering engine and all its rules
     *
     * @param rules the rules to build into the system
     */
    void build(const std::vector<VFRule> &rules);
    /**
     * @brief scan a payload for the vector filter rules in the engine
     *
     * @param payload payload to check and scan
     * @return std::vector<int> rules that were found
     */
    std::vector<int> scanPayload(std::span<const std::uint8_t> payload) const;
    /**
     * @brief get rule's description from id
     *
     * @param id id to get description of
     * @return const std::string& the description of the rule
     */
    const std::string &describe(int id) const;
    /**
     * @brief add a new rule to the vector filtering engine
     *
     * @param newRule rule to add
     * @return true if the rule was added successfully
     * @return false if the rule could not be added
     */
    bool addRuleToVectorEngine(const VFRule &newRule);
    /**
     * @brief set the rule metadata map used by the vector engine
     *
     * @param meta pointer to the rule metadata map
     */
    void setRuleMeta(std::unordered_map<int, RuleHelper::RuleMeta> *meta) { metaByRuleId = meta; }

private:
    std::unordered_map<int, std::string> m_ruleDescriptions;

    using mask_t = typename simd_u8::mask_type;

    /**
     * @brief key used to group rules by offset and length
     *
     */
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

    /**
     * @brief group of vector filtering rules with the same offset and length
     *
     */
    struct Group
    {
        std::size_t offset = 0;
        std::uint8_t length = 0;
        int groupRuleCount = 0;

        std::vector<std::vector<std::uint8_t>> anchorBytes; // vector of each n-th byte vector, i.e all 0 bytes, 1 bytes etc
        std::vector<int> ruleIDs;

        std::size_t lanesPadded = 0;
        std::bitset<256> firstByteBitmap{}; // quick check bytemap
    };

    std::unordered_map<GroupKey, Group, GroupKeyHash> m_groups;

    /**
     * @brief insert rules into a group and make it a more SIMD friendly format
     *
     * @param group group to insert into
     * @param rulesInGroup rules to insert
     */
    static void padAndPack(Group &group, const std::vector<VFRule> &rulesInGroup);
    /**
     * @brief add a rule from metadata into the vector filtering engine
     *
     * @param newRule rule metadata to add
     */
    void addRule(RuleHelper::RuleMeta &newRule);
    std::unordered_map<int, RuleHelper::RuleMeta> *metaByRuleId = nullptr;
};
