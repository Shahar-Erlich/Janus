#pragma once
#include <iostream>
#include <vector>
#include <cstdint>
#include <string_view>

constexpr int MIN_RULE_ID = 1;

class RuleHelper
{

public:
    typedef struct
    {
        enum class Action
        {
            ALLOW,
            FLAG,
            BLOCK
        };
        enum class Proto
        {
            ANY,
            TCP,
            UDP
        };

        std::string id;
        std::string desc;
        std::string regex_pattern;
        std::vector<std::string> aho_patterns;
        Action action = Action::FLAG;
        Proto proto = Proto::ANY;
        std::string offset_mode;
        int exact_offset;
        int length;
        int ruleId;
        std::array<std::uint8_t, 4> bytes;
    } RuleMeta;
    /**
     * @brief generate an internal rule ID from rule identity fields
     *
     * @param id rule string ID
     * @param protoStr rule protocol as string
     * @param length rule anchor length
     * @param offset rule anchor offset
     * @param hex rule anchor bytes as hex string
     * @return int generated rule ID
     */
    static int idToRuleID(std::string_view id,
                          std::string_view protoStr,
                          int length,
                          int offset,
                          std::string_view hex);

    /**
     * @brief generate an internal rule ID from rule metadata
     *
     * @param rule rule metadata
     * @return int generated rule ID
     */
    static int idToRuleID(RuleMeta &rule);

    /**
     * @brief convert a hex string into bytes
     *
     * @param hex hex string to convert
     * @return std::vector<std::uint8_t> converted bytes
     */
    static std::vector<std::uint8_t> hexToBytes(const std::string &hex);

    /**
     * @brief parse rule action from string
     *
     * @param action action string
     * @return RuleMeta::Action parsed action
     */
    static RuleMeta::Action parseAction(std::string action);

    /**
     * @brief parse rule protocol from string
     *
     * @param proto protocol string
     * @return RuleMeta::Proto parsed protocol
     */
    static RuleMeta::Proto parseProto(std::string proto);
};