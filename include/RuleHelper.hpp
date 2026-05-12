#pragma once
#include <iostream>
#include <vector>
#include <cstdint>
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
        Action action = Action::FLAG;
        Proto proto = Proto::ANY;
        std::string offset_mode;
        int exact_offset;
        int length;
        int ruleId;
        std::array<std::uint8_t, 4> bytes;
    } RuleMeta;
    static int idToRuleID(std::string id, std::string protoStr, int length, int offset, std::string hex);
    static int idToRuleID(RuleMeta &rule);
    static std::vector<std::uint8_t> hexToBytes(const std::string &hex);

    static RuleMeta::Action parseAction(std::string action);
    static RuleMeta::Proto parseProto(std::string proto);
};