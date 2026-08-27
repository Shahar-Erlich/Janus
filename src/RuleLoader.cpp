#include "RuleLoader.hpp"
#include "Logger.hpp"
#include "RuleHelper.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <format>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "third_party/json.hpp"

using json = nlohmann::json;

namespace
{
    json readJsonFile(std::string_view path)
    {
        std::ifstream f{std::string(path)};
        if (!f.is_open())
            throw std::runtime_error("Failed to open rules file");

        json j;
        f >> j;
        return j;
    }

    std::vector<std::string> parseAhoPatterns(const json &ruleJson)
    {
        std::vector<std::string> patterns;

        if (!ruleJson.contains("aho_patterns") || !ruleJson["aho_patterns"].is_array())
            return patterns;

        for (const auto &patternJson : ruleJson["aho_patterns"])
        {
            if (!patternJson.is_string())
                continue;

            std::string pattern = patternJson.get<std::string>();
            if (!pattern.empty())
            {
                patterns.push_back(std::move(pattern));
            }
        }

        return patterns;
    }

    void validateOffsetMode(const std::string &id, const std::string &offsetMode)
    {
        if (offsetMode != "PAYLOAD" && offsetMode != "EXACT")
        {
            throw std::runtime_error(
                std::format("offset_mode currently only supports PAYLOAD or EXACT (rule: {})", id));
        }
    }

    void validateLength(const std::string &id, int length)
    {
        if (length < 1 || length > 4)
        {
            throw std::runtime_error(
                std::format("VF rule length must be 1..4 (rule: {})", id));
        }
    }

    std::array<std::uint8_t, 4> parseRuleBytes(
        const std::string &id,
        const std::string &hex,
        int length)
    {
        auto bytes = RuleHelper::hexToBytes(hex);

        if (static_cast<int>(bytes.size()) != length)
        {
            throw std::runtime_error(
                std::format("value_hex length mismatch (rule: {})", id));
        }

        std::array<std::uint8_t, 4> fixedBytes{0, 0, 0, 0};

        for (int i = 0; i < length; ++i)
        {
            fixedBytes[i] = bytes[i];
        }

        return fixedBytes;
    }

    VFRule buildVfRule(
        int ruleId,
        int offset,
        int length,
        const std::array<std::uint8_t, 4> &bytes,
        const std::string &id,
        const std::string &desc)
    {
        VFRule rule{};
        rule.ruleId = ruleId;
        rule.offset = static_cast<std::size_t>(offset);
        rule.length = static_cast<std::uint8_t>(length);
        rule.bytes = bytes;
        rule.description = desc.empty() ? id : desc;

        return rule;
    }

    RuleHelper::RuleMeta buildRuleMeta(
        int ruleId,
        int offset,
        int length,
        const std::array<std::uint8_t, 4> &bytes,
        const std::string &id,
        const std::string &desc,
        const std::string &regexPattern,
        std::vector<std::string> ahoPatterns,
        const std::string &protoStr,
        const std::string &actionStr,
        const std::string &offsetMode)
    {
        RuleHelper::RuleMeta meta{};
        meta.id = id;
        meta.desc = desc;
        meta.regex_pattern = regexPattern;
        meta.aho_patterns = std::move(ahoPatterns);
        meta.action = RuleHelper::parseAction(actionStr);
        meta.proto = RuleHelper::parseProto(protoStr);
        meta.offset_mode = offsetMode;
        meta.exact_offset = offset;
        meta.length = length;
        meta.ruleId = ruleId;
        meta.bytes = bytes;

        return meta;
    }

    struct ParsedRule
    {
        VFRule vfRule;
        RuleHelper::RuleMeta meta;
    };

    ParsedRule parseRule(const json &ruleJson)
    {
        const std::string id = ruleJson.at("id").get<std::string>();
        const std::string desc = ruleJson.value("desc", "");
        const std::string regexPattern = ruleJson.value("regex", "");
        auto ahoPatterns = parseAhoPatterns(ruleJson);

        const std::string protoStr = ruleJson.value("proto", "ANY");
        const std::string actionStr = ruleJson.value("action", "FLAG");

        const std::string offsetMode = ruleJson.value("offset_mode", "PAYLOAD");
        validateOffsetMode(id, offsetMode);

        const int offset = ruleJson.at("offset").get<int>();
        const int length = ruleJson.at("length").get<int>();
        validateLength(id, length);

        const std::string hex = ruleJson.at("value_hex").get<std::string>();
        const auto bytes = parseRuleBytes(id, hex, length);

        const int ruleId = RuleHelper::idToRuleID(id, protoStr, length, offset, hex);

        ParsedRule parsed{};
        parsed.vfRule = buildVfRule(ruleId, offset, length, bytes, id, desc);
        parsed.meta = buildRuleMeta(
            ruleId,
            offset,
            length,
            bytes,
            id,
            desc,
            regexPattern,
            std::move(ahoPatterns),
            protoStr,
            actionStr,
            offsetMode);

        return parsed;
    }
}

RuleLoaded RuleLoader::loadFromFile(std::string_view path)
{
    const json j = readJsonFile(path);

    RuleLoaded out;
    out.maxScanShiftBytes = j.value("defaults", json::object()).value("max_scan_shift_bytes", 64);

    const auto rulesJ = j.at("vf_rules");
    out.rules.reserve(rulesJ.size());

    for (const auto &ruleJson : rulesJ)
    {
        ParsedRule parsed = parseRule(ruleJson);

        const int ruleId = parsed.vfRule.ruleId;

        out.rules.push_back(std::move(parsed.vfRule));
        out.metaByRuleId[ruleId] = std::move(parsed.meta);
    }

    return out;
}