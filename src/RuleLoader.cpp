#include "RuleLoader.hpp"
#include "Logger.hpp"
#include <fstream>
#include <stdexcept>
#include <cstdint>
#include <algorithm>

#include "third_party/json.hpp"

#include "RuleHelper.hpp"

using json = nlohmann::json;

RuleLoaded RuleLoader::loadFromFile(std::string_view path)
{
    std::ifstream f(path.data());
    if (!f.is_open())
        throw std::runtime_error("Failed to open rules file");

    json j;
    f >> j;

    RuleLoaded out;
    out.maxScanShiftBytes = j.value("defaults", json::object()).value("max_scan_shift_bytes", 64);

    const auto rulesJ = j.at("vf_rules");
    out.rules.reserve(rulesJ.size());

    for (const auto &r : rulesJ)
    {
        const std::string id = r.at("id").get<std::string>();
        const std::string desc = r.value("desc", "");
        const std::string regex_pattern = r.value("regex", "");
        const std::string protoStr = r.value("proto", "ANY");
        const std::string actionStr = r.value("action", "FLAG");

        const std::string offsetMode = r.value("offset_mode", "PAYLOAD");
        if (offsetMode != "PAYLOAD" && offsetMode != "EXACT")
            throw std::runtime_error(std::format("offset_mode currently only supports PAYLOAD or EXACT (rule: {})", id));

        const int offset = r.at("offset").get<int>();
        const int length = r.at("length").get<int>();
        if (length < 1 || length > 4)
            throw std::runtime_error(std::format("VF rule length must be 1..4 (rule: {})", id));

        const std::string hex = r.at("value_hex").get<std::string>();
        auto bytes = RuleHelper::hexToBytes(hex);
        if ((int)bytes.size() != length)
            throw std::runtime_error(std::format("value_hex length mismatch (rule: {})", id));

        const int ruleId = RuleHelper::idToRuleID(id, protoStr, length, offset, hex);

        VFRule rule{};
        rule.ruleId = ruleId;
        rule.offset = (std::size_t)offset;
        rule.length = (std::uint8_t)length;
        rule.bytes = {0, 0, 0, 0};
        for (int i = 0; i < length; i++)
            rule.bytes[i] = bytes[i];
        rule.description = desc.empty() ? id : desc;

        out.rules.push_back(rule);

        RuleHelper::RuleMeta meta{};
        meta.id = id;
        meta.desc = desc;
        meta.regex_pattern = regex_pattern;
        meta.action = RuleHelper::parseAction(actionStr);
        meta.proto = RuleHelper::parseProto(protoStr);
        meta.offset_mode = offsetMode;
        meta.exact_offset = offset;
        meta.length = length;
        meta.ruleId = ruleId;
        meta.bytes = rule.bytes;

        out.metaByRuleId[ruleId] = std::move(meta);
    }

    return out;
}