#include "IcdLoader.hpp"
#include "Logger.hpp"
#include <fstream>
#include <stdexcept>
#include <cstdint>
#include <algorithm>

#include "third_party/json.hpp"
using json = nlohmann::json;

/* ---------- helpers ---------- */

static std::vector<std::uint8_t> hexToBytes(const std::string &hex)
{
    if (hex.size() % 2 != 0)
        throw std::runtime_error("hex string must have even length");

    auto nyb = [](char c) -> int
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F')
            return 10 + (c - 'A');
        return -1;
    };

    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        int hi = nyb(hex[i]), lo = nyb(hex[i + 1]);
        if (hi < 0 || lo < 0)
            throw std::runtime_error("invalid hex");
        out.push_back(std::uint8_t((hi << 4) | lo));
    }
    return out;
}

// FNV-1a 32-bit (stable auto-id)
static std::uint32_t fnv1a32(const std::string &s)
{
    std::uint32_t h = 2166136261u;
    for (unsigned char c : s)
    {
        h ^= c;
        h *= 16777619u;
    }
    return h;
}

static IcdRuleMeta::Action parseAction(std::string a)
{
    std::transform(a.begin(), a.end(), a.begin(), ::toupper);
    if (a == "ALLOW")
        return IcdRuleMeta::Action::ALLOW;
    if (a == "FLAG")
        return IcdRuleMeta::Action::FLAG;
    if (a == "BLOCK")
        return IcdRuleMeta::Action::BLOCK;
    return IcdRuleMeta::Action::FLAG;
}

static IcdRuleMeta::Proto parseProto(std::string p)
{
    std::transform(p.begin(), p.end(), p.begin(), ::toupper);
    if (p == "TCP")
        return IcdRuleMeta::Proto::TCP;
    if (p == "UDP")
        return IcdRuleMeta::Proto::UDP;
    return IcdRuleMeta::Proto::ANY;
}

IcdLoaded IcdLoader::loadFromFile(const std::string &path)
{
    std::ifstream f(path);
    if (!f.is_open())
        throw std::runtime_error("Failed to open ICD file: " + path);

    json j;
    f >> j;

    IcdLoaded out;
    out.maxScanShiftBytes = j.value("defaults", json::object()).value("max_scan_shift_bytes", 64);

    const auto rulesJ = j.at("vf_rules");
    out.rules.reserve(rulesJ.size());

    for (const auto &r : rulesJ)
    {
        const std::string id = r.at("id").get<std::string>();
        const std::string desc = r.value("desc", "");
        const std::string protoStr = r.value("proto", "ANY");
        const std::string actionStr = r.value("action", "FLAG");

        const std::string offsetMode = r.value("offset_mode", "PAYLOAD");
        if (offsetMode != "PAYLOAD")
            throw std::runtime_error("offset_mode currently only supports PAYLOAD (rule: " + id + ")");

        const int offset = r.at("offset").get<int>();
        const int length = r.at("length").get<int>();
        if (length < 1 || length > 4)
            throw std::runtime_error("VF rule length must be 1..4 (rule: " + id + ")");

        const std::string hex = r.at("value_hex").get<std::string>();
        auto bytes = hexToBytes(hex);
        if ((int)bytes.size() != length)
            throw std::runtime_error("value_hex length mismatch (rule: " + id + ")");

        // Stable auto-id derived from rule content
        const std::string key = id + "|" + protoStr + "|" + std::to_string(offset) + "|" +
                                std::to_string(length) + "|" + hex;
        const int ruleId = (int)(fnv1a32(key) & 0x7fffffff); // positive int

        VFRule rule{};
        rule.ruleId = ruleId;
        rule.offset = (std::size_t)offset;
        rule.length = (std::uint8_t)length;
        rule.bytes = {0, 0, 0, 0};
        for (int i = 0; i < length; i++)
            rule.bytes[i] = bytes[i];
        rule.description = id;

        out.rules.push_back(rule);

        IcdRuleMeta meta{};
        meta.id = id;
        meta.desc = desc;
        meta.action = parseAction(actionStr);
        meta.proto = parseProto(protoStr);

        out.metaByRuleId[ruleId] = std::move(meta);
    }

    Logger::log("Loaded ICD VF rules: " + std::to_string(out.rules.size()));
    return out;
}