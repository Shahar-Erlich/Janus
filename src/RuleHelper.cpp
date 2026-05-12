#include "RuleHelper.hpp"
#include <algorithm>
#include <cctype>
#include <array>
#include <cstdint>
#include <string>
#include <stdexcept>
static std::uint32_t stringHash(const std::string &s)
{
    std::uint32_t h = 0;

    for (unsigned char c : s)
        h = h * 31 + c;

    return h;
}
static std::string protoToString(RuleHelper::RuleMeta::Proto proto)
{
    switch (proto)
    {
    case RuleHelper::RuleMeta::Proto::TCP:
        return "TCP";
    case RuleHelper::RuleMeta::Proto::UDP:
        return "UDP";
    case RuleHelper::RuleMeta::Proto::ANY:
    default:
        return "ANY";
    }
}
static std::string bytesToHex(const std::array<std::uint8_t, 4> &bytes, int length)
{
    static constexpr char hexChars[] = "0123456789ABCDEF";

    std::string out;
    out.reserve(length * 2);

    for (int i = 0; i < length; ++i)
    {
        std::uint8_t b = bytes[i];
        out.push_back(hexChars[b >> 4]);
        out.push_back(hexChars[b & 0x0F]);
    }

    return out;
}
std::vector<std::uint8_t> RuleHelper::hexToBytes(const std::string &hex)
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

    for (std::size_t i = 0; i < hex.size(); i += 2)
    {
        int hi = nyb(hex[i]);
        int lo = nyb(hex[i + 1]);

        if (hi < 0 || lo < 0)
            throw std::runtime_error("invalid hex");

        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }

    return out;
}
int RuleHelper::idToRuleID(
    std::string id,
    std::string protoStr,
    int length,
    int offset,
    std::string hex)
{
    const std::string key =
        id + "|" + protoStr + "|" + std::to_string(offset) + "|" +
        std::to_string(length) + "|" + hex;

    return static_cast<int>(stringHash(key) & 0x7fffffff);
}
int RuleHelper::idToRuleID(RuleMeta &rule)
{
    return idToRuleID(
        rule.id,
        protoToString(rule.proto),
        rule.length,
        rule.exact_offset,
        bytesToHex(rule.bytes, rule.length));
}
RuleHelper::RuleMeta::Action RuleHelper::parseAction(std::string a)
{
    std::transform(a.begin(), a.end(), a.begin(), ::toupper);
    if (a == "ALLOW")
        return RuleHelper::RuleMeta::Action::ALLOW;
    if (a == "FLAG")
        return RuleHelper::RuleMeta::Action::FLAG;
    if (a == "BLOCK")
        return RuleHelper::RuleMeta::Action::BLOCK;
    return RuleHelper::RuleMeta::Action::FLAG;
}
RuleHelper::RuleMeta::Proto RuleHelper::parseProto(std::string p)
{
    std::transform(p.begin(), p.end(), p.begin(), ::toupper);
    if (p == "TCP")
        return RuleHelper::RuleMeta::Proto::TCP;
    if (p == "UDP")
        return RuleHelper::RuleMeta::Proto::UDP;
    return RuleHelper::RuleMeta::Proto::ANY;
}