#pragma once
#include <re2/re2.h>
#include <string>
#include <vector>
#include <memory>
#include <optional>

struct RegexRule
{
    int id;
    std::unique_ptr<re2::RE2> re;
    std::string description;
};

class RegexEngine
{
public:
    RegexEngine() = default;
    bool matchRule(int id, const std::string &text) const;
    void addRule(int id, const std::string &pattern, const std::string &desc);
    std::optional<int> scan(const std::string &text) const;
    bool hasRule(int id) const;

private:
    std::vector<RegexRule> m_rules;
};