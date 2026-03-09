#include "RegexEngine.hpp"
#include "Logger.hpp"

void RegexEngine::addRule(int id, const std::string &pattern, const std::string &desc)
{
    auto re = std::make_unique<re2::RE2>(pattern, re2::RE2::Latin1);

    if (!re->ok())
    {
        Logger::error("RE2 Compilation failed for [" + pattern + "]: " + re->error());
        return;
    }

    m_rules.push_back({id, std::move(re), desc});
}

std::optional<int> RegexEngine::scan(const std::string &text) const
{
    for (const auto &rule : m_rules)
    {
        if (re2::RE2::PartialMatch(text, *rule.re))
        {
            return rule.id;
        }
    }
    return std::nullopt;
}
bool RegexEngine::matchRule(int id, const std::string &text) const
{
    for (const auto &rule : m_rules)
    {
        if (rule.id == id)
        {
            return re2::RE2::PartialMatch(text, *rule.re);
        }
    }
    return false;
}
bool RegexEngine::hasRule(int id) const
{
    for (const auto &rule : m_rules)
    {
        if (rule.id == id)
        {
            return true;
        }
    }
    return false;
}