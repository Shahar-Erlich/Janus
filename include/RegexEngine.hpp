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
    /**
     * @brief Construct a new Regex Engine object
     *
     */
    RegexEngine() = default;
    /**
     * @brief check a given regex rule is found in text
     *
     * @param id id of the rule
     * @param text text to check rule on
     * @return true if regex found
     * @return false if regex not found
     */
    bool matchRule(int id, const std::string &text) const;
    /**
     * @brief add regex rule to regex engine
     *
     * @param id id of rule to add
     * @param pattern the regex pattern
     * @param desc description of the rule
     */
    void addRule(int id, const std::string &pattern, const std::string &desc);
    /**
     * @brief scan the text against all stored regex rules.

     *
     * @param text text to scan
     * @return std::optional<int> matching rule ID, or std::nullopt if no rule matched.
     */
    std::optional<int> scan(const std::string &text) const;
    /**
     * @brief check if rule exists in regex engine
     *
     * @param id id of rule to check
     * @return true if found
     * @return false if not found
     */
    bool hasRule(int id) const;

private:
    std::vector<RegexRule> m_rules;
};