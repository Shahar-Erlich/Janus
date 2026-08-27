#pragma once
#include <string>
#include <vector>
#include <unordered_map>

#include "VectorFilteringEngine.hpp"

struct RuleLoaded
{
    std::vector<VFRule> rules;
    std::unordered_map<int, RuleHelper::RuleMeta> metaByRuleId;
    int maxScanShiftBytes = 64;
};

class RuleLoader
{
public:
    /**
     * @brief load the json file with the SIMD rules
     *
     * @param path the file path to open
     * @return RuleLoaded, struct with all rules
     */
    static RuleLoaded loadFromFile(std::string_view path);
};