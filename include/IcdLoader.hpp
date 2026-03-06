#pragma once
#include <string>
#include <vector>
#include <unordered_map>

#include "VectorFilteringEngine.hpp"

struct IcdRuleMeta
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
    Action action = Action::FLAG;
    Proto proto = Proto::ANY;
};

struct IcdLoaded
{
    std::vector<VFRule> rules;
    std::unordered_map<int, IcdRuleMeta> metaByRuleId;
    int maxScanShiftBytes = 64;
};

class IcdLoader
{
public:
    static IcdLoaded loadFromFile(const std::string &path);
};