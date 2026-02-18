#pragma once

#include <iostream>
#include <string>

namespace TerminalColors
{
    constexpr std::string_view Color_Off = "\033[0m";

    constexpr std::string_view Black = "\033[0;30m";
    constexpr std::string_view Red = "\033[0;31m";
    constexpr std::string_view Green = "\033[0;32m";
    constexpr std::string_view Yellow = "\033[0;33m";
    constexpr std::string_view Blue = "\033[0;34m";
    constexpr std::string_view Purple = "\033[0;35m";
    constexpr std::string_view Cyan = "\033[0;36m";
    constexpr std::string_view White = "\033[0;37m";
}