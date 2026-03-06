#include "Logger.hpp"
#include "TerminalColors.hpp"
#include <print>

void Logger::log(std::string log)
{
    std::println(stdout, "[System] {}", log);
    std::fflush(stdout);
}

void Logger::error(std::string error)
{
    std::println(
        stderr,
        "{}[Error] {}{}",
        TerminalColors::Red,
        error,
        TerminalColors::Color_Off);
}