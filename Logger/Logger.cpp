#include "Logger.hpp"

void Logger::log(std::string log)
{
    std::clog << "[System] " << log.c_str() << std::endl;
}
void Logger::error(std::string error)
{
    std::cerr << "[Error] " << error.c_str() << std::endl;
}
