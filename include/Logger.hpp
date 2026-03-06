#pragma once

#include <iostream>

namespace Logger
{
    /**
     * @brief Log system message
     *
     * @param log message to log
     */
    void log(std::string log);
    /**
     * @brief Log system error
     *
     * @param error error to log
     */
    void error(std::string error);
};