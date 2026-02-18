#pragma once

#include <iostream>
#include <fstream>
#include "BlacklistHandler.hpp"
#include <pcapplusplus/Packet.h>
#include "VectorFilteringEngine.hpp"

enum Verdict
{
    ALLOW,
    DROP,
    INSPECT,
};

namespace PacketPolicy
{

    /**
     * @brief evaluate and return a passing status for the packet
     *
     * @param packet packet to evaluate
     * @return Verdict DROP,ALLOW or INSPECT
     */
    Verdict evaluatePacket(const pcpp::Packet &packet);

    /**
     * @brief check if packet has a legal payload
     *
     * @param packet packet to check
     * @return true has legal payload
     * @return false doesn't have a legal payload
     */
    bool hasPayload(pcpp::Packet packet);
    /**
     * @brief check if packet needs inspection
     *
     * @param packet packet to check
     * @return true packet needs inpsection
     * @return false packet doesn't need inspection
     */
    bool checkForInspection(pcpp::Packet packet);

    /**
     * @brief read the ip and port blacklists and initialize
     *
     */
    void readPolicyLists();

};