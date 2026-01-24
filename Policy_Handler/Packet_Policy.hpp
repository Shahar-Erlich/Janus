#include "../Parsed_Packet/Parsed_Packet.hpp"
#include <iostream>
#include <fstream>
#include <unordered_set>
#include "../Blacklist_Handler/Blacklist_Handler.hpp"

enum Verdict
{
    ALLOW,
    DROP,
    INSPECT,
};

namespace packetPolicy
{

    /**
     * @brief evaluate and return a passing status for the packet
     *
     * @param packet packet to evaluate
     * @return Verdict DROP,ALLOW or INSPECT
     */
    Verdict evaluatePacket(ParsedPacket packet);

    /**
     * @brief check if packet has a legal payload
     *
     * @param packet packet to check
     * @return true has legal payload
     * @return false doesn't have a legal payload
     */
    bool hasPayload(ParsedPacket packet);
    /**
     * @brief check if packet needs inspection
     *
     * @param packet packet to check
     * @return true packet needs inpsection
     * @return false packet doesn't need inspection
     */
    bool checkForInspection(ParsedPacket packet);

    void readPolicyLists();
};