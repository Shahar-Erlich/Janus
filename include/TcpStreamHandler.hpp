#pragma once

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpReassembly.h>
#include "TcpSessionTracker.hpp"

#include <iostream>
#include <unordered_map>
#include <vector>
#include <string>
#include <mutex>

struct ConnectionState
{
    std::vector<uint8_t> clientBuffer;
    std::vector<uint8_t> serverBuffer;
    int sessionId;
    bool flagged = false;
};
class VectorFilteringEngine;

class TcpStreamHandler
{
public:
    TcpStreamHandler();
    int processPacket(pcpp::Packet &packet);
    void shutdown();
    TcpSessionTracker m_sessionTracker;
    static TcpStreamHandler &instance();

private:
    static constexpr std::size_t MAX_ANCHOR_LEN = 4;     // your SIMD anchor limit (1..4)
    static constexpr std::size_t MAX_STREAM_KEEP = 4096; // keep only last 4KB per direction
    static void onConnectionStart(const pcpp::ConnectionData &connectionData, void *userCookie);
    bool hasHits(std::vector<int> hits, int side, pcpp::TcpStreamData tcpData);
    static void onDataReady(int8_t side, const pcpp::TcpStreamData &tcpData, void *userCookie);
    static void onConnectionEnd(const pcpp::ConnectionData &connData, pcpp::TcpReassembly::ConnectionEndReason reason, void *userCookie);
    pcpp::TcpReassembly reassembly;
    std::unordered_map<uint32_t, ConnectionState> connections;
    std::mutex mutex;
    int foundHits;
};
