#include "TcpStreamHandler.hpp"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpReassembly.h>
#include "Logger.hpp"
#include "TerminalColors.hpp"
#include "BlacklistHandler.hpp"
#include <algorithm>
#include "VectorFilteringEngine.hpp"

#include <iostream>
#include <unordered_map>
#include <vector>
#include <string>
#include <mutex>
#include <print>
#include <atomic>

static std::atomic<int> g_sessionCounter = 1;

TcpStreamHandler &TcpStreamHandler::instance()
{
    static TcpStreamHandler handler;
    return handler;
}

TcpStreamHandler::TcpStreamHandler()
    : reassembly(
          onDataReady,
          this,
          onConnectionStart,
          onConnectionEnd),
      m_sessionTracker()
{
}

int TcpStreamHandler::processPacket(pcpp::Packet &packet)
{
    if (!packet.isPacketOfType(pcpp::TCP))
        return 0;
    std::println("{}Reassembling package{}", TerminalColors::Purple, TerminalColors::Color_Off);
    reassembly.reassemblePacket(packet);
    return foundHits > 0;
}

void TcpStreamHandler::shutdown()
{
    reassembly.closeAllConnections();
}

void TcpStreamHandler::onConnectionStart(
    const pcpp::ConnectionData &connectionData,
    void *userCookie)
{
    auto *self = static_cast<TcpStreamHandler *>(userCookie);

    std::lock_guard<std::mutex> lock(self->mutex);

    int id = g_sessionCounter++;
    self->connections[connectionData.flowKey] = ConnectionState{};
    self->connections[connectionData.flowKey].sessionId = id;

    std::println(
        "{}\n=== TCP Session #{} ==={}\n"
        "{}{}:{} → {}:{}{}\n",
        TerminalColors::Cyan,
        id,
        TerminalColors::Color_Off,

        TerminalColors::Yellow,
        connectionData.srcIP.toString(),
        connectionData.srcPort,
        connectionData.dstIP.toString(),
        connectionData.dstPort,
        TerminalColors::Color_Off);
}

void TcpStreamHandler::onDataReady(
    int8_t side,
    const pcpp::TcpStreamData &tcpData,
    void *userCookie)
{
    auto *self = static_cast<TcpStreamHandler *>(userCookie);

    std::lock_guard<std::mutex> lock(self->mutex);

    auto it = self->connections.find(tcpData.getConnectionData().flowKey);
    if (it == self->connections.end())
        return;

    auto &state = it->second;

    const uint8_t *data = tcpData.getData();
    const std::size_t len = tcpData.getDataLength();

    if (len == 0)
        return;

    auto &buffer = (side == 0) ? state.clientBuffer : state.serverBuffer;

    const std::size_t overlap =
        (buffer.size() >= (MAX_ANCHOR_LEN - 1)) ? (MAX_ANCHOR_LEN - 1) : buffer.size();

    std::vector<std::uint8_t> scanWindow;
    scanWindow.reserve(overlap + len);

    if (overlap > 0)
    {
        scanWindow.insert(scanWindow.end(),
                          buffer.end() - overlap,
                          buffer.end());
    }
    scanWindow.insert(scanWindow.end(), data, data + len);

    if (!state.flagged)
    {
        for (size_t i = 0; i < overlap; ++i)
        {
            auto hits = VectorFilteringEngine::instance().scanPayload(
                std::span(scanWindow.data() + i,
                          scanWindow.size() - i));
            if (self->hasHits(hits, side, tcpData))
            {
            }
        }

        const uint8_t *data = tcpData.getData();
        size_t len = tcpData.getDataLength();

        std::span<const uint8_t> payload(data, len);
        auto hits = VectorFilteringEngine::instance().scanPayload(payload);
        if (self->hasHits(hits, side, tcpData))
        {
        }
    }

    buffer.insert(buffer.end(), data, data + len);

    if (buffer.size() > MAX_STREAM_KEEP)
    {
        const std::size_t drop = buffer.size() - MAX_STREAM_KEEP;
        buffer.erase(buffer.begin(), buffer.begin() + drop);
    }

    const int id = state.sessionId;
    std::println(
        "{}[#{}] {}{} | {} bytes{}",
        TerminalColors::Green,
        id,
        (side == 0 ? "C → S" : "S → C"),
        TerminalColors::Color_Off,
        len,
        TerminalColors::Color_Off);
}

bool TcpStreamHandler::hasHits(std::vector<int> hits, int side, pcpp::TcpStreamData tcpData)
{
    if (!hits.empty())
    {
        const auto &conn = tcpData.getConnectionData();
        const std::string suspectIp =
            (side == 0) ? conn.srcIP.toString() : conn.dstIP.toString();

        Logger::error("VectorFilter HIT on TCP stream! Blacklisting: " + suspectIp);

        for (int id : hits)
        {
            Logger::log(
                "Rule hit: " +
                std::to_string(id) +
                " → \"" +
                VectorFilteringEngine::instance().describe(id) +
                "\"");
        }
        return true;
    }
    return false;
}
void TcpStreamHandler::onConnectionEnd(
    const pcpp::ConnectionData &connData,
    pcpp::TcpReassembly::ConnectionEndReason reason,
    void *userCookie)
{
    auto *self = static_cast<TcpStreamHandler *>(userCookie);

    std::lock_guard<std::mutex> lock(self->mutex);

    auto it = self->connections.find(connData.flowKey);

    if (it == self->connections.end())
        return;

    const auto &state = it->second;

    int id = state.sessionId;

    std::println(
        "\n{}=== Session #{} Closed ==={}",
        TerminalColors::Red,
        id,
        TerminalColors::Color_Off);

    std::println(
        "Client stream: {} bytes\nServer stream: {} bytes",
        state.clientBuffer.size(),
        state.serverBuffer.size());

    if (!state.clientBuffer.empty())
    {
        std::println(
            "\n{}--- Client → Server ---{}",
            TerminalColors::Blue,
            TerminalColors::Color_Off);

        std::cout.write(
            reinterpret_cast<const char *>(state.clientBuffer.data()),
            state.clientBuffer.size());
        std::cout << "\n";
    }

    if (!state.serverBuffer.empty())
    {
        std::println(
            "\n{}--- Server → Client ---{}",
            TerminalColors::Cyan,
            TerminalColors::Color_Off);

        std::cout.write(
            reinterpret_cast<const char *>(state.serverBuffer.data()),
            state.serverBuffer.size());
        std::cout << "\n";
    }

    std::println(
        "{}===========================\n{}",
        TerminalColors::Cyan,
        TerminalColors::Color_Off);

    self->connections.erase(it);
}
