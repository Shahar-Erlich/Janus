#include "TcpStreamHandler.hpp"
#include "Logger.hpp"
#include <algorithm>
#include <print>
#include <atomic>

static std::atomic<int> g_sessionCounter = 1;

TcpStreamHandler::TcpStreamHandler(AhoCorasick &ac, VectorFilteringEngine &ve, RegexEngine &re)
    : reassembly(onDataReady, this, onConnectionStart, onConnectionEnd),
      ahoCorasick(ac),
      vectorEngine(ve),
      regexEngine(re)
{
}

TcpPacketScanResult TcpStreamHandler::processPacket(pcpp::Packet &packet)
{
    TcpPacketScanResult res{};

    if (!packet.isPacketOfType(pcpp::TCP))
        return res;

    currentScan = &res;
    reassembly.reassemblePacket(packet);
    currentScan = nullptr;

    return res;
}

void TcpStreamHandler::shutdown()
{
    reassembly.closeAllConnections();
}

void TcpStreamHandler::onConnectionStart(const pcpp::ConnectionData &connectionData, void *userCookie)
{
    auto *self = static_cast<TcpStreamHandler *>(userCookie);
    std::lock_guard<std::mutex> lock(self->mutex);

    ConnectionState st{};
    st.sessionId = g_sessionCounter++;
    self->connections[connectionData.flowKey] = std::move(st);
}

void TcpStreamHandler::onDataReady(int8_t side, const pcpp::TcpStreamData &tcpData, void *userCookie)
{
    auto *self = static_cast<TcpStreamHandler *>(userCookie);
    std::lock_guard<std::mutex> lock(self->mutex);

    auto it = self->connections.find(tcpData.getConnectionData().flowKey);
    if (it == self->connections.end())
        return;

    auto &state = it->second;

    const uint8_t *data = tcpData.getData();
    const std::size_t len = tcpData.getDataLength();
    if (!data || len == 0)
        return;

    auto &buffer = (side == 0) ? state.clientBuffer : state.serverBuffer;

    const std::size_t overlap =
        (buffer.size() >= (MAX_ANCHOR_LEN - 1)) ? (MAX_ANCHOR_LEN - 1) : buffer.size();

    std::vector<std::uint8_t> scanWindow;
    scanWindow.reserve(overlap + len);
    if (overlap > 0)
    {
        scanWindow.insert(scanWindow.end(), buffer.end() - overlap, buffer.end());
    }
    scanWindow.insert(scanWindow.end(), data, data + len);

    const std::size_t ahoTail = std::min(buffer.size(), AHO_TAIL);
    std::vector<std::uint8_t> ahoWindow;
    ahoWindow.reserve(ahoTail + len);
    if (ahoTail > 0)
    {
        ahoWindow.insert(ahoWindow.end(), buffer.end() - ahoTail, buffer.end());
    }
    ahoWindow.insert(ahoWindow.end(), data, data + len);

    if (!state.flowFlagged)
    {
        bool anyVf = false;
        std::vector<int> bestHits;
        const size_t maxShift = std::min<size_t>(64, scanWindow.size());
        for (size_t i = 0; i <= maxShift; ++i)
        {
            std::span<const uint8_t> win(scanWindow.data() + i, scanWindow.size() - i);
            auto hits = self->vectorEngine.scanPayload(win);

            std::vector<int> validHits;
            for (int rid : hits)
            {
                if (self->m_metaMap)
                {
                    auto it = self->m_metaMap->find(rid);
                    if (it != self->m_metaMap->end())
                    {
                        if (it->second.offset_mode == "EXACT" && i != 0)
                            continue;
                    }
                }
                validHits.push_back(rid);
            }

            if (!validHits.empty())
            {
                anyVf = true;
                bestHits = std::move(validHits);
                break;
            }
        }

        if (!anyVf)
        {
            std::span<const uint8_t> payload(data, len);
            auto hits = self->vectorEngine.scanPayload(payload);

            std::vector<int> validHits;
            for (int rid : hits)
            {
                if (self->m_metaMap)
                {
                    auto it = self->m_metaMap->find(rid);
                    if (it != self->m_metaMap->end())
                    {
                        if (it->second.offset_mode == "EXACT")
                            continue;
                    }
                }
                validHits.push_back(rid);
            }

            if (!validHits.empty())
            {
                anyVf = true;
                bestHits = std::move(validHits);
            }
        }
        if (anyVf)
        {
            if (self->currentScan)
            {
                self->currentScan->vfHit = true;
                self->currentScan->vfRuleIds = bestHits;
            }

            std::string scanDataStr(reinterpret_cast<const char *>(scanWindow.data()), scanWindow.size());
            bool confirmedByRegex = false;

            for (int rid : bestHits)
            {
                if (self->regexEngine.hasRule(rid))
                {
                    if (self->regexEngine.matchRule(rid, scanDataStr))
                    {
                        confirmedByRegex = true;
                        if (self->currentScan)
                        {
                            self->currentScan->ahoInfo = "Regex Hit [Rule " + std::to_string(rid) + "] in TCP stream";
                        }
                        break;
                    }
                }
                else
                {
                    confirmedByRegex = true;
                    break;
                }
            }

            if (confirmedByRegex)
            {
                std::string dataStr(reinterpret_cast<const char *>(ahoWindow.data()), ahoWindow.size());
                auto result = self->ahoCorasick.search(dataStr);
                if (result.has_value())
                {
                    state.flowFlagged = true;
                    if (self->currentScan)
                    {
                        self->currentScan->ahoHit = true;
                        self->currentScan->ahoInfo = result.value();
                    }

                    std::println("=== AHO HIT SESSION {} ===", state.sessionId);
                    std::println("{}", result.value());
                }
            }
        }
    }

    buffer.insert(buffer.end(), data, data + len);
    if (buffer.size() > MAX_STREAM_KEEP)
    {
        const std::size_t drop = buffer.size() - MAX_STREAM_KEEP;
        buffer.erase(buffer.begin(), buffer.begin() + drop);
    }
}

void TcpStreamHandler::onConnectionEnd(const pcpp::ConnectionData &connData,
                                       pcpp::TcpReassembly::ConnectionEndReason reason,
                                       void *userCookie)
{
    auto *self = static_cast<TcpStreamHandler *>(userCookie);
    std::lock_guard<std::mutex> lock(self->mutex);

    auto it = self->connections.find(connData.flowKey);
    if (it != self->connections.end())
        self->connections.erase(it);
}