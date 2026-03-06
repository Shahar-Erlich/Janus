#include "TcpStreamHandler.hpp"
#include "Logger.hpp"
#include <algorithm>
#include <print>
#include <atomic>

static std::atomic<int> g_sessionCounter = 1;

TcpStreamHandler::TcpStreamHandler(AhoCorasick &ac, VectorFilteringEngine &ve)
    : reassembly(onDataReady, this, onConnectionStart, onConnectionEnd),
      ahoCorasick(ac),
      vectorEngine(ve)
{
}

TcpPacketScanResult TcpStreamHandler::processPacket(pcpp::Packet &packet)
{
    TcpPacketScanResult res{};

    if (!packet.isPacketOfType(pcpp::TCP))
        return res;

    // set "currentScan" רק לפרק הזמן של הקריאה הזו
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

    // Window עבור VF: overlap קטן + ה-data החדש
    std::vector<std::uint8_t> scanWindow;
    scanWindow.reserve(overlap + len);
    if (overlap > 0)
    {
        scanWindow.insert(scanWindow.end(), buffer.end() - overlap, buffer.end());
    }
    scanWindow.insert(scanWindow.end(), data, data + len);

    // Window עבור Aho: tail גדול יותר + ה-data החדש
    const std::size_t ahoTail = std::min(buffer.size(), AHO_TAIL);
    std::vector<std::uint8_t> ahoWindow;
    ahoWindow.reserve(ahoTail + len);
    if (ahoTail > 0)
    {
        ahoWindow.insert(ahoWindow.end(), buffer.end() - ahoTail, buffer.end());
    }
    ahoWindow.insert(ahoWindow.end(), data, data + len);

    // אם כבר flagged flow אפשר לדלג/לוגג, אבל לא חובה
    if (!state.flowFlagged)
    {
        // בדיקה עם shifts כדי לא לפספס anchors שחוצים גבול
        bool anyVf = false;
        std::vector<int> bestHits;
        const size_t maxShift = std::min<size_t>(64, scanWindow.size());
        for (size_t i = 0; i <= maxShift; ++i)
        {
            std::span<const uint8_t> win(scanWindow.data() + i, scanWindow.size() - i);
            auto hits = self->vectorEngine.scanPayload(win);
            if (!hits.empty())
            {
                anyVf = true;
                bestHits = std::move(hits);
                break;
            }
        }

        // fallback על ה-data החדש בלבד
        if (!anyVf)
        {
            std::span<const uint8_t> payload(data, len);
            auto hits = self->vectorEngine.scanPayload(payload);
            if (!hits.empty())
            {
                anyVf = true;
                bestHits = std::move(hits);
            }
        }

        if (anyVf)
        {
            // עדכון תוצאה של הפאקטה הנוכחית (אם אנחנו בתוך processPacket)
            if (self->currentScan)
            {
                self->currentScan->vfHit = true;
                self->currentScan->vfRuleIds = bestHits;
            }

            // Aho confirm על חלון "tail + new"
            std::string dataStr(reinterpret_cast<const char *>(ahoWindow.data()), ahoWindow.size());
            auto result = self->ahoCorasick.search(dataStr);
            if (result.has_value())
            {
                state.flowFlagged = true; // future: drop-fast
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

    // Update stream buffer (keep tail)
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