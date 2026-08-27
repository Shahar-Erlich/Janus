#include "TcpStreamHandler.hpp"
#include "Logger.hpp"
#include <algorithm>
#include <print>
#include <atomic>
#include <chrono>
#include "BlacklistHandler.hpp"

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
static janus::common::ProcessingStamp makeStamp(
    janus::common::EngineStage stage,
    uint64_t startedMs,
    uint64_t finishedMs,
    uint64_t durationUs,
    std::string status)
{
    janus::common::ProcessingStamp s;
    s.set_stage(stage);
    s.set_started_unix_ms(startedMs);
    s.set_finished_unix_ms(finishedMs);
    s.set_duration_us(durationUs);
    s.set_status(std::move(status));
    return s;
}
void TcpStreamHandler::onConnectionStart(const pcpp::ConnectionData &connectionData, void *userCookie)
{
    auto *self = static_cast<TcpStreamHandler *>(userCookie);
    std::lock_guard<std::mutex> lock(self->mutex);

    ConnectionState st{};
    st.sessionId = g_sessionCounter++;
    self->connections[connectionData.flowKey] = std::move(st);
}
static uint64_t nowUnixMs()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(
               system_clock::now().time_since_epoch())
        .count();
}
std::vector<std::uint8_t> TcpStreamHandler::makeWindow(
    const std::vector<std::uint8_t> &buffer,
    const std::uint8_t *data,
    std::size_t len,
    std::size_t tailSize)
{
    const std::size_t tail = std::min(buffer.size(), tailSize);

    std::vector<std::uint8_t> window;
    window.reserve(tail + len);

    if (tail > 0)
    {
        window.insert(window.end(), buffer.end() - tail, buffer.end());
    }

    window.insert(window.end(), data, data + len);
    return window;
}

void TcpStreamHandler::appendTrim(
    std::vector<std::uint8_t> &buffer,
    const std::uint8_t *data,
    std::size_t len)
{
    buffer.insert(buffer.end(), data, data + len);

    if (buffer.size() > MAX_STREAM_KEEP)
    {
        const std::size_t drop = buffer.size() - MAX_STREAM_KEEP;
        buffer.erase(buffer.begin(), buffer.begin() + drop);
    }
}

void TcpStreamHandler::reuseConfirmed(const ConnectionState &state)
{
    if (!currentScan)
        return;

    currentScan->vfHit = !state.confirmedRuleIds.empty();
    currentScan->vfRuleIds = state.confirmedRuleIds;
    currentScan->ahoHit = true;
    currentScan->ahoInfo = state.confirmedAhoInfo;
}

std::vector<int> TcpStreamHandler::filterHits(
    const std::vector<int> &hits,
    bool allowExact) const
{
    std::vector<int> validHits;

    for (int rid : hits)
    {
        if (m_metaMap)
        {
            auto it = m_metaMap->find(rid);

            if (it != m_metaMap->end())
            {
                if (it->second.offset_mode == "EXACT" && !allowExact)
                    continue;
            }
        }

        validHits.push_back(rid);
    }

    return validHits;
}

bool TcpStreamHandler::runVf(
    const std::vector<std::uint8_t> &vfWindow,
    const std::uint8_t *data,
    std::size_t len,
    std::vector<int> &bestHits)
{
    const uint64_t vfStartMs = nowUnixMs();
    const auto vfStart = std::chrono::steady_clock::now();

    bool anyVf = false;

    const std::size_t maxShift = std::min<std::size_t>(64, vfWindow.size());
    bestHits.clear();

    for (std::size_t i = 0; i <= maxShift; ++i)
    {
        std::span<const std::uint8_t> win(
            vfWindow.data() + i,
            vfWindow.size() - i);

        auto hits = vectorEngine.scanPayload(win);
        auto validHits = filterHits(hits, i == 0);

        if (!validHits.empty())
        {
            anyVf = true;
            bestHits.insert(bestHits.end(), validHits.begin(), validHits.end());
        }
    }

    std::sort(bestHits.begin(), bestHits.end());
    bestHits.erase(std::unique(bestHits.begin(), bestHits.end()), bestHits.end());

    const auto vfEnd = std::chrono::steady_clock::now();
    const uint64_t vfEndMs = nowUnixMs();
    const uint64_t vfDurationUs =
        std::chrono::duration_cast<std::chrono::microseconds>(vfEnd - vfStart).count();

    if (currentScan)
    {
        currentScan->trace.push_back(makeStamp(
            janus::common::ENGINE_STAGE_VECTOR_FILTER,
            vfStartMs,
            vfEndMs,
            vfDurationUs,
            anyVf ? "vf hits found" : "no hits"));
    }

    return anyVf;
}

bool TcpStreamHandler::runAho(
    ConnectionState &state,
    const std::vector<int> &bestHits,
    const std::vector<std::uint8_t> &ahoWindow)
{
    const uint64_t ahoStartMs = nowUnixMs();
    const auto ahoStart = std::chrono::steady_clock::now();

    std::string dataStr(
        reinterpret_cast<const char *>(ahoWindow.data()),
        ahoWindow.size());

    auto result = ahoCorasick.search(dataStr);

    const auto ahoEnd = std::chrono::steady_clock::now();
    const uint64_t ahoEndMs = nowUnixMs();
    const uint64_t ahoDurationUs =
        std::chrono::duration_cast<std::chrono::microseconds>(ahoEnd - ahoStart).count();

    if (currentScan)
    {
        currentScan->trace.push_back(makeStamp(
            janus::common::ENGINE_STAGE_AHO,
            ahoStartMs,
            ahoEndMs,
            ahoDurationUs,
            result.has_value() ? "aho hit" : "no aho hit"));
    }

    if (!result.has_value())
        return false;

    state.flowFlagged = true;
    state.flowConfirmed = true;
    state.confirmedRuleIds = bestHits;
    state.confirmedAhoInfo = result.value();
    if (currentScan)
    {
        currentScan->ahoHit = true;
        currentScan->ahoInfo = result.value();
    }

    return true;
}

bool TcpStreamHandler::runRegex(
    ConnectionState &state,
    const std::vector<int> &bestHits,
    const std::vector<std::uint8_t> &vfWindow)
{
    const uint64_t regexStartMs = nowUnixMs();
    const auto regexStart = std::chrono::steady_clock::now();

    bool regexHit = false;

    std::string_view scanData(
        reinterpret_cast<const char *>(vfWindow.data()),
        vfWindow.size());

    for (int rid : bestHits)
    {
        if (!regexEngine.hasRule(rid))
            continue;

        if (regexEngine.matchRule(rid, scanData))
        {
            regexHit = true;

            state.flowFlagged = true;
            state.flowConfirmed = true;
            state.confirmedRuleIds = bestHits;
            state.confirmedAhoInfo =
                std::format("Regex Hit [Rule {}] in TCP stream", rid);

            if (currentScan)
            {
                currentScan->ahoHit = true;
                currentScan->ahoInfo =
                    std::format("Regex Hit [Rule {}] in TCP stream", rid);
            }

            break;
        }
    }

    const auto regexEnd = std::chrono::steady_clock::now();
    const uint64_t regexEndMs = nowUnixMs();
    const uint64_t regexDurationUs =
        std::chrono::duration_cast<std::chrono::microseconds>(regexEnd - regexStart).count();

    if (currentScan)
    {
        currentScan->trace.push_back(makeStamp(
            janus::common::ENGINE_STAGE_REGEX,
            regexStartMs,
            regexEndMs,
            regexDurationUs,
            regexHit ? "regex hit" : "no regex hit"));
    }

    return regexHit;
}

void TcpStreamHandler::inspectFlow(
    ConnectionState &state,
    const std::vector<std::uint8_t> &vfWindow,
    const std::vector<std::uint8_t> &ahoWindow,
    const std::uint8_t *data,
    std::size_t len,
    const std::string &senderIp)
{
    if (state.flowFlagged)
        return;

    std::vector<int> bestHits;

    if (!runVf(vfWindow, data, len, bestHits))
        return;

    if (currentScan)
    {
        currentScan->vfHit = true;
        currentScan->vfRuleIds = bestHits;
    }

    if (runAho(state, bestHits, ahoWindow))
    {
        // BlacklistHandler::addToIPBlacklist(senderIp);
        return;
    }

    if (runRegex(state, bestHits, vfWindow))
    {
        // BlacklistHandler::addToIPBlacklist(senderIp);
    }
}
void TcpStreamHandler::onDataReady(int8_t side, const pcpp::TcpStreamData &tcpData, void *userCookie)
{
    auto *self = static_cast<TcpStreamHandler *>(userCookie);
    std::lock_guard<std::mutex> lock(self->mutex);

    auto it = self->connections.find(tcpData.getConnectionData().flowKey);
    if (it == self->connections.end())
        return;

    auto &state = it->second;

    const std::uint8_t *data = tcpData.getData();
    const std::size_t len = tcpData.getDataLength();

    if (!data || len == 0)
        return;

    auto &buffer = (side == 0) ? state.clientBuffer : state.serverBuffer;

    const auto vfWindow = self->makeWindow(
        buffer,
        data,
        len,
        MAX_ANCHOR_LEN - 1);

    const auto ahoWindow = self->makeWindow(
        buffer,
        data,
        len,
        AHO_TAIL);

    if (state.flowConfirmed)
    {
        self->reuseConfirmed(state);
        self->appendTrim(buffer, data, len);
        return;
    }
    const auto &conn = tcpData.getConnectionData();

    const std::string senderIp =
        (side == 0)
            ? conn.srcIP.toString()
            : conn.dstIP.toString();
    self->inspectFlow(
        state,
        vfWindow,
        ahoWindow,
        data,
        len,
        senderIp);

    self->appendTrim(buffer, data, len);
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