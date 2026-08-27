#include "SystemEventSender.hpp"
#include "third_party/json.hpp"
#include "RuleHelper.hpp"
#include "Janus.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include "Logger.hpp"

using json = nlohmann::json;
constexpr std::uint32_t MAX_CONTROL_FRAME_BYTES = 64 * 1024;

bool SystemEventSender::sendAll(const void *data, std::size_t len)
{
    const char *buffer = static_cast<const char *>(data);
    std::size_t totalSent = 0;

    while (totalSent < len)
    {
        ssize_t sent = ::send(
            senderSocket,
            buffer + totalSent,
            len - totalSent,
            MSG_NOSIGNAL);

        if (sent < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return false;
        }

        if (sent == 0)
        {
            return false;
        }

        totalSent += static_cast<std::size_t>(sent);
    }

    return true;
}

void SystemEventSender::sendToHandler(const janus::packet::PacketDecisionEvent &event)
{
    std::string payload;
    if (!event.SerializeToString(&payload))
    {
        std::cerr << "Failed to serialize PacketDecisionEvent\n";
        return;
    }

    uint32_t payloadSize = static_cast<uint32_t>(payload.size());
    uint32_t netPayloadSize = htonl(payloadSize);

    if (!sendAll(&netPayloadSize, sizeof(netPayloadSize)) ||
        !sendAll(payload.data(), payload.size()))
    {
        std::cerr << "Failed to send event to handler\n";

        close(senderSocket);
        senderSocket = -1;

        connectSendToHandler();

        // retry once after reconnect
        if (senderSocket >= 0)
        {
            if (!sendAll(&netPayloadSize, sizeof(netPayloadSize)) ||
                !sendAll(payload.data(), payload.size()))
            {
                std::cerr << "Retry send failed after reconnect\n";
            }
        }
    }
}
SystemEventSender::SystemEventSender() : senderSocket(-1), receiverSocket(-1)
{
    connectSendToHandler();
    openReceiverSocket();
    senderThread = std::thread(&SystemEventSender::threadSendRun, this);
    receiverThread = std::thread(&SystemEventSender::threadReceiveRun, this);
}
SystemEventSender::~SystemEventSender()
{
    running = false;
    queueCv.notify_all();

    if (receiverSocket >= 0)
    {
        shutdown(receiverSocket, SHUT_RDWR);
        close(receiverSocket);
        receiverSocket = -1;
    }

    if (senderSocket >= 0)
    {
        shutdown(senderSocket, SHUT_RDWR);
        close(senderSocket);
        senderSocket = -1;
    }

    if (senderThread.joinable())
    {
        senderThread.join();
    }

    if (receiverThread.joinable())
    {
        receiverThread.join();
    }
}
void SystemEventSender::connectSendToHandler()
{
    if (senderSocket >= 0)
    {
        close(senderSocket);
    }

    senderSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (senderSocket < 0)
    {
        std::cerr << "socket() failed\n";
        return;
    }

    sockaddr_in handler{};
    handler.sin_family = AF_INET;
    handler.sin_port = htons(HANDLER_PORT);

    if (inet_pton(AF_INET, HANDLER_IP, &handler.sin_addr) <= 0)
    {
        std::cerr << "inet_pton() failed\n";
        close(senderSocket);
        senderSocket = -1;
        return;
    }

    if (connect(senderSocket, reinterpret_cast<sockaddr *>(&handler), sizeof(handler)) < 0)
    {
        std::cerr << "connect() failed errno=" << errno
                  << " (" << std::strerror(errno) << ")"
                  << " ip=" << HANDLER_IP
                  << " port=" << HANDLER_PORT
                  << "\n";
        close(senderSocket);
        senderSocket = -1;
        return;
    }
}
void SystemEventSender::openReceiverSocket()
{
    if (receiverSocket >= 0)
    {
        close(receiverSocket);
    }

    receiverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (receiverSocket < 0)
    {
        std::cerr << "socket() failed\n";
        return;
    }

    sockaddr_in handler{};
    handler.sin_family = AF_INET;
    handler.sin_port = htons(LISTEN_PORT);
    handler.sin_addr.s_addr = INADDR_ANY;
    bind(receiverSocket, reinterpret_cast<sockaddr *>(&handler), sizeof(handler));
    listen(receiverSocket, 1);
}
void SystemEventSender::threadSendRun()
{
    while (running)
    {
        janus::packet::PacketDecisionEvent event;

        {
            std::unique_lock<std::mutex> lock(queueMutex);

            queueCv.wait(lock, [this]
                         { return !running || !eventQueue.empty(); });

            if (!running && eventQueue.empty())
            {
                return;
            }

            event = std::move(eventQueue.front());
            eventQueue.pop_front();
        }

        sendToHandler(event);
    }
}

static bool recvExact(int socketFd, void *data, std::size_t length)
{
    auto *buffer = static_cast<char *>(data);
    std::size_t totalReceived = 0;

    while (totalReceived < length)
    {
        ssize_t received = recv(
            socketFd,
            buffer + totalReceived,
            length - totalReceived,
            0);

        if (received == 0)
        {
            return false;
        }

        if (received < 0)
        {
            if (errno == EINTR)
                continue;

            return false;
        }

        totalReceived += static_cast<std::size_t>(received);
    }

    return true;
}

static bool readFrame(int socketFd, std::vector<std::uint8_t> &payload)
{
    std::uint32_t netSize = 0;

    if (!recvExact(socketFd, &netSize, sizeof(netSize)))
        return false;

    const std::uint32_t size = ntohl(netSize);

    if (size == 0 || size > MAX_CONTROL_FRAME_BYTES)
        return false;

    payload.resize(size);

    return recvExact(socketFd, payload.data(), payload.size());
}
static RuleHelper::RuleMeta ruleMetaFromText(const std::string &text)
{
    auto command = json::parse(text);
    auto ruleJson = command.at("rule");

    const std::string id = ruleJson.at("id").get<std::string>();
    const std::string proto = ruleJson.value("proto", "ANY");
    const std::string action = ruleJson.value("action", "FLAG");
    const std::string valueHex = ruleJson.at("value_hex").get<std::string>();

    const int offset = ruleJson.at("offset").get<int>();
    const int length = ruleJson.at("length").get<int>();

    auto bytes = RuleHelper::hexToBytes(valueHex);

    RuleHelper::RuleMeta meta{};
    meta.id = id;
    meta.desc = ruleJson.value("desc", "");
    meta.regex_pattern = ruleJson.value("regex", "");
    if (ruleJson.contains("aho_patterns") && ruleJson["aho_patterns"].is_array())
    {
        for (const auto &patternJson : ruleJson["aho_patterns"])
        {
            if (!patternJson.is_string())
                continue;

            std::string pattern = patternJson.get<std::string>();
            if (!pattern.empty())
            {
                meta.aho_patterns.push_back(std::move(pattern));
            }
        }
    }
    meta.action = RuleHelper::parseAction(action);
    meta.proto = RuleHelper::parseProto(proto);
    meta.offset_mode = ruleJson.value("offset_mode", "PAYLOAD");
    meta.exact_offset = offset;
    meta.length = length;
    meta.ruleId = RuleHelper::idToRuleID(id, proto, length, offset, valueHex);
    meta.bytes = {0, 0, 0, 0};

    for (int i = 0; i < length; ++i)
        meta.bytes[i] = bytes.at(i);

    return meta;
}

static void sendControlResponse(int clientSocket, bool ok, const std::string &message)
{
    json response;
    response["ok"] = ok;

    if (ok)
        response["message"] = message;
    else
        response["error"] = message;

    std::string payload = response.dump();

    std::uint32_t size = htonl(static_cast<std::uint32_t>(payload.size()));

    send(clientSocket, &size, sizeof(size), MSG_NOSIGNAL);
    send(clientSocket, payload.data(), payload.size(), MSG_NOSIGNAL);
}
void SystemEventSender::threadReceiveRun()
{
    while (running)
    {
        int clientSocket = accept(receiverSocket, nullptr, nullptr);

        if (clientSocket < 0)
        {
            if (errno == EINTR)
                continue;

            if (!running)
                break;

            Logger::error("accept() failed on rule control socket");
            continue;
        }

        std::vector<std::uint8_t> payload;

        if (!readFrame(clientSocket, payload))
        {
            Logger::error("failed to read rule control frame");
            close(clientSocket);
            continue;
        }

        std::string rule(
            reinterpret_cast<const char *>(payload.data()),
            payload.size());
        try
        {
            RuleHelper::RuleMeta meta = ruleMetaFromText(rule);

            bool added = Janus::addRuleToAllWorkers(meta);

            if (added)
                sendControlResponse(clientSocket, true, "rule added successfully");
            else
                sendControlResponse(clientSocket, false, "failed to add rule to one or more workers");
        }
        catch (const std::exception &ex)
        {
            sendControlResponse(clientSocket, false, ex.what());
        }
        close(clientSocket);
    }
}
bool SystemEventSender::enqueue(janus::packet::PacketDecisionEvent event)
{
    {
        std::lock_guard<std::mutex> lock(queueMutex);

        if (eventQueue.size() >= MAX_QUEUE_SIZE)
        {
            return false;
        }

        eventQueue.push_back(std::move(event));
    }

    queueCv.notify_one();
    return true;
}