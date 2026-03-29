#include "SystemEventSender.hpp"
#include <cstring>
#include <cerrno>

bool SystemEventSender::sendAll(const void *data, std::size_t len)
{
    const char *buf = static_cast<const char *>(data);
    std::size_t totalSent = 0;

    while (totalSent < len)
    {
        ssize_t sent = ::send(
            senderSocket,
            buf + totalSent,
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

        connectToHandler();

        // optional: retry once after reconnect
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
SystemEventSender::SystemEventSender() : senderSocket(-1)
{
    connectToHandler();
    senderThread = std::thread(&SystemEventSender::threadRun, this);
}
SystemEventSender::~SystemEventSender()
{
    running = false;
    queueCv.notify_all();

    if (senderThread.joinable())
    {
        senderThread.join();
    }

    if (senderSocket >= 0)
    {
        close(senderSocket);
    }
}
void SystemEventSender::connectToHandler()
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
    std::cerr << "Connecting to handler ip=" << HANDLER_IP
              << " port=" << HANDLER_PORT << "\n";
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
void SystemEventSender::threadRun()
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