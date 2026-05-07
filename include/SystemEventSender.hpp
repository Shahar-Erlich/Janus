#pragma once
#include <iostream>
#include <thread>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "janus_common.pb.h"
#include "janus_packet.pb.h"

#define HANDLER_IP "172.16.0.30"
#define HANDLER_PORT 50051

class SystemEventSender
{
public:
    /**
     * @brief Construct a new System Event Sender object
     *
     */
    SystemEventSender();
    /**
     * @brief Destroy the System Event Sender object
     *
     */
    ~SystemEventSender();
    /**
     * @brief queue an event to be sent to the frontend/database handler
     *
     * @param event event to queue
     * @return true if the event was queued successfully
     * @return false if the queue is full
     */
    bool enqueue(janus::packet::PacketDecisionEvent event);

private:
    std::thread senderThread;
    int senderSocket{-1};
    std::deque<janus::packet::PacketDecisionEvent> eventQueue;
    std::mutex queueMutex;
    std::condition_variable queueCv;
    std::atomic<bool> running{true};
    static constexpr std::size_t MAX_QUEUE_SIZE = 8192;
    /**
     * @brief worker thread loop for sending queued events to the handler
     *
     * waits for events to appear in the queue and forwards them to the system handler
     */
    void threadRun();
    /**
     * @brief establish a TCP connection to the external system handler
     */
    void connectToHandler();
    /**
     * @brief serialize and send an event to the system handler
     *
     * sends the payload size first, then the serialized protobuf payload
     * if sending fails, reconnects and retries once
     *
     * @param event Event to send.
     */
    void sendToHandler(const janus::packet::PacketDecisionEvent &event);
    /**
     * @brief Send the entire buffer to the connected handler socket.
     *
     * Repeatedly calls send() until all bytes in the given buffer were sent
     * or an error/closed connection occurs.
     *
     * @param data Pointer to the buffer to send.
     * @param len Number of bytes to send.
     * @return true if all bytes were sent successfully.
     * @return false if sending failed or the connection was closed.
     */
    bool sendAll(const void *data, std::size_t len);
};
