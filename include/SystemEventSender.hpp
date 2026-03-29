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
    SystemEventSender();
    ~SystemEventSender();
    bool enqueue(janus::packet::PacketDecisionEvent event);

private:
    std::thread senderThread;
    int senderSocket{-1};
    std::deque<janus::packet::PacketDecisionEvent> eventQueue;
    std::mutex queueMutex;
    std::condition_variable queueCv;
    std::atomic<bool> running{true};
    static constexpr std::size_t MAX_QUEUE_SIZE = 8192;
    void threadRun();
    void connectToHandler();
    void sendToHandler(const janus::packet::PacketDecisionEvent &event);
    bool sendAll(const void *data, std::size_t len);
};
