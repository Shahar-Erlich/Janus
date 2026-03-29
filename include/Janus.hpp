#pragma once

#include <iostream>
#include "Core.hpp"
#include "Logger.hpp"
#include <thread>
#include "PacketPolicy.hpp"
#include "TcpStreamHandler.hpp"
#include "VectorFilteringEngine.hpp"
#include "AhoCorasick.hpp"
#include "SystemEventSender.hpp"

#define MAX_WORKER_THREAD 4

class Janus
{
private:
    class WorkerThread
    {
    public:
        std::unique_ptr<Core> workerCore;
        std::thread workerThread;
        WorkerThread(int queueNumber);
        void threadRun();
    };
    static void createWorkerThreads();

public:
    Janus() = default;
    ~Janus();
    static void init();
    static AhoCorasick globalAhoCorasick;
    static SystemEventSender systemEventSender;
    static std::vector<std::unique_ptr<WorkerThread>> workerThreads;
};