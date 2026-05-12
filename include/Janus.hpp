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
#include "RuleHelper.hpp"

#define MAX_WORKER_THREAD 4

class Janus
{
private:
    class WorkerThread
    {
    public:
        std::unique_ptr<Core> workerCore;
        std::thread workerThread;
        /**
         * @brief construct a worker thread wrapper for a specific NFQUEUE queue
         *
         * @param queueNumber queue number assigned to this worker
         */
        WorkerThread(int queueNumber);
        /**
         * @brief entry point for the worker thread
         */
        void threadRun();
    };
    /**
     * @brief create the worker threads
     *
     */
    static void createWorkerThreads();

public:
    Janus() = default;
    ~Janus();
    /**
     * @brief initialize the global AhoCorasick engine and start all worker threads
     */
    static void init();
    static bool addRuleToAllWorkers(const RuleHelper::RuleMeta &meta);
    static AhoCorasick globalAhoCorasick;
    static SystemEventSender systemEventSender;
    static std::vector<std::unique_ptr<WorkerThread>> workerThreads;
};