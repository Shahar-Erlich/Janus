#include "Janus.hpp"
#include <fstream>
#include <cstdlib>
#include <string>

AhoCorasick Janus::globalAhoCorasick;
SystemEventSender Janus::systemEventSender;
std::vector<std::unique_ptr<Janus::WorkerThread>> Janus::workerThreads;

Janus::~Janus()
{
}

void Janus::WorkerThread::threadRun()
{
    workerCore->init();
}

Janus::WorkerThread::WorkerThread(int queueNumber)
    : workerCore(std::make_unique<Core>(queueNumber, globalAhoCorasick, systemEventSender)),
      workerThread(&Janus::WorkerThread::threadRun, this)
{
}

void Janus::createWorkerThreads()
{
    for (int i = 0; i < MAX_WORKER_THREAD; i++)
    {
        workerThreads.emplace_back(std::make_unique<WorkerThread>(i));
    }
}
bool Janus::addRuleToAllWorkers(RuleHelper::RuleMeta &meta)
{
    bool ok = true;

    for (auto &worker : workerThreads)
    {
        if (!worker || !worker->workerCore)
        {
            ok = false;
            continue;
        }

        if (!worker->workerCore->addRule(meta))
        {
            ok = false;
        }
    }

    return ok;
}
void Janus::init()
{
    try
    {
        auto loaded = RuleLoader::loadFromFile("/app/rules.json");

        std::size_t ahoCount = 0;

        for (const auto &[ruleId, meta] : loaded.metaByRuleId)
        {
            for (const auto &pattern : meta.aho_patterns)
            {
                if (!pattern.empty())
                {
                    globalAhoCorasick.addString(pattern);
                    ++ahoCount;
                }
            }
        }

        globalAhoCorasick.prepare();
    }
    catch (const std::exception &ex)
    {
        Logger::error(std::format(
            "Failed to load Aho-Corasick patterns from rules.json: {}",
            ex.what()));
    }

    createWorkerThreads();
}

int main()
{

    freopen("/blacklists/debug.log", "w", stdout);
    freopen("/blacklists/debug.log", "a", stderr);

    Janus::init();

    for (auto &worker : Janus::workerThreads)
    {
        if (worker->workerThread.joinable())
            worker->workerThread.join();
    }

    return 0;
}