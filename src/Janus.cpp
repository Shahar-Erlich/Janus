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
bool Janus::addRuleToAllWorkers(const RuleHelper::RuleMeta &meta)
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
    std::ifstream f("/app/dpi_rules.txt");
    if (!f.is_open())
    {
        Logger::error("Could not open dpi_rules.txt");
        return;
    }

    std::string line;
    while (std::getline(f, line))
    {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        if (!line.empty())
            globalAhoCorasick.addString(line);
    }

    globalAhoCorasick.prepare();
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