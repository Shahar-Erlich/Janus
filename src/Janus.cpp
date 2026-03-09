#include "Janus.hpp"
#include <fstream>
AhoCorasick Janus::globalAhoCorasick;
std::vector<std::unique_ptr<Janus::WorkerThread>> Janus::workerThreads;
Janus::~Janus()
{
}

void Janus::WorkerThread::threadRun()
{
    workerCore->init();
}

Janus::WorkerThread::WorkerThread(int queueNumber) : workerCore(std::make_unique<Core>(queueNumber, globalAhoCorasick)),
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