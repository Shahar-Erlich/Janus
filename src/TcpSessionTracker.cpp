#include "TcpSessionTracker.hpp"
#include <sys/socket.h>
#include "Logger.hpp"
#include "TerminalColors.hpp"
#include <print>

TcpSessionTracker::TcpSessionTracker() = default;

bool TcpSessionTracker::addSession(const pcpp::ConnectionData &session, int socket)
{
    TcpConnection connection = {socket, true, TCP_STATE::ESTABLISHED, session};
    return m_activeSessions.emplace(session.flowKey, connection).second;
}
bool TcpSessionTracker::addSession(const pcpp::ConnectionData &session)
{
    TcpConnection connection = {-1, true, TCP_STATE::ESTABLISHED, session};
    return m_activeSessions.emplace(session.flowKey, connection).second;
}

bool TcpSessionTracker::removeSession(const pcpp::ConnectionData &session)
{
    return m_activeSessions.erase(session.flowKey) > 0;
}

bool TcpSessionTracker::sessionExists(const pcpp::ConnectionData &session)
{
    return m_activeSessions.contains(session.flowKey);
}

void TcpSessionTracker::printSessionTable()
{
    std::println("{}ACTIVE SESSIONS:\n================================================{}", TerminalColors::Green, TerminalColors::Color_Off);
    for (const auto &session : m_activeSessions)
    {
        auto sessionData = session.second.sessionData;
        std::println(
            "{}{} / {} -> {} / {}\n================================================\n\n{}",
            TerminalColors::Green,
            sessionData.srcIP.toString(),
            sessionData.srcPort,
            sessionData.dstIP.toString(),
            sessionData.dstPort,
            TerminalColors::Color_Off);
    }
}
TcpSessionTracker::TcpConnection TcpSessionTracker::getSession(uint32_t flowKey)
{
    return m_activeSessions.at(flowKey);
}
