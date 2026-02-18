#pragma once

#include <iostream>
#include <unordered_map>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpReassembly.h>

enum TCP_STATE
{
    SYN_SEN,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT,
    CLOSE_WAIT
};

class TcpSessionTracker
{

public:
    TcpSessionTracker();
    typedef struct
    {
        int socket;
        bool connected = false;
        TCP_STATE state;
        pcpp::ConnectionData sessionData;
    } TcpConnection;

    bool addSession(const pcpp::ConnectionData &session, int socket);
    bool addSession(const pcpp::ConnectionData &session);
    bool removeSession(const pcpp::ConnectionData &session);
    bool sessionExists(const pcpp::ConnectionData &session);
    void printSessionTable();
    TcpConnection getSession(uint32_t flowKey);

private:
    std::unordered_map<uint32_t, TcpConnection> m_activeSessions;
};