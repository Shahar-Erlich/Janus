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
    /**
     * @brief Construct a new Tcp Session Tracker object
     *
     */
    TcpSessionTracker();
    typedef struct
    {
        int socket;
        bool connected = false;
        TCP_STATE state;
        pcpp::ConnectionData sessionData;
    } TcpConnection;
    /**
     * @brief add TCP session to track
     *
     * @param session session to add
     * @param socket socket of the connected session
     * @return true if session added
     * @return false if session adding failed
     */
    bool addSession(const pcpp::ConnectionData &session, int socket);
    bool addSession(const pcpp::ConnectionData &session);
    /**
     * @brief remove session from system
     *
     * @param session session to remove
     * @return true if removed
     * @return false if removing failed
     */
    bool removeSession(const pcpp::ConnectionData &session);
    /**
     * @brief check if session exists in tracker
     *
     * @param session session to check
     * @return true if session exists
     * @return false if session doesnt exist
     */
    bool sessionExists(const pcpp::ConnectionData &session);
    /**
     * @brief print the session table in the tracker
     *
     */
    void printSessionTable();
    /**
     * @brief get session by id (unique flowkey)
     *
     * @param flowKey unique session id
     * @return TcpConnection the connection struct
     */
    TcpConnection getSession(uint32_t flowKey);

private:
    std::unordered_map<uint32_t, TcpConnection> m_activeSessions;
};