#include "Logger.hpp"
#include "PcapParser.hpp"
#include <pcapplusplus/PcapFileDevice.h>
#include <memory>
#include <print>
#include "TerminalColors.hpp"

int main()
{
    std::string pcapFilePath = "../pcaps/10kPackets_3.pcap";
    auto pcapFile = std::make_unique<pcpp::PcapFileReaderDevice>(pcapFilePath);
    if (!pcapFile->open())
    {
        Logger::error("Failed to open pcap file");
        std::exit(1);
    }

    pcpp::RawPacket rawPacket;

    int totalSeen = 0;
    int tcpSeen = 0;
    int udpSeen = 0;
    int icmpSkipped = 0;

    int sendOk = 0;
    int sendFailed = 0;
    int tcpOk = 0;
    int tcpFailed = 0;
    int udpOk = 0;
    int udpFailed = 0;

    while (pcapFile->getNextPacket(rawPacket))
    {
        const pcpp::Packet packet(&rawPacket);
        auto proto = PcapParser::getTransportProtocol(packet);

        if (proto == pcpp::ICMP)
        {
            icmpSkipped++;
            continue;
        }

        totalSeen++;

        if (proto == pcpp::TCP)
            tcpSeen++;
        else if (proto == pcpp::UDP)
            udpSeen++;

        // std::println("\n{}=========Packet {} Data:=========", TerminalColors::Yellow, totalSeen);
        // Logger::log("Source: " + PcapParser::extractSourceAddress(packet).toString());
        // Logger::log("Destination " + PcapParser::extractDestinationAddress(packet).toString());
        // Logger::log(proto == pcpp::TCP ? "TCP packet" : "UDP Packet");
        // Logger::log("port: " + std::to_string(PcapParser::extractPorts(packet)));
        // std::println("=============================={}\n", TerminalColors::Color_Off);

        const bool ok = sendPacket(packet);

        if (ok)
        {
            sendOk++;
            if (proto == pcpp::TCP)
                tcpOk++;
            else if (proto == pcpp::UDP)
                udpOk++;
        }
        else
        {
            sendFailed++;
            if (proto == pcpp::TCP)
                tcpFailed++;
            else if (proto == pcpp::UDP)
                udpFailed++;
        }
    }

    // std::println("\n{}========== Sender Summary =========={}", TerminalColors::Green, TerminalColors::Color_Off);
    // std::println("PCAP: {}", pcapFilePath);
    // std::println("totalSeen={}", totalSeen);
    // std::println("tcpSeen={} udpSeen={} icmpSkipped={}", tcpSeen, udpSeen, icmpSkipped);
    // std::println("sendOk={} sendFailed={}", sendOk, sendFailed);
    // std::println("tcpOk={} tcpFailed={}", tcpOk, tcpFailed);
    // std::println("udpOk={} udpFailed={}", udpOk, udpFailed);
    // std::println("{}===================================={}\n", TerminalColors::Green, TerminalColors::Color_Off);

    return 0;
}