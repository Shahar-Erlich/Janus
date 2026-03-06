#include "Logger.hpp"
#include "PcapParser.hpp"
#include <pcapplusplus/PcapFileDevice.h>
#include <memory>
#include <print>
#include "TerminalColors.hpp"

int main()
{
    std::string pcapFilePath = "../pcaps/10kPackets_1.pcap";
    auto pcapFile = std::make_unique<pcpp::PcapFileReaderDevice>(pcapFilePath);
    if (!pcapFile->open())
    {
        Logger::error("Failed to open pcap file");
        std::exit(1);
    }
    pcpp::RawPacket rawPacket;
    // pcapFile->getNextPacket(rawPacket);
    int i = 0;
    while (pcapFile->getNextPacket(rawPacket))
    {
        const pcpp::Packet packet(&rawPacket);

        // for (pcpp::Layer *layer = packet.getFirstLayer();
        //      layer != nullptr;
        //      layer = layer->getNextLayer())
        // {
        //     auto proto = layer->getProtocol();
        //     Logger::log("Layer protocol: " + std::to_string((int)proto));
        // }

        // auto parsed = PcapParser::parsePacket(packet);
        // Logger::log("Parsed packet");
        // if (!parsed)
        // {
        //     Logger::error("Failed to parse packet");
        //     continue;
        // }
        if (PcapParser::getTransportProtocol(packet) == pcpp::ICMP)
            continue;
        std::println("\n{}=========Packet {} Data:=========", TerminalColors::Yellow, i);
        Logger::log("Source: " + PcapParser::extractSourceAddress(packet).toString());
        Logger::log("Destination " + PcapParser::extractDestinationAddress(packet).toString());
        Logger::log(PcapParser::getTransportProtocol(packet) == pcpp::TCP ? "TCP packet" : "UDP Packet");
        Logger::log("port: " + std::to_string(PcapParser::extractPorts(packet)));
        std::println("=============================={}\n", TerminalColors::Color_Off);

        sendPacket(packet);
        i++;
    }
    return 0;
}