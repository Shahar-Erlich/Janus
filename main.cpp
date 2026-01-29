#include "include/Logger.hpp"
#include "include/PcapParser.hpp"
#include "include/ParsedPacket.hpp"
#include <pcapplusplus/PcapFileDevice.h>
#include <memory>
#include <print>

int main()
{
    std::string pcapFilePath = "../pcaps/test_pcap.pcap";
    auto pcapFile = std::make_unique<pcpp::PcapFileReaderDevice>(pcapFilePath);
    if (!pcapFile->open())
    {
        Logger::error("Failed to open pcap file");
        std::exit(1);
    }
    pcpp::RawPacket rawPacket;
    // pcapFile->getNextPacket(rawPacket);
    while (pcapFile->getNextPacket(rawPacket))
    {
        pcpp::Packet packet(&rawPacket);

        // for (pcpp::Layer *layer = packet.getFirstLayer();
        //      layer != nullptr;
        //      layer = layer->getNextLayer())
        // {
        //     auto proto = layer->getProtocol();
        //     Logger::log("Layer protocol: " + std::to_string((int)proto));
        // }

        auto parsed = PcapParser::parsePacket(packet);
        Logger::log("Parsed packet");
        if (!parsed)
        {
            Logger::error("Failed to parse packet");
            continue;
        }
        if (parsed->getProtocol() == pcpp::ICMP)
            continue;
        Logger::log("Source: " + parsed.get()->getSourceAddress().toString());
        Logger::log("Destination " + parsed.get()->getDestinationAddress().toString());
        Logger::log(parsed.get()->getProtocol() == pcpp::TCP ? "TCP" : "UDP");
        Logger::log("port: " + std::to_string(parsed->getDestinationPort()));

        sendPacket(*parsed);
    }
    return 0;
}