#include "Logger/Logger.hpp"
#include "Pcap_Parser/Pcap_Parser.hpp"
#include "Parsed_Packet/Parsed_Packet.hpp"
#include <pcapplusplus/PcapFileDevice.h>
#include <memory>

int main()
{
    std::string pcapFilePath = "Pcap_Parser/pcaps/fake_traffic.pcap";
    auto pcapFile = std::make_unique<pcpp::PcapFileReaderDevice>(pcapFilePath);
    if (!pcapFile->open())
    {
        Logger::error("Failed to open pcap file");
        std::exit(1);
    }
    pcpp::RawPacket rawPacket;
    pcapFile->getNextPacket(rawPacket);
    while (pcapFile->getNextPacket(rawPacket))
    {
        pcpp::Packet packet(&rawPacket);
        std::unique_ptr<ParsedPacket> parsed = Parser::parsePacket(packet);
        Logger::log(parsed.get()->getSourceAddress().toString());
        Logger::log(parsed.get()->getDestinationAddress().toString());
        Logger::log(parsed.get()->getProtocol() == pcpp::TCP ? "TCP" : "UDP");
        sendPacket(*parsed);
    }
    return 0;
}