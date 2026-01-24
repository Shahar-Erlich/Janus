cmake_minimum_required(VERSION 3.16)
project(Janus LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)

set(CMAKE_CXX_STANDARD_REQUIRED ON)

#Logger
add_library(janus_logger STATIC Logger/Logger.cpp)

target_include_directories(janus_logger PUBLIC ${PROJECT_SOURCE_DIR}/Logger)

#packet
add_library(packet STATIC Parsed_Packet/Parsed_Packet.cpp Pcap_Parser/Pcap_Parser.cpp)
target_include_directories(packet PUBLIC ${PROJECT_SOURCE_DIR}/Parsed_Packet ${PROJECT_SOURCE_DIR}/Pcap_Parser)
target_link_libraries(packet janus_logger Pcap++ Packet++ Common++ pcap)

#policy
add_library(policy_handler STATIC Policy_Handler/Packet_Policy.cpp)
target_include_directories(policy_handler PUBLIC ${PROJECT_SOURCE_DIR}/Policy_Handler)
target_link_libraries(policy_handler blacklist_handler packet janus_logger Pcap++ Packet++ Common++ pcap packet)

#blacklist
add_library(blacklist_handler STATIC Blacklist_Handler/Blacklist_Handler.cpp)
target_include_directories(blacklist_handler PUBLIC ${PROJECT_SOURCE_DIR}/Blacklist_Handler)
target_link_libraries(blacklist_handler janus_logger packet Pcap++ Packet++ Common++ pcap)

#Core
add_executable(janus_core Janus_Core/Core.cpp)

target_include_directories(janus_core PRIVATE ${PROJECT_SOURCE_DIR}/Janus_Core)

target_link_libraries(janus_core janus_logger mnl netfilter_queue policy_handler blacklist_handler)


#main
add_executable(main main.cpp)

target_include_directories(main PRIVATE ${PROJECT_SOURCE_DIR})

target_link_libraries(main janus_logger packet)
