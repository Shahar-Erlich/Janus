cmake_minimum_required(VERSION 3.16)
project(Janus LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

#  ommon include directory
set(JANUS_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)

#logger
add_library(janus_logger STATIC
    src/Logger.cpp
)

target_include_directories(janus_logger
    PUBLIC ${JANUS_INCLUDE_DIR}
)

#packet
add_library(packet STATIC
    src/ParsedPacket.cpp
    src/PcapParser.cpp
)

target_include_directories(packet
    PUBLIC ${JANUS_INCLUDE_DIR}
)

target_link_libraries(packet
    PUBLIC janus_logger
    PUBLIC Pcap++ Packet++ Common++ pcap
)

#blacklist
add_library(blacklist_handler STATIC
    src/BlacklistHandler.cpp
)

target_include_directories(blacklist_handler
    PUBLIC ${JANUS_INCLUDE_DIR}
)

target_link_libraries(blacklist_handler
    PUBLIC janus_logger
    PUBLIC packet
)

#policy
add_library(policy_handler STATIC
    src/PacketPolicy.cpp
)

target_include_directories(policy_handler
    PUBLIC ${JANUS_INCLUDE_DIR}
)

target_link_libraries(policy_handler
    PUBLIC janus_logger
    PUBLIC packet
    PUBLIC blacklist_handler
)

#core
add_executable(janus_core
    src/Core.cpp
)

target_include_directories(janus_core
    PRIVATE ${JANUS_INCLUDE_DIR}
)

target_link_libraries(janus_core
    janus_logger
    packet
    policy_handler
    blacklist_handler
    mnl
    netfilter_queue
)

#main
add_executable(main
    main.cpp
)

target_include_directories(main
    PRIVATE ${JANUS_INCLUDE_DIR}
)

target_link_libraries(main
    janus_logger
    packet
)
