cmake_minimum_required(VERSION 3.16)
project(Janus LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Common include directory
set(JANUS_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)

#logger
add_library(janus_logger STATIC
    src/Logger.cpp
)

target_include_directories(janus_logger
    PUBLIC ${JANUS_INCLUDE_DIR}
)
#vector filter
add_library(vector_filter STATIC
    src/VectorFilteringEngine.cpp
)

target_compile_options(vector_filter PUBLIC
    -O3
    -march=native
)
target_include_directories(vector_filter
    PUBLIC ${JANUS_INCLUDE_DIR}
)
target_link_libraries(vector_filter
    PUBLIC janus_logger
    PUBLIC Pcap++ Packet++ Common++ pcap
)

#packet
add_library(packet STATIC
    #src/ParsedPacket.cpp
    src/PcapParser.cpp
)

target_include_directories(packet
    PUBLIC ${JANUS_INCLUDE_DIR}
)

target_link_libraries(packet
    PUBLIC janus_logger
    PUBLIC Pcap++ Packet++ Common++ pcap
    PUBLIC tcp_handler
    PUBLIC vector_filter
)



#tcp handler
add_library(tcp_handler STATIC
    src/TcpSessionTracker.cpp
    src/TcpStreamHandler.cpp
)

target_include_directories(packet
    PUBLIC ${JANUS_INCLUDE_DIR}
)

target_link_libraries(tcp_handler
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
    PUBLIC vector_filter

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
    tcp_handler
    policy_handler
    blacklist_handler
    mnl
    netfilter_queue
    vector_filter

)
target_compile_options(janus_core PRIVATE -mavx2 -O3)


#main
add_executable(main
    main.cpp
)

target_include_directories(main
    PRIVATE ${JANUS_INCLUDE_DIR}
)

target_link_libraries(main
    PUBLIC janus_logger
    PUBLIC packet
    PUBLIC vector_filter

)

