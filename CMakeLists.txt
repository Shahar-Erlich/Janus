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

target_include_directories(tcp_handler
    PUBLIC ${JANUS_INCLUDE_DIR}
)

target_link_libraries(tcp_handler
    PUBLIC janus_logger
    PUBLIC Pcap++ Packet++ Common++ pcap
    PUBLIC regex_engine
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

add_library(regex_engine STATIC
    src/RegexEngine.cpp
)

target_include_directories(regex_engine
    PUBLIC ${JANUS_INCLUDE_DIR}
)

# קישור ל-re2
target_link_libraries(regex_engine
    PUBLIC re2
    PUBLIC janus_logger
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
    PUBLIC regex_engine
    


)
#Aho Corasick
add_library(aho_corasick STATIC
    src/AhoCorasick.cpp
)
target_include_directories(aho_corasick 
    PUBLIC ${JANUS_INCLUDE_DIR}
)
#icd
add_library(icd_loader
    src/IcdLoader.cpp
)
target_include_directories(icd_loader
    PUBLIC ${JANUS_INCLUDE_DIR}
)

#core
add_library(janus_core
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
    aho_corasick
    icd_loader
    regex_engine
    re2
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

#main 2
add_executable(main_2
    main_2.cpp
)

target_include_directories(main_2
    PRIVATE ${JANUS_INCLUDE_DIR}
)

target_link_libraries(main_2
    PUBLIC janus_logger
    PUBLIC packet
    PUBLIC vector_filter

)

#main 3
add_executable(main_3
    main_3.cpp
)

target_include_directories(main_3
    PRIVATE ${JANUS_INCLUDE_DIR}
)

target_link_libraries(main_3
    PUBLIC janus_logger
    PUBLIC packet
    PUBLIC vector_filter

)
#janus
add_executable(janus
    src/Janus.cpp
)

target_include_directories(janus
    PRIVATE ${JANUS_INCLUDE_DIR}
)

target_link_libraries(janus
    PUBLIC janus_logger
    PUBLIC packet
    PUBLIC vector_filter
    PUBLIC janus_core
    PUBLIC policy_handler
    PUBLIC tcp_handler
    PUBLIC regex_engine
    PUBLIC re2

)
