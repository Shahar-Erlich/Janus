cmake_minimum_required(VERSION 3.16)
project(Janus LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(JANUS_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(JANUS_SRC_DIR ${PROJECT_SOURCE_DIR}/src)

find_package(Protobuf REQUIRED)
find_package(absl REQUIRED)

# -----------------------------
# Logger
# -----------------------------
add_library(janus_logger STATIC
    ${JANUS_SRC_DIR}/Logger.cpp
)

target_include_directories(janus_logger
    PUBLIC ${JANUS_INCLUDE_DIR}
)

# -----------------------------
# Protobuf generated code
# -----------------------------
add_library(janus_proto STATIC
    ${JANUS_SRC_DIR}/janus_common.pb.cc
    ${JANUS_SRC_DIR}/janus_packet.pb.cc
)

target_include_directories(janus_proto
    PUBLIC ${JANUS_INCLUDE_DIR}
)

target_link_libraries(janus_proto
    PUBLIC
        protobuf::libprotobuf
)
add_library(rule_helper STATIC
    ${JANUS_SRC_DIR}/RuleHelper.cpp
)

target_include_directories(rule_helper
    PUBLIC ${JANUS_INCLUDE_DIR}
)

# -----------------------------
# Rule Loader
# -----------------------------
add_library(rule_loader STATIC
    ${JANUS_SRC_DIR}/RuleLoader.cpp
)

target_include_directories(rule_loader
    PUBLIC ${JANUS_INCLUDE_DIR}
)

target_link_libraries(rule_loader
    PUBLIC janus_logger
        rule_helper)


# -----------------------------
# Vector Filtering Engine
# -----------------------------
add_library(vector_filter STATIC
    ${JANUS_SRC_DIR}/VectorFilteringEngine.cpp
)

target_compile_options(vector_filter PUBLIC
    -O3
    -march=native
)

target_include_directories(vector_filter
    PUBLIC ${JANUS_INCLUDE_DIR}
)

target_link_libraries(vector_filter
    PUBLIC
        janus_logger
        Pcap++
        Packet++
        Common++
        pcap
        rule_loader
        rule_helper
)

# -----------------------------
# Regex Engine
# -----------------------------
add_library(regex_engine STATIC
    ${JANUS_SRC_DIR}/RegexEngine.cpp
)

target_include_directories(regex_engine
    PUBLIC ${JANUS_INCLUDE_DIR}
)

target_link_libraries(regex_engine
    PUBLIC
        janus_logger
        re2
        absl::raw_hash_set
        absl::hash
        absl::hashtablez_sampler
        absl::strings
        absl::base
)

# -----------------------------
# Aho Corasick
# -----------------------------
add_library(aho_corasick STATIC
    ${JANUS_SRC_DIR}/AhoCorasick.cpp
)

target_include_directories(aho_corasick
    PUBLIC ${JANUS_INCLUDE_DIR}
)

target_link_libraries(aho_corasick
    PUBLIC janus_logger
)


# -----------------------------
# TCP handler
# -----------------------------
add_library(tcp_handler STATIC
    ${JANUS_SRC_DIR}/TcpSessionTracker.cpp
    ${JANUS_SRC_DIR}/TcpStreamHandler.cpp
)

target_include_directories(tcp_handler
    PUBLIC ${JANUS_INCLUDE_DIR}
)

target_link_libraries(tcp_handler
    PUBLIC
        janus_logger
        janus_proto
        regex_engine
        aho_corasick
        vector_filter
        Pcap++
        Packet++
        Common++
        pcap
)

# -----------------------------
# Packet / parser
# -----------------------------
add_library(packet STATIC
    ${JANUS_SRC_DIR}/PcapParser.cpp
)

target_include_directories(packet
    PUBLIC ${JANUS_INCLUDE_DIR}
)

target_link_libraries(packet
    PUBLIC
        tcp_handler
        vector_filter
        Pcap++
        Packet++
        Common++
        pcap
)

# -----------------------------
# Blacklist
# -----------------------------
add_library(blacklist_handler STATIC
    ${JANUS_SRC_DIR}/BlacklistHandler.cpp
)

target_include_directories(blacklist_handler
    PUBLIC ${JANUS_INCLUDE_DIR}
)

target_link_libraries(blacklist_handler
    PUBLIC
        janus_logger
        packet
)

# -----------------------------
# Policy
# -----------------------------
add_library(policy_handler STATIC
    ${JANUS_SRC_DIR}/PacketPolicy.cpp
)

target_include_directories(policy_handler
    PUBLIC ${JANUS_INCLUDE_DIR}
)

target_link_libraries(policy_handler
    PUBLIC
        janus_logger
        janus_proto
        packet
        blacklist_handler
        vector_filter
        regex_engine
        aho_corasick
        rule_loader
)


# -----------------------------
# Core
# -----------------------------
add_library(janus_core STATIC
    ${JANUS_SRC_DIR}/Core.cpp
    ${JANUS_SRC_DIR}/SystemEventSender.cpp
)

target_include_directories(janus_core
    PUBLIC ${JANUS_INCLUDE_DIR}
)

target_compile_options(janus_core PRIVATE
    -mavx2
    -O3
)

target_link_libraries(janus_core
    PUBLIC
        janus_logger
        janus_proto
        packet
        tcp_handler
        policy_handler
        blacklist_handler
        vector_filter
        aho_corasick
        rule_loader
        regex_engine
        mnl
        netfilter_queue
)

# -----------------------------
# main
# -----------------------------
add_executable(main
    ${PROJECT_SOURCE_DIR}/main.cpp
)

target_include_directories(main
    PRIVATE ${JANUS_INCLUDE_DIR}
)

target_link_libraries(main
    PUBLIC
        janus_logger
        packet
        vector_filter
)

# -----------------------------
# main_2
# -----------------------------
add_executable(main_2
    ${PROJECT_SOURCE_DIR}/main_2.cpp
)

target_include_directories(main_2
    PRIVATE ${JANUS_INCLUDE_DIR}
)

target_link_libraries(main_2
    PUBLIC
        janus_logger
        packet
        vector_filter
)

# -----------------------------
# main_3
# -----------------------------
add_executable(main_3
    ${PROJECT_SOURCE_DIR}/main_3.cpp
)

target_include_directories(main_3
    PRIVATE ${JANUS_INCLUDE_DIR}
)

target_link_libraries(main_3
    PUBLIC
        janus_logger
        packet
        vector_filter
)

# -----------------------------
# Janus executable
# -----------------------------
add_executable(janus
    ${JANUS_SRC_DIR}/Janus.cpp
)

target_include_directories(janus
    PRIVATE ${JANUS_INCLUDE_DIR}
)

target_link_libraries(janus
    PUBLIC
        janus_logger
        janus_core
        packet
        vector_filter
        policy_handler
        tcp_handler
        regex_engine
        janus_proto
)



# -----------------------------
# bench_mix_sender
# -----------------------------
add_executable(bench_mix_sender
    ${PROJECT_SOURCE_DIR}/bench_mix_sender.cpp
)

target_compile_features(bench_mix_sender PUBLIC cxx_std_20)

target_include_directories(bench_mix_sender
    PRIVATE ${JANUS_INCLUDE_DIR}
)

target_link_libraries(bench_mix_sender
    PUBLIC
        janus_logger
)

#### 64,groups before, add blacklist to web,research more filtering fields in header