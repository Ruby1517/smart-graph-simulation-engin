
cmake_minimum_required(VERSION 3.16)

project(SmartGraphSimulationEngine
    VERSION 1.0
    LANGUAGES CXX
)

# Use C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

# Shared project code
add_library(graph_core
    Graph.cpp
    NetworkAnalyzer.cpp
    TrafficCSVReader.cpp
    PortScanDetector.cpp
    ZeekLogReader.cpp
    GeoAnalyzer.cpp
    InvestigationReport.cpp
    EvidenceHasher.cpp
    EvidenceSnapshot.cpp
)

target_include_directories(graph_core
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(graph_core
    PRIVATE OpenSSL::Crypto
)

# Compiler warnings
if(MSVC)
    target_compile_options(graph_core PRIVATE /W4)
else()
    target_compile_options(graph_core PRIVATE
        -Wall -Wextra -pedantic
    )
endif()

# Main application
add_executable(graph main.cpp)

target_link_libraries(graph
    PRIVATE graph_core
)

# Enable automated testing
include(CTest)

if(BUILD_TESTING)
    add_executable(test_port_scan
        tests/test_port_scan.cpp
    )

    target_link_libraries(test_port_scan
        PRIVATE graph_core
    )

    add_test(
        NAME PortScanDetection
        COMMAND test_port_scan
    )

    add_executable(test_csv_reader
        tests/test_csv_reader.cpp
    )

    target_link_libraries(test_csv_reader
        PRIVATE graph_core
    )

    add_test(
        NAME CSVReaderValidation
        COMMAND test_csv_reader
    )

    add_executable(test_geo_analyzer
        tests/test_geo_analyzer.cpp
    )

    target_link_libraries(test_geo_analyzer
        PRIVATE graph_core
    )

    add_test(
        NAME GeoAnalyzerValidation
        COMMAND test_geo_analyzer
    )

    add_executable(test_investigation_report
        tests/test_investigation_report.cpp
    )

    target_link_libraries(test_investigation_report
        PRIVATE graph_core
    )

    add_test(
        NAME InvestigationReportValidation
        COMMAND test_investigation_report
    )

    add_executable(test_evidence_hasher
        tests/test_evidence_hasher.cpp
    )

    target_link_libraries(test_evidence_hasher
        PRIVATE graph_core
    )

    add_test(
        NAME EvidenceHasherValidation
        COMMAND test_evidence_hasher
    )

    add_executable(test_evidence_snapshot
        tests/test_evidence_snapshot.cpp
    )

    target_link_libraries(test_evidence_snapshot
        PRIVATE graph_core
    )

    add_test(
        NAME EvidenceSnapshotValidation
        COMMAND test_evidence_snapshot
    )
endif()
