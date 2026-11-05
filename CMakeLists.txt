
cmake_minimum_required(VERSION 3.16)

project(SmartGraphSimulationEngine
    VERSION 1.0
    LANGUAGES CXX
)

# Use C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Shared project code
add_library(graph_core
    Graph.cpp
    NetworkAnalyzer.cpp
    TrafficCSVReader.cpp
    PortScanDetector.cpp
)

target_include_directories(graph_core
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
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
    
endif()
