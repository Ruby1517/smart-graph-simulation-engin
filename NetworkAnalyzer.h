
#pragma once

#include "Graph.h"
#include "NetworkConnection.h"

#include <vector>
#include <map>
#include <string>
#include <cstdint>
#include <cstddef>


class NetworkAnalyzer {
private:
    Graph communicationGraph;
    std::vector<NetworkConnection> connections;

public:

    //Traffic statistics
    std::uint64_t totalBytes() const;

    std::map<std::string, std::size_t>
    protocolCounts() const;

    std::map<std::string, std::size_t>
    sourceIPCounts() const;

    std::map<std::uint16_t, std::size_t>
    destinationPortCounts() const;

    void addConnection(const NetworkConnection& connection);

    void printConnections() const;

    void printNetworkGraph() const;

    std::size_t connectionCount() const;

    // Allow read-only access to traffic records
    const std::vector<NetworkConnection>& getConnections() const;
};
