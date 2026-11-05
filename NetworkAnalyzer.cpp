
#include "NetworkAnalyzer.h"

#include <iostream>

void NetworkAnalyzer::addConnection(
    const NetworkConnection& connection
) {
    // Store the original traffic record
    connections.push_back(connection);

    // Add source and destination nodes
    communicationGraph.addNode(connection.sourceIP);
    communicationGraph.addNode(connection.destinationIP);

    // Build an undirected communication relationship
    if (connection.sourceIP != connection.destinationIP) {
        communicationGraph.addEdge(
            connection.sourceIP,
            connection.destinationIP
        );
    }
}

void NetworkAnalyzer::printConnections() const {
    for (const auto& connection : connections) {
        std::cout
            << connection.timestamp << " | "
            << connection.sourceIP << ":"
            << connection.sourcePort << " -> "
            << connection.destinationIP << ":"
            << connection.destinationPort << " | "
            << connection.protocol << " | "
            << connection.bytesTransferred
            << " bytes\n";
    }
}

void NetworkAnalyzer::printNetworkGraph() const {
    communicationGraph.printGraph();
}

std::size_t NetworkAnalyzer::connectionCount() const {
    return connections.size();
}



std::uint64_t NetworkAnalyzer::totalBytes() const {
    std::uint64_t total = 0;

    for (const auto& connection : connections) {
        total += connection.bytesTransferred;
    }

    return total;
}

std::map<std::string, std::size_t>
NetworkAnalyzer::protocolCounts() const {
    std::map<std::string, std::size_t> counts;

    for (const auto& connection : connections) {
        ++counts[connection.protocol];
    }

    return counts;
}

std::map<std::string, std::size_t>
NetworkAnalyzer::sourceIPCounts() const {
    std::map<std::string, std::size_t> counts;

    for (const auto& connection : connections) {
        ++counts[connection.sourceIP];
    }

    return counts;
}

std::map<std::uint16_t, std::size_t>
NetworkAnalyzer::destinationPortCounts() const {
    std::map<std::uint16_t, std::size_t> counts;

    for (const auto& connection : connections) {
        ++counts[connection.destinationPort];
    }

    return counts;
}


const std::vector<NetworkConnection>&
NetworkAnalyzer::getConnections() const {
    return connections;
}
