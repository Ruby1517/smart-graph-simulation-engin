
#include "NetworkAnalyzer.h"
#include "ProtocolUtils.h"

#include <iostream>

void NetworkAnalyzer::addConnection(
    const NetworkConnection& connection
) {

    // Create a copy for normalization    
    NetworkConnection normalized = connection;

    normalized.protocol =
        normalizeProtocol(connection.protocol);

    // Store the normalized traffic record
    connections.push_back(normalized);

    //Add source and destination IPs to the graph
    communicationGraph.addNode(normalized.sourceIP);
    communicationGraph.addNode(normalized.destinationIP);

    //Add and undirected edge between source and destination IPs if they are different
    if (normalized.sourceIP != normalized.destinationIP) {
        communicationGraph.addEdge(
            normalized.sourceIP,
            normalized.destinationIP
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
