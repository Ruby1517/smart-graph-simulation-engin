
#pragma once

#include <map>
#include <vector>
#include <set>
#include <string>
#include <cstddef>

class Graph {
private:
    // Node -> list of connected neighbors
    std::map<std::string, std::vector<std::string>> adjacencyList;

    // Private DFS helper
    void dfsVisit(
        const std::string& current,
        std::set<std::string>& visited,
        std::vector<std::string>& traversal
    ) const;

public:
    // Constructor
    Graph();

    // Modify graph
    void addNode(const std::string& node);
    void removeNode(const std::string& node);

    void addEdge(
        const std::string& from,
        const std::string& to
    );

    void removeEdge(
        const std::string& from,
        const std::string& to
    );

    // Read graph
    bool hasNode(const std::string& node) const;

    std::vector<std::string> getNeighbors(
        const std::string& node
    ) const;

    // Graph traversal
    std::vector<std::string> bfs(
        const std::string& start
    ) const;

    std::vector<std::string> dfs(
        const std::string& start
    ) const;

    // Graph analytics
    std::size_t nodeCount() const;
    std::size_t edgeCount() const;

    std::size_t degree(
        const std::string& node
    ) const;

    std::vector<std::vector<std::string>>
    connectedComponents() const;

    // Display graph
    void printGraph() const;
};
