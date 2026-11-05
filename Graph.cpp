
#include "Graph.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <queue>
#include <set>
#include <string>

// Constructor
Graph::Graph() : adjacencyList{} {
}

// Add a node
void Graph::addNode(const std::string& node) {
    if (!hasNode(node)) {
        adjacencyList.insert({node, {}});
    }
}

// Check whether a node exists
bool Graph::hasNode(const std::string& node) const {
    return adjacencyList.find(node) != adjacencyList.end();
}

// Add an undirected edge
void Graph::addEdge(
    const std::string& from,
    const std::string& to
) {
    if (!hasNode(from) || !hasNode(to)) {
        throw std::invalid_argument("Both nodes must exist");
    }

    if (from == to) {
        throw std::invalid_argument("Self-loops are not allowed");
    }

    auto& neighborsFrom = adjacencyList.at(from);
    auto& neighborsTo = adjacencyList.at(to);

    // Prevent duplicate edges
    if (std::find(
            neighborsFrom.begin(),
            neighborsFrom.end(),
            to
        ) != neighborsFrom.end()) {
        return;
    }

    neighborsFrom.push_back(to);

    try {
        neighborsTo.push_back(from);
    } catch (...) {
        neighborsFrom.pop_back();
        throw;
    }
}

// Remove an edge
void Graph::removeEdge(
    const std::string& from,
    const std::string& to
) {
    if (!hasNode(from) || !hasNode(to)) {
        return;
    }

    auto& neighborsFrom = adjacencyList.at(from);
    auto& neighborsTo = adjacencyList.at(to);

    neighborsFrom.erase(
        std::remove(
            neighborsFrom.begin(),
            neighborsFrom.end(),
            to
        ),
        neighborsFrom.end()
    );

    neighborsTo.erase(
        std::remove(
            neighborsTo.begin(),
            neighborsTo.end(),
            from
        ),
        neighborsTo.end()
    );
}

// Remove a node and all its connected edges
void Graph::removeNode(const std::string& node) {
    if (!hasNode(node)) {
        return;
    }

    for (auto& entry : adjacencyList) {
        auto& neighbors = entry.second;

        neighbors.erase(
            std::remove(
                neighbors.begin(),
                neighbors.end(),
                node
            ),
            neighbors.end()
        );
    }

    adjacencyList.erase(node);
}

// Get a node's neighbors
std::vector<std::string> Graph::getNeighbors(
    const std::string& node
) const {
    if (!hasNode(node)) {
        throw std::invalid_argument("Node does not exist");
    }

    return adjacencyList.at(node);
}

// Display graph
void Graph::printGraph() const {
    for (const auto& entry : adjacencyList) {
        std::cout << entry.first << ": ";

        for (const auto& neighbor : entry.second) {
            std::cout << neighbor << " ";
        }

        std::cout << '\n';
    }
}

// Breadth-First Search
std::vector<std::string> Graph::bfs(
    const std::string& start
) const {
    if (!hasNode(start)) {
        throw std::invalid_argument("Start node does not exist");
    }

    std::vector<std::string> traversal;
    std::queue<std::string> pending;
    std::set<std::string> visited;

    pending.push(start);
    visited.insert(start);

    while (!pending.empty()) {
        std::string current = pending.front();
        pending.pop();

        traversal.push_back(current);

        const auto& neighbors = adjacencyList.at(current);

        for (const auto& neighbor : neighbors) {
            if (visited.insert(neighbor).second) {
                pending.push(neighbor);
            }
        }
    }

    return traversal;
}

// Depth-First Search
std::vector<std::string> Graph::dfs(
    const std::string& start
) const {
    if (!hasNode(start)) {
        throw std::invalid_argument("Start node does not exist");
    }

    std::vector<std::string> traversal;
    std::set<std::string> visited;

    dfsVisit(start, visited, traversal);

    return traversal;
}

// Recursive DFS helper
void Graph::dfsVisit(
    const std::string& current,
    std::set<std::string>& visited,
    std::vector<std::string>& traversal
) const {
    visited.insert(current);
    traversal.push_back(current);

    const auto& neighbors = adjacencyList.at(current);

    for (const auto& neighbor : neighbors) {
        if (visited.find(neighbor) == visited.end()) {
            dfsVisit(neighbor, visited, traversal);
        }
    }
}

// Count nodes
std::size_t Graph::nodeCount() const {
    return adjacencyList.size();
}

// Count edges
std::size_t Graph::edgeCount() const {
    std::size_t total = 0;

    for (const auto& entry : adjacencyList) {
        total += entry.second.size();
    }

    // Each undirected edge appears twice
    return total / 2;
}

// Count a node's neighbors
std::size_t Graph::degree(
    const std::string& node
) const {
    if (!hasNode(node)) {
        throw std::invalid_argument("Node does not exist");
    }

    return adjacencyList.at(node).size();
}

// Find connected components
std::vector<std::vector<std::string>>
Graph::connectedComponents() const {
    std::vector<std::vector<std::string>> components;
    std::set<std::string> visited;

    for (const auto& entry : adjacencyList) {
        const std::string& node = entry.first;

        if (visited.find(node) != visited.end()) {
            continue;
        }

        std::vector<std::string> component = bfs(node);

        for (const auto& member : component) {
            visited.insert(member);
        }

        components.push_back(component);
    }

    return components;
}
