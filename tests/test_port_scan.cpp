
#include "../PortScanDetector.h"

#include <cassert>
#include <iostream>
#include <vector>

int main() {
    PortScanDetector detector(5, 60);

    // Test 1: Five ports within four seconds
    std::vector<NetworkConnection> scanTraffic = {
        {"2026-11-04 10:32:00", "192.168.1.50",
         "192.168.1.20", 54001, 21, "TCP", 64},

        {"2026-11-04 10:32:01", "192.168.1.50",
         "192.168.1.20", 54002, 22, "TCP", 64},

        {"2026-11-04 10:32:02", "192.168.1.50",
         "192.168.1.20", 54003, 23, "TCP", 64},

        {"2026-11-04 10:32:03", "192.168.1.50",
         "192.168.1.20", 54004, 80, "TCP", 64},

        {"2026-11-04 10:32:04", "192.168.1.50",
         "192.168.1.20", 54005, 443, "TCP", 64}
    };

    auto alerts = detector.detect(scanTraffic);

    assert(alerts.size() == 1);
    assert(alerts[0].uniquePorts == 5);
    assert(alerts[0].sourceIP == "192.168.1.50");

    std::cout << "PASS: Rapid port scan detected\n";

    // Test 2: Only three distinct ports
    std::vector<NetworkConnection> normalTraffic(
        scanTraffic.begin(),
        scanTraffic.begin() + 3
    );

    assert(detector.detect(normalTraffic).empty());

    std::cout << "PASS: Below-threshold traffic ignored\n";

    // Test 3: Five ports spread over several minutes
    auto slowTraffic = scanTraffic;

    slowTraffic[1].timestamp = "2026-11-04 10:34:00";
    slowTraffic[2].timestamp = "2026-11-04 10:36:00";
    slowTraffic[3].timestamp = "2026-11-04 10:38:00";
    slowTraffic[4].timestamp = "2026-11-04 10:40:00";

    assert(detector.detect(slowTraffic).empty());

    std::cout << "PASS: Slow activity outside window ignored\n";

    std::cout << "\nAll port scan tests passed!\n";
    return 0;
}
