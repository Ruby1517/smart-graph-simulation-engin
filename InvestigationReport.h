
#pragma once

#include "NetworkAnalyzer.h"
#include "PortScanDetector.h"
#include "GeoAnalyzer.h"

#include <string>
#include <vector>

class InvestigationReport {
public:
    void exportText(
        const std::string& filename,
        const NetworkAnalyzer& analyzer,
        const std::vector<PortScanAlert>& alerts,
        const GeoAnalyzer& geoAnalyzer
    ) const;
};
