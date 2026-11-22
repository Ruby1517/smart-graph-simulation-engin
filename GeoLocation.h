
#pragma once

#include <string>

struct GeoLocation {
    std::string ipAddress;
    std::string country;
    std::string city;

    double latitude = 0.0;
    double longitude = 0.0;

    bool located = false;
};
