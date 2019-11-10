//
// Created by Laurits on 10-11-2019.
//

#ifndef CRYPTOGRAPHIC_COMPUTING_CIRCUIT_H
#define CRYPTOGRAPHIC_COMPUTING_CIRCUIT_H

#include <iostream>
#include <vector>

class Circuit {
public:
    explicit Circuit(const std::string& filePath);

    struct gate {
        std::string type;
        int inputA;
        int inputB;
        int output;
    };
    std::vector<bool> getWires();
    std::vector<gate> getGates();
private:
    std::vector<bool> wires;
    std::vector<gate> gates;
};


#endif //CRYPTOGRAPHIC_COMPUTING_CIRCUIT_H
