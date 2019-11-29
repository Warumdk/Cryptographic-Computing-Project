//
// Created by Laurits on 10-11-2019.
//
#pragma once
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
