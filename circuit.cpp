//
// Created by Laurits on 10-11-2019.
//

#include "circuit.h"
#include <fstream>


Circuit::Circuit(const std::string& filePath) {
    std::ifstream inFile;
    inFile.open(filePath);
    if(!inFile){
        std::cerr << "Unable to open file" << filePath << std::endl;
        exit(1);
    }

    int numGates, numWires, numInputs, numOutputs;
    inFile >> numGates >> numWires >> numInputs;
    wires.insert(wires.end(), numWires, false);
    int inputSize[numInputs];

    for (int i = 0; i < numInputs; i++){
        inFile >> inputSize[i];
    }

    inFile >> numOutputs;
    int outputSize[numOutputs];

    for (int i = 0; i < numOutputs; i++){
        inFile >> outputSize[i];
    }

    for (int i = 0; i < numGates; i++){
        int numGateInput, numGateOutput;
        inFile >> numGateInput >> numGateOutput;
        int gateInput[numGateInput], gateOutput[numGateOutput];
        std::string type;
        for(int j = 0; j < numGateInput; j++){
            inFile >> gateInput[j];
        }

        for(int j = 0; j < numGateOutput; j++){
            inFile >> gateOutput[j];
        }

        inFile >> type;

        if (type == "AND") {
            numberOfANDs++;
        }
        gates.emplace_back(Circuit::gate{
            type,
            gateInput[0],
            gateInput[1],
            gateOutput[0]}
            );
    }

    inFile.close();
}

std::vector<Circuit::gate> Circuit::getGates() {
    return gates;
}

std::vector<bool> Circuit::getWires() {
    return wires;
}

int Circuit::getNumberOfANDs(){
    return numberOfANDs;
}