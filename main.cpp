#include <iostream>
#include "circuit.h"

std::vector<bool> intToBoolVector(__int128 in, int bits){
    std::vector<bool> temp;
    temp.reserve(bits);
    for (int i = 0; i < bits; ++i) {
        temp.push_back((in >> i) & 1);
    }
    return temp;
}

__int128_t boolVectorToInt(std::vector<bool> in, int bits){
    __int128_t out = 0;
    for (int i = bits-1; i > 0; --i) {
        if(in.back()) {
            out |= 1 << i;
        }
        in.pop_back();
    }
    return out;
}

void test64BitAdderLocally(int64_t in1, int64_t in2){
    auto test = Circuit("adder64.txt");
    auto wires = test.getWires();
    auto gates = test.getGates();

    auto in1BoolVector = intToBoolVector(in1, 64);
    auto in2BoolVector = intToBoolVector(in2, 64);

    auto last = std::copy(std::begin(in1BoolVector), std::end(in1BoolVector), std::begin(wires));
    std::copy(std::begin(in2BoolVector), std::end(in2BoolVector), last);

    for (auto const &gate: gates) {
        if (gate.type == "XOR") {
            wires[gate.output] = wires[gate.inputA] ^ wires[gate.inputB];
        } else if (gate.type == "AND") {
            wires[gate.output] = wires[gate.inputA] & wires[gate.inputB];
        } else if (gate.type == "INV") {
            wires[gate.output] = !wires[gate.inputA];
        } else if (gate.type == "EQ") {
            wires[gate.output] = gate.inputA;
        } else if (gate.type == "NOT") {
            wires[gate.output] = !wires[gate.inputA];
        } else if (gate.type == "EQW") {
            wires[gate.output] = wires[gate.inputA];
        }
    }

    std::vector<bool> result(wires.end() - 64, wires.end());
    std::cout <<  (int64_t) boolVectorToInt(result, 64) << std::endl;
}

int main() {
   test64BitAdderLocally(5001, 201331);
}

