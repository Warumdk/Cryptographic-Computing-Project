#include <iostream>
#include "circuit.h"
#include "party.h"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <cstdlib>
#include <chrono>

std::vector<bool> intToBoolVector(__int128_t in, int bits){
    std::vector<bool> temp;
    temp.reserve(bits);
    for (int i = 0; i < bits; ++i) {
        temp.push_back((in >> i) & 1);
    }
    return temp;
}

__int128_t boolVectorToInt(std::vector<bool> in, int bits){
    __int128_t out = 0;
    for (int i = bits-1; i >= 0; --i) {
        if(in.at(i)) {
            out |= 1 << i;
        }
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

    // Cannot currently print 128bit ints that is why the 64bit cast is there
    std::cout <<  (int64_t) boolVectorToInt(result, 32) << std::endl;
}

void fcrSetup(Party &p1, Party &p2, Party &p3){
    p1.receive(p3.send());
    p2.receive(p1.send());
    p3.receive(p2.send());
}

int main() {
    auto *circuit = new Circuit("50KANDs.txt");
    moodycamel::BlockingReaderWriterQueue<bool> p1p2Queue, p2p3Queue, p3p1Queue, p1p3Queue, p2p1Queue, p3p2Queue;
    //CryptoPP::byte id[] = "AGLtdP9NzXOYUGbb";

    Party::queues args1 = {&p3p1Queue, &p2p1Queue, &p1p2Queue, &p1p3Queue};
    Party::queues args2 = {&p1p2Queue, &p3p2Queue, &p2p3Queue, &p2p1Queue};
    Party::queues args3 = {&p2p3Queue, &p1p3Queue, &p3p1Queue, &p3p2Queue};



    Party p1(0, circuit->getNumberOfANDs(), args1, circuit, intToBoolVector(1, 1));
    Party p2(1, circuit->getNumberOfANDs(), args2, circuit, intToBoolVector(0, 1));
    Party p3(2, circuit->getNumberOfANDs(), args3, circuit, {});

    //Share keys
    fcrSetup(p1, p2, p3);

    auto then = std::chrono::high_resolution_clock::now();
    std::thread t1(&Party::evaluateCircuit, &p1);
    std::thread t2(&Party::evaluateCircuit, &p2);
    std::thread t3(&Party::evaluateCircuit, &p3);

    t1.join();
    t2.join();
    t3.join();
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - then);
    std::cout << std::endl << duration.count();
}
