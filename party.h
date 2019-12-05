//
// Created by czn on 19/11/2019.
//

#pragma once
#include "cryptopp/osrng.h"
#include "cryptopp/secblock.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "circuit.h"
#include <queue>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <thread>


//Generate key by init new SecByteBlock and use it as first argument to AutoSeededRandomPool.GenerateBlock
class Party {
public:
    struct inArgs{
        std::queue<bool> *ingoing;
        std::queue<bool> *outgoing;
        std::mutex *inMtx;
        std::mutex *outMtx;
        std::condition_variable *inCv;
        std::condition_variable *outCv;
    };

    struct triple{
        bool a;
        bool b;
        bool c;
    };

    //TODO: proper constructor signature
    Party(std::string partyNo, int noOfAndGates, inArgs args, Circuit* circuit);

    //TODO: parametre er placeholders (ved ikke helt hvad de tager endnu)

    bool sendToNext(bool v);
    CryptoPP::SecByteBlock send();
    void receive(const CryptoPP::SecByteBlock correlatedKey);
    std::vector<int> compareview(std::vector<int>);
    bool open(std::pair<bool, bool> share);

    std::pair<bool, bool> secMultAnd(std::pair<bool, bool> v, std::pair<bool, bool> u);
    bool cr1();
    std::pair<bool, bool> cr2();
    std::pair<bool, bool> rand();
    std::vector<bool> coin(int bits);
    std::vector<triple> perm(std::vector<triple> d);
    void evaluateCircuit();


private:
    //TODO: Mangler en pseudorandom funktion (måske leg med noget fra "cryptopp/aes.h")
    //int PRF();

    CryptoPP::AutoSeededRandomPool rnd;
    CryptoPP::SecByteBlock iv;
    CryptoPP::SecByteBlock key;
    CryptoPP::SecByteBlock correlatedKey;
    std::string id, partyNo;
    inArgs args;
    int noOfAndGates;
    Circuit* circuit;
    int ivIter;

};