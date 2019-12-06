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
        std::queue<bool> *ingoingNext;
        std::queue<bool> *outgoing;
        std::queue<bool> *outgoingPrevious;
        std::mutex *inMtx;
        std::mutex *outMtx;
        std::condition_variable *inCv;
        std::condition_variable *outCv;
    };

    struct triple{
        std::pair<bool, bool> a;
        std::pair<bool, bool> b;
        std::pair<bool, bool> c;
    };

    //TODO: proper constructor signature
    Party(int partyNo, int noOfAndGates, inArgs args, Circuit* circuit, std::vector<std::pair<bool, bool>> test);

    //TODO: parametre er placeholders (ved ikke helt hvad de tager endnu)

    bool sendToNext(bool v);
    void sendToParty(int pid, bool v);
    bool receiveFromParty(int pid);
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
    std::pair<int, bool> reconstruct(int pid, std::pair<bool, bool> share);
    bool compareView(bool val);
    std::pair<bool, bool> shareSecret(int pid, bool v);
    bool verifyTripleWithOpening(triple t);


private:
    //TODO: Mangler en pseudorandom funktion (måske leg med noget fra "cryptopp/aes.h")

    CryptoPP::AutoSeededRandomPool rnd;
    CryptoPP::SecByteBlock iv;
    CryptoPP::SecByteBlock key;
    CryptoPP::SecByteBlock correlatedKey;
    std::string id;
    int partyNo;
    inArgs args;
    int noOfAndGates;
    Circuit* circuit;
    __int128_t ivIter;  //TODO: Ghetto fix
    std::vector<std::pair<bool, bool>> testShares;
    std::queue<bool> *out, *in;

};