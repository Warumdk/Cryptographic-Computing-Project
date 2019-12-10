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
        std::queue<std::pair<bool, int>> *ingoing;
        std::queue<std::pair<bool, int>> *ingoingNext;
        std::queue<std::pair<bool, int>> *outgoing;
        std::queue<std::pair<bool, int>> *outgoingPrevious;
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
    Party(int partyNo, int noOfAndGates, inArgs &args, Circuit* circuit, std::vector<std::pair<bool, bool>> test);

    std::pair<bool, int> sendToNext(bool v, int i);
    void sendToParty(int pid, bool v, int i);
    std::pair<bool, int> receiveFromParty(int pid);
    CryptoPP::SecByteBlock send();
    void receive(const CryptoPP::SecByteBlock correlatedKey);
    bool open(std::pair<bool, bool> share);
    std::pair<bool, int> open(std::pair<bool, bool> share, int i);

    std::pair<std::pair<bool, bool>, int> secMultAnd(std::pair<bool, bool> v, std::pair<bool, bool> u, int i);
    bool cr1();
    std::pair<bool, bool> cr2();
    std::pair<bool, bool> rand();
    std::vector<bool> coin(int bits);
    std::vector<triple> perm(std::vector<triple> d);
    void evaluateCircuit();
    std::pair<int, bool> reconstruct(int pid, std::pair<bool, bool> share);
    bool compareView(bool val);
    bool compareView(std::vector<bool> values);
    bool compareView(std::pair<bool, bool> share);
    std::pair<bool, bool> shareSecret(int pid, bool v);
    bool verifyTripleWithOpening(triple t);
    bool verifyTripleWithoutOpening(Party::triple xyz, Party::triple abc);
    std::vector<Party::triple> generateTriples();


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
    std::vector<std::pair<bool, bool>> testShares;
    std::queue<std::pair<bool, int>> *out, *in;

    CryptoPP::SecByteBlock *plainText;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption *cbcEncryption, *cbcEncryptionFromPrevious;
    size_t messageLen;

};