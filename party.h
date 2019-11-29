//
// Created by czn on 19/11/2019.
//

#pragma once
#include "cryptopp/osrng.h"
#include "cryptopp/secblock.h"
#include <queue>
#include <vector>

#include <mutex>
#include <condition_variable>


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

    //TODO: proper constructor signature
    Party(std::string id, int noOfAndGates, inArgs args);

    //TODO: parametre er placeholders (ved ikke helt hvad de tager endnu)

    bool send(bool v);
    std::pair<bool, bool> send(bool v1, bool v2);
    CryptoPP::SecByteBlock send(CryptoPP::SecByteBlock key);
    void receive(bool v1, bool v2);
    void receive(bool v);
    void receive(CryptoPP::SecByteBlock correlatedKey);

    void open(std::pair<bool, bool> share);
    std::vector<int> compareview(std::vector<int>);


private:
    //TODO: Mangler en pseudorandom funktion (måske leg med noget fra "cryptopp/aes.h")
    //int PRF();

    CryptoPP::AutoSeededRandomPool rnd;
    CryptoPP::SecByteBlock key;
    CryptoPP::SecByteBlock correlatedKey;
    std::string id;
    int secParam;
    inArgs args;
    std::vector<bool> v;
    


};