//
// Created by czn on 19/11/2019.
//

#pragma once
#include "cryptopp/osrng.h"
#include "cryptopp/secblock.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "circuit.h"
#include "readerwriterqueue.h"
#include <queue>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <thread>


//Generate key by init new SecByteBlock and use it as first argument to AutoSeededRandomPool.GenerateBlock
class Party {
public:
    struct queues{
        moodycamel::BlockingReaderWriterQueue<bool> *receiveFromPrevious;
        moodycamel::BlockingReaderWriterQueue<bool> *receiveFromNext;
        moodycamel::BlockingReaderWriterQueue<bool> *sendToNext;
        moodycamel::BlockingReaderWriterQueue<bool> *sendToPrevious;
        moodycamel::BlockingReaderWriterQueue<std::string> *sendHashToNext;
        moodycamel::BlockingReaderWriterQueue<std::string> *receiveHashFromPrevious;
    };

    struct share{
        bool t;
        bool s;

        share operator^(const share& other) const{
            return share{t != other.t, s != other.s};
        };

        share operator*(const bool& other) const {
            return share{t && other, s && other};
        };

        share operator^(const bool& other) const {
            return share{t, s != other};
        };

        share operator!() const {
            return share{t, !s};
        };
    };



    struct triple {
        share a;
        share b;
        share c;
    };

    //TODO: proper constructor signature
    Party(int partyNo, int noOfAndGates, queues &args, Circuit* circuit, std::vector<bool> input);

    bool sendToNext(bool v);
    void sendToParty(int pid, bool v);
    bool receiveFromParty(int pid);
    CryptoPP::SecByteBlock send();
    void receive(CryptoPP::SecByteBlock correlatedKey);
    bool open(share v);

    share secMultAnd(share v, share u);
    bool cr1();
    share cr2();
    share rand();
    std::vector<bool> coin(int bits);
    std::vector<triple> perm(std::vector<triple> d);
    void evaluateCircuit();
    std::pair<int, bool> reconstruct(int pid, share v);
    bool compareView(bool val);
    bool compareView(share v);
    share shareSecret(int pid, bool v);
    bool verifyTripleWithOpening(triple t);
    share verifyTripleWithoutOpening(Party::triple xyz, Party::triple abc);
    std::vector<Party::triple> generateTriples();


private:
    CryptoPP::AutoSeededRandomPool rnd;
    CryptoPP::SecByteBlock iv;
    CryptoPP::SecByteBlock key;
    std::string id;
    int partyNo;
    queues args;
    int noOfAndGates;
    Circuit* circuit;
    std::vector<bool> input;

    CryptoPP::SecByteBlock *plainText;
    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption *cbcEncryption, *cbcEncryptionFromPrevious;
    size_t messageLen;
    int bits = 128;
};