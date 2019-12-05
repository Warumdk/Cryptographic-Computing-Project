//
// Created by czn on 29/11/2019.
//

#include "party.h"
#include <math.h>
#include <ctime>

Party::Party(std::string partyNo, int noOfAndGates, inArgs args, Circuit* circuit) {
    Party::partyNo = partyNo;
    Party::ivIter = 1;
    Party::circuit = circuit;
    Party::args = args;
    Party::noOfAndGates = noOfAndGates;
    Party::key = CryptoPP::SecByteBlock(0x00, CryptoPP::AES::DEFAULT_KEYLENGTH); //default keylength 128 bits
    Party::rnd.GenerateBlock(Party::key, Party::key.size());

    std::string stringIv = "6G5LI5m5em1BiDIQ";
    Party::iv = CryptoPP::SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(&stringIv[0]), stringIv.size());
    Party::id = "AGLtdP9NzXOYUGbb";
}

void Party::evaluateCircuit(){

    std::vector<bool> tmpres = coin(5);
    for (const auto &res : tmpres){
        std::printf("%d ", (bool) res);
    }
    std::printf("\n");

    /*
    Circuit circuittmp = *Party::circuit;
    auto gates = circuittmp.getGates();
    auto wires = circuittmp.getWires();
    std::vector<std::pair<bool, bool>> wireShares(wires.size());
    wireShares.insert(wireShares.end(), wires.size(), {false, true});

    for (const auto &gate : gates){
        if (gate.type == "XOR") {
            wireShares[gate.output] = {wireShares[gate.inputA].first ^ wireShares[gate.inputB].first,
                                       wireShares[gate.inputA].second ^ wireShares[gate.inputB].second};
        } else if (gate.type == "AND") {
            wireShares[gate.output] = secMultAnd(wireShares[gate.inputA], wireShares[gate.inputB]);
        } else if (gate.type == "INV") {
            wireShares[gate.output] = {wireShares[gate.inputA].first, !wireShares[gate.inputA].second};
        } else if (gate.type == "NOT") {
            wireShares[gate.output] = {wireShares[gate.inputA].first, !wireShares[gate.inputA].second};
        } else if (gate.type == "EQW") {
            wireShares[gate.output] = {wireShares[gate.inputA].first, wireShares[gate.inputA].second};
        }
    }
    std::vector<std::pair<bool, bool>> result(wireShares.end() - 64, wireShares.end());
    std::vector<bool> finalOutput(64);
    for (auto &res : result){
        //finalOutput.emplace_back(open(res));
        std::printf("%d\n", (bool) open(res));
    }
     */

}


CryptoPP::SecByteBlock Party::send(){
    return Party::key;
}

void Party::receive(const CryptoPP::SecByteBlock correlatedKey){
    Party::correlatedKey = correlatedKey;
}

bool Party::sendToNext(bool share){

    std::unique_lock<std::mutex> lockOut(*args.outMtx);
    args.outCv->wait(lockOut, [this]() {return args.outgoing->size() < 1;}); //wait if element not taken
    args.outgoing->push(share);
    lockOut.unlock();
    args.outCv->notify_one();

    std::unique_lock<std::mutex> lockIn(*args.inMtx);
    args.inCv->wait(lockIn, [this]() {return !(args.ingoing->empty());}); // wait until not empty
    bool tFromPreviousParty = args.ingoing->front();
    args.ingoing->pop();
    lockIn.unlock();
    args.inCv->notify_one();
    return tFromPreviousParty;
}

bool Party::open(std::pair<bool, bool> share) {
    bool tFromPreviousParty = sendToNext(share.first);

    return share.second ^ tFromPreviousParty;
}

//Right now naively recomputes the AES every time a bit is needed for fcr1
std::pair<bool, bool> Party::cr2(){
    /*
    CryptoPP::SecByteBlock newIv(CryptoPP::AES::BLOCKSIZE);
    rnd.GenerateBlock(newIv, newIv.size());
    Party::iv = newIv;
    */
    // Calculate F function
    CryptoPP::SecByteBlock cipher = CryptoPP::SecByteBlock(16);
    CryptoPP::SecByteBlock cipherPrevious = CryptoPP::SecByteBlock(16);

    CryptoPP::SecByteBlock plainText = CryptoPP::SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(&Party::id[0]), Party::id.size());
    size_t messageLen = std::size(plainText) + 1;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cbcEncryption(key, key.size(), iv); //deterministic as IV=null
    cbcEncryption.ProcessData(cipher, plainText, messageLen);

    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cbcEncryptionFromPrevious(correlatedKey, correlatedKey.size(), iv); //deterministic as IV=null
    cbcEncryptionFromPrevious.ProcessData(cipherPrevious, plainText, messageLen);

    // naïve
    bool lastBit = (*cipher.BytePtr()) & Party::ivIter; // Use ivIter to take the next bit in every call.
    bool lastBitPrevious = (*cipherPrevious.BytePtr()) & Party::ivIter; //TODO Fix so it is viable for larger circuits.
    Party::ivIter *= 2;
    return {lastBitPrevious, lastBit};

    //return lastBit lastBitPrevious; //Probably works.
}
bool Party::cr1(){
    std::pair<bool, bool> cr2Res = cr2();
    return cr2Res.first ^ cr2Res.second;
}

/**
 * Securely evalues AND-gates in a semi-honest manner.
 * @param v : share of first value (t,s)
 * @param u : share of second value (u,w)
 * @return : pair (e,f)
 */
 //TODO check whether this protocol as described in section 2.2 is the same one used in the active version.
std::pair<bool, bool> Party::secMultAnd(std::pair<bool, bool> v, std::pair<bool, bool> u){
    bool r = (v.first & u.first) ^ (v.second & u.second) ^ cr1();
    bool rPrevious = Party::sendToNext(r);
    bool e = r ^ rPrevious;
    return {e, r};
}
/**
 * Generates shares of randomly selected value
 * @return share
 */
std::pair<bool, bool> Party::rand(){
    std::pair<bool, bool> cr = cr2();
    bool t = cr.first ^ cr.second;
    return {t, cr.second};
}

/**
 * Generates a number of bits and distributes them between the parties.
 * @param bits : number of bits to generate.
 * @return : the vector of randomly generated bits.
 */
std::vector<bool> Party::coin(int bits){
    std::vector<std::pair<bool, bool>> vShare;
    for (int i = 0; i < bits; ++i) {
        vShare.emplace_back(rand());
    }
    std::vector<bool> v;

    for (const auto &share : vShare) {
        v.emplace_back(open(share));
    }
    //TODO compareView()
    return v;
}

std::vector<Party::triple> Party::perm(std::vector<triple> d){
    for (int j = 1; j < d.size(); ++j) {
        std::vector<bool> coins = coin(ceil(log2(j)));
        int i = 0u;
        for (const auto &c : coins){
            i = i << 1 | c;
        }
        std::swap(d[i], d[j]);
    }
    return d;
}

