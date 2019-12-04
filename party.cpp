//
// Created by czn on 29/11/2019.
//

#include "party.h"
#include <math.h>

Party::Party(int noOfAndGates, inArgs args, Circuit circuit) {
    Party::args = args;

    Party::key = CryptoPP::SecByteBlock(0x00, CryptoPP::AES::DEFAULT_KEYLENGTH); //default keylength 128 bits
    Party::rnd.GenerateBlock(Party::key, Party::key.size());

    std::string stringIv = "6G5LI5m5em1BiDIQ";
    Party::iv = CryptoPP::SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(&stringIv[0]), stringIv.size());
    Party::id = "AGLtdP9NzXOYUGbb";
}

CryptoPP::SecByteBlock Party::send(){
    return Party::key;
}

void Party::receive(const CryptoPP::SecByteBlock correlatedKey){
    Party::correlatedKey = correlatedKey;
    std::cout << rand().first << std::endl;
    std::cout << rand().second << std::endl;
}

bool Party::sendToNext(bool share){
    args.outgoing->push(share);
    std::unique_lock<std::mutex> lockIn(*args.inMtx);
    std::unique_lock<std::mutex> lockOut(*args.outMtx);
    args.outCv->notify_one();
    args.inCv->wait(lockIn);
    args.outCv->notify_one(); //Might be unnecessary.
    bool tFromPreviousParty = args.ingoing->front();
    args.ingoing->pop();
    return tFromPreviousParty;
}

bool Party::open(std::pair<bool, bool> share) {
    bool tFromPreviousParty = sendToNext(share.first);

    return share.second ^ tFromPreviousParty;
}

//Right now naively recomputes the AES every time a bit is needed for fcr1
std::pair<bool, bool> Party::cr2(){
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
    bool lastBit = (*cipher.BytePtr()) & 1;
    bool lastBitPrevious = (*cipherPrevious.BytePtr()) & 1;

    return {lastBit, lastBitPrevious};

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
    std::vector<std::pair<bool, bool>> vShare(bits);
    for (int i = 0; i < bits; ++i) {
        vShare.emplace_back(rand());
    }
    std::vector<bool> v(bits);
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

