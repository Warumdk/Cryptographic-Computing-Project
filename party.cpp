//
// Created by czn on 23/11/2019.
//

#include "party.h"
#include <cmath>
#include <ctime>
#include <exception>
#include <fstream>
#include <unistd.h>

Party::Party(int partyNo, int noOfAndGates, queues &args, Circuit *circuit, std::vector<bool> input) {
    Party::input = input;
    Party::partyNo = partyNo;
    Party::circuit = circuit;
    Party::args = args;
    Party::noOfAndGates = noOfAndGates;
    Party::key = CryptoPP::SecByteBlock(0x00, CryptoPP::AES::DEFAULT_KEYLENGTH); //default keylength 128 bits
    Party::rnd.GenerateBlock(Party::key, Party::key.size());

    std::string stringIv = "6G5LI5m5em1BiDIQ";
    Party::iv = CryptoPP::SecByteBlock(reinterpret_cast<const CryptoPP::byte *>(&stringIv[0]), stringIv.size());
    Party::id = "AGLtdP9NzXOYUGbb";

    Party::plainText = new CryptoPP::SecByteBlock(reinterpret_cast<const CryptoPP::byte *>(&Party::id[0]),
                                                  Party::id.size());
    Party::messageLen = Party::plainText->size() + 1;
    Party::cbcEncryption = new CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption(key, key.size(),
                                                                             iv);

}

void Party::evaluateCircuit() {
    try {

        auto then = std::chrono::high_resolution_clock::now();
        auto d = generateTriples();

        auto now = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - then);
        std::cout << partyNo << " Triple: " << duration.count() << " ";

        Circuit circuittmp = *Party::circuit;
        auto gates = circuittmp.getGates();
        auto wires = circuittmp.getWires();
        std::vector<share> wireShares;
        wireShares.insert(wireShares.end(), wires.size(), {false, false});

        for (int i = 0; i < 128; ++i) {
            if(partyNo == 0){
                wireShares.at(i) = shareSecret(0, input.at(i));
            } else {
                wireShares.at(i) = shareSecret(0, false);
            }
        }

        for (int i = 0; i < 128; ++i) {
            if(partyNo == 1){
                wireShares.at(i+128) = shareSecret(1, input.at(i));
            } else {
                wireShares.at(i+128) = shareSecret(1, false);
            }
        }

        for (int i = 0; i < 128; ++i) {
            if(partyNo == 2){
                wireShares.at(i+256) = shareSecret(2, input.at(i));
            } else {
                wireShares.at(i+256) = shareSecret(2, false);
            }
        }


        int counter = 0;
        std::vector<Party::triple> ands;
        for (const auto &gate : gates){
            if (gate.type == "XOR") {
                wireShares[gate.output] = wireShares[gate.inputA] ^ wireShares[gate.inputB];
            } else if (gate.type == "AND") {
                wireShares[gate.output] = secMultAnd(wireShares[gate.inputA], wireShares[gate.inputB]);
                ands.push_back(Party::triple{wireShares[gate.inputA], wireShares[gate.inputB], wireShares[gate.output]});
            } else if (gate.type == "INV") {
                wireShares[gate.output] = !wireShares[gate.inputA];
            } else if (gate.type == "NOT") {
                wireShares[gate.output] = !wireShares[gate.inputA];
            } else if (gate.type == "EQW") {
                wireShares[gate.output] = wireShares[gate.inputA];
            }
            counter++;
        }
        counter = 0;
        std::string view, viewNext;
        for (const auto &andTriple : ands){
            share temp = verifyTripleWithoutOpening(andTriple, d.at(counter));
            view += temp.s ? "1" : "0";
            viewNext += temp.t ? "1" : "0";
            counter++;
        }
        CryptoPP::SHA256 hash;
        std::string viewHash, nextViewHash;
        CryptoPP::StringSource s1(view, true, new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(viewHash)));
        CryptoPP::StringSource s2(viewNext, true, new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(nextViewHash)));
        args.sendHashToNext->enqueue(nextViewHash);
        std::string receivedHash;
        args.receiveHashFromPrevious->wait_dequeue(receivedHash);
        if (receivedHash != viewHash) {
            throw "ABORT. Triple verification without opening failed in cut-and-bucket";
        }

        std::vector<share> result(wireShares.end() - 128, wireShares.end());
        for (auto &res : result) {
            auto tmp = reconstruct(0, res);
            if(tmp.first == 0) {
                printf("%d", tmp.second);
            }
        }

    }catch (const char *err){
        printf("%s\n", err);
    }
}


CryptoPP::SecByteBlock Party::send() {
    return Party::key;
}

void Party::receive(const CryptoPP::SecByteBlock correlatedKey) {
    Party::cbcEncryptionFromPrevious = new CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption(correlatedKey,
                                                                                         correlatedKey.size(),
                                                                                         iv);
}

void Party::sendToParty(int pid, bool v) {
    if (pid == (partyNo + 1) % 3) {
        args.sendToNext->enqueue(v);
    } else if (pid == ((3 + partyNo - 1) % 3)) {
        args.sendToPrevious->enqueue(v);
    }
}

bool Party::receiveFromParty(int pid) {
    bool t;
    if (pid == (partyNo + 1) % 3) {
        args.receiveFromNext->wait_dequeue(t);
    } else if (pid == ((3 + partyNo - 1) % 3)) {
        args.receiveFromPrevious->wait_dequeue(t);
    }
    return t;
}

bool Party::sendToNext(bool v) {
    sendToParty((partyNo + 1) % 3, v);
    bool tFromPreviousParty = receiveFromParty((3 + partyNo - 1) % 3);
    return tFromPreviousParty;
}

bool Party::open(share v) {
    bool tFromPreviousParty = sendToNext(v.t);

    return v.s ^ tFromPreviousParty;
}

//Right now naively recomputes the AES every time a bit is needed for fcr1
Party::share Party::cr2() {
    if (bits == 128) {
        CryptoPP::SecByteBlock cipher = CryptoPP::SecByteBlock(16);
        CryptoPP::SecByteBlock cipherPrevious = CryptoPP::SecByteBlock(16);

        Party::cbcEncryption->ProcessData(cipher, *Party::plainText, Party::messageLen);
        Party::cbcEncryptionFromPrevious->ProcessData(cipherPrevious, *Party::plainText, Party::messageLen);
        ci.Decode(cipher.BytePtr(), cipher.SizeInBytes());
        cj.Decode(cipherPrevious.BytePtr(), cipherPrevious.SizeInBytes());
        bits = 0;
    }
    bool lastBit = ci.GetBit(bits);
    bool lastBitPrevious = cj.GetBit(bits);
    bits++;
    return {lastBitPrevious, lastBit};
}

bool Party::cr1() {
    Party::share cr2Res = cr2();
    return cr2Res.t ^ cr2Res.s;
}

/**
 * Securely evalues AND-gates in a semi-honest manner.
 * @param v : share of first value (t,s)
 * @param u : share of second value (u,w)
 * @return : pair (e,f)
 */

Party::share Party::secMultAnd(share v, share u) {
    bool crand = cr1();
    bool r = (v.t && u.t) != (v.s && u.s) != crand;
    bool rPrevious = Party::sendToNext(r);
    bool e = r ^rPrevious;
    return share{e, r};
}

/**
 * Generates shares of randomly selected value
 * @return share
 */
Party::share Party::rand() {
    share cr = cr2();
    bool t = cr.t ^cr.s;
    return share{t, cr.s};
}

/**
 * Generates a number of bits and distributes them between the parties.
 * @param bits : number of bits to generate.
 * @return : the vector of randomly generated bits.
 */
std::vector<bool> Party::coin(int bits) {
    std::vector<share> vShare;
    for (int i = 0; i < bits; ++i) {
        vShare.push_back(rand());
    }
    std::vector<bool> v;

    for (int j = 0; j < bits; ++j) {
        bool secret = open(vShare[j]);
        v.push_back(secret);
    }

    for(const auto& val : v){
        if(!compareView(val)){
            throw "ABORT. Coins does not match.";
        }
    }
    return v;
}

std::vector<Party::triple> Party::perm(std::vector<triple> d) {
    std::string temp;
    std::vector<bool> coins = coin(256);
    for (const auto &c : coins) {
        temp +=  c ? "1" : "0";
    }
    CryptoPP::SecByteBlock seed = CryptoPP::SecByteBlock(reinterpret_cast<const CryptoPP::byte *>(&temp[0]), temp.size());
    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption prng;
    prng.SetKeyWithIV(seed, 16, seed+16, 16);
    for (unsigned long j = 1; j < d.size(); ++j) {
        CryptoPP::SecByteBlock t(log2(j));
        prng.GenerateBlock(t, t.size());
        CryptoPP::Integer i;
        i.Decode(t.BytePtr(), t.SizeInBytes());
        std::swap(d[i.ConvertToLong()% d.size()], d[j]);
    }
    return d;
}

/**
 * Reconstructs a secret to party pid from the parties' shares.
 * @param pid : the ID of the player to reconstruct the share to
 * @param v : The shares of the value to be reconstructed
 * @return : A pair of int, bool where:
 *          int=0 indicates the player is the receiver of the reconstruction.
 *          int=1 indicates the player is a sender (and thus the value can be ignored)
 *          exception indicates an abort.
 */
std::pair<int, bool> Party::reconstruct(int pid, share v) {
    if (pid != Party::partyNo) {
        sendToParty(pid, v.t);
        return {1, false};
    } else {
        bool tNext = receiveFromParty((Party::partyNo + 1) % 3);
        bool tPrevious = receiveFromParty((3 + Party::partyNo - 1) % 3);
        if (v.t == (tNext ^ tPrevious)) {
            return {0, v.s ^ tPrevious};
        } else {
            throw "ABORT. Reconstruction failed. Shares do not match.";
        }
    }
}

/** The parties send a value val to the next party and compare that the one sent is the same as the one received.
 * @param val : The value to be compare
 * @return : True if the value received from previous party is the same as the one sent to the next party.
 */
bool Party::compareView(bool val) {
    bool receivedVal = sendToNext(val);
    return val == receivedVal;
}

/**
 * Robust sharing of a secret. Party pid shares a bool with the other two parties by giving them the correct shares.
 * @param pid : The ID of the party who is sharing (i.e. the Dealer).
 * @param v : The value (bool/bit) to be shared.
 * @return : Returns the share of the shared secret.
 */
Party::share Party::shareSecret(int pid, bool v) {
    Party::share aShare = rand();
    std::pair<int, bool> a = reconstruct(pid, aShare);
    bool b;
    if (a.first == 0) { //I am the one who shares
        b = a.second != v;
        sendToParty((pid + 1) % 3, b);
        sendToParty((3 + (pid - 1)) % 3, b);
    } else {
        b = receiveFromParty(pid);
    }
    if (!compareView(b)) {
        throw "ABORT. Failed to share secret. Shares not consistent.";
    }
    return aShare^b; // XOR by constant
}

/**
 * Verifies a triple by opening them.
 * @param t : The triple to verify.
 * @return : True if the triple is correct, else false (notice this does not throw an exception).
 */

bool Party::verifyTripleWithOpening(Party::triple t) {
    bool a = open(t.a);
    bool b = open(t.b);
    bool c = open(t.c);
    return c == (a & b);
}

/**
 * The parties send the first part of a share and compares the received part with the second part of its own share.
 * @param v : the share to compare with the other parties.
 * @return : True if t_{j-1} received is equal to s_j.
 */
bool Party::compareView(share v) {
    bool receivedVal = sendToNext(v.t);
    return v.s == receivedVal;
}

/**
 * Verifies that a triple is generated correctly without opening it. It does so by using another intermediate triple.
 * This is used for the cut-and-choose method when generating triples to verify security.
 * @param xyz : The triple to verify.
 * @param abc : The auxillary triple that is used to verify xyz.
 * @return : True if the triple xyz is consistent. Else false.
 */
Party::share Party::verifyTripleWithoutOpening(Party::triple xyz, Party::triple abc) {
    Party::share rho = share{xyz.a.t != abc.a.t, xyz.a.s != abc.a.s};
    Party::share sigma = share{xyz.b.t != abc.b.t, xyz.b.s != abc.b.s};

    bool rhoJ = open(rho);
    bool sigmaJ = open(sigma);

    if (!compareView(rhoJ) || !compareView(sigmaJ))
        throw "ABORT. Could not verify without opening. Views not equal.";

    Party::share tmp1 = share{sigmaJ && abc.a.t, sigmaJ && abc.a.s};
    Party::share tmp2 = share{rhoJ && abc.b.t, rhoJ && abc.b.s};
    bool tmp3 = sigmaJ & rhoJ;
    Party::share tjsj = share{xyz.c.t != abc.c.t != tmp1.t != tmp2.t,
                                  xyz.c.s != abc.c.s != tmp1.s != tmp2.s != tmp3};
    return tjsj;
}

/**
 * Finds the best values for B and C (while compromising on the security). This is necessary as high security is not
 * possible for small values of N.
 * @param N :
 * @return
 */
std::pair<int, int> parameterSearch(int N) {
    int sigma = 80;
    int B = 1;
    int C;
    int bestB = 2;
    int bestC = 1;
    double currentBest = 0;
    do {
        B++;
        C = N / (int) pow(B, 2);
        if (C == 0) {
            break;
        }
        if (N != C * pow(B, 2)) {
            continue;
        }
        if ((B - 1) * log2(C) > currentBest || ((B - 1) * log2(C) == currentBest && B < bestB)) {
            currentBest = (B - 1) * log2(C);
            bestB = B;
            bestC = C;
        }
    } while ((B - 1) * log2(C) <= sigma);
    return {bestB, bestC};
}

int improvedParamSearch(int N){
    int sigma = 80;
    int B = 1;
    double result = 0;
    do {
        result = log2(exp(lgamma(N * B + B) - (log(N) + lgamma(B) + lgamma(N * B))));
        B ++;
    }while (result < sigma);
    return B-1;
}

/**
 * Generates multiplication triples that are verified to be valid.
 * @param noOfAndGates : Number of AND-gates in the circuit.
 * @return d : Vector of multiplication triples that are valid.
 */
std::vector<Party::triple> Party::generateTriples() { //N = number of AND-gates.

    int N = Party::noOfAndGates;
    int B = improvedParamSearch(N);
    int C = B;
    int M = N * B + C;
    //random sharings
    std::vector<std::pair<share, share>> randomSharings;
    for (int i = 0; i < M; i++) {
        randomSharings.emplace_back(std::make_pair(rand(), rand()));
    }

    //semi-honest mult
    std::vector<Party::triple> D(randomSharings.size());
    for (int j = 0; j < M; ++j) {
        share ciShare = secMultAnd(randomSharings.at(j).first, randomSharings.at(j).second);
        D[j] = Party::triple{randomSharings[j].first, randomSharings[j].second, ciShare};
    }
    D = perm(D);

    for (int k = 0; k < C; ++k) {
        if (!verifyTripleWithOpening(D[k])) {
            throw "ABORT. Triple verification failed in Cut-and-bucket. ";
        }
    }

    D.erase(D.begin(), D.begin() + C); //Erase the triples that were used to check
    //(c)
    std::vector<std::vector<Party::triple>> DBuckets(N);
    for (int l = 0; l < N; ++l) {
        for (int i = 0; i < B; ++i) {
            DBuckets.at(l).emplace_back(D.back());
            D.pop_back();
        }
    }
    //check-buckets
    std::vector<Party::triple> d;
    std::string view, viewNext;
    for (int m = 0; m < N; ++m) {
        for (int i = 1; i < B; ++i) {
            share temp = verifyTripleWithoutOpening(DBuckets[m][0], DBuckets[m][i]);
            view += temp.s ? "1" : "0";
            viewNext += temp.t ? "1" : "0";
        }
        d.emplace_back(DBuckets[m][0]);
    }
    CryptoPP::SHA256 hash;
    std::string viewHash, nextViewHash;
    CryptoPP::StringSource s1(view, true, new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(viewHash)));
    CryptoPP::StringSource s2(viewNext, true, new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(nextViewHash)));
    args.sendHashToNext->enqueue(nextViewHash);
    std::string receivedHash;
    args.receiveHashFromPrevious->wait_dequeue(receivedHash);
    if (receivedHash != viewHash) {
        throw "ABORT. Triple verification without opening failed in cut-and-bucket";
    }

    return d;
}

