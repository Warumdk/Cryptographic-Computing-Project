//
// Created by czn on 29/11/2019.
//

#include "party.h"
#include <math.h>
#include <ctime>
#include <exception>
#include <fstream>
#include <unistd.h>

Party::Party(int partyNo, int noOfAndGates, inArgs &args, Circuit *circuit, std::vector<bool> input) {
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
    Party::cbcEncryption = new CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption(key, key.size(),
                                                                             iv); //deterministic as IV=null

}

void Party::evaluateCircuit() {
    try {
        auto d = generateTriples();
        Circuit circuittmp = *Party::circuit;
        auto gates = circuittmp.getGates();
        auto wires = circuittmp.getWires();
        std::vector<std::pair<bool, bool>> wireShares(wires.size());
        wireShares.insert(wireShares.end(), wires.size(), {false, false});

        for (int i = 0; i < 64; ++i) {
            if(partyNo == 0){
                wireShares.at(i) = shareSecret(0, input.at(i), i);
            } else {
                wireShares.at(i) = shareSecret(0, false, i);
            }
        }

        for (int i = 0; i < 64; ++i) {
            if(partyNo == 1){
                wireShares.at(i+64) = shareSecret(1, input.at(i), i+64);
            } else {
                wireShares.at(i+64) = shareSecret(1, false, i+64);
            }
        }

        int counter = 0;
        std::vector<Party::triple> ands;
        for (const auto &gate : gates){
            if (gate.type == "XOR") {
                wireShares[gate.output] = {wireShares[gate.inputA].first ^ wireShares[gate.inputB].first,
                                           wireShares[gate.inputA].second ^ wireShares[gate.inputB].second};
            } else if (gate.type == "AND") {
                wireShares[gate.output] = secMultAnd(wireShares[gate.inputA], wireShares[gate.inputB], counter).first;
                ands.push_back(Party::triple{wireShares[gate.inputA], wireShares[gate.inputB], wireShares[gate.output]});
            } else if (gate.type == "INV") {
                wireShares[gate.output] = {wireShares[gate.inputA].first, !wireShares[gate.inputA].second};
            } else if (gate.type == "NOT") {
                wireShares[gate.output] = {wireShares[gate.inputA].first, !wireShares[gate.inputA].second};
            } else if (gate.type == "EQW") {
                wireShares[gate.output] = {wireShares[gate.inputA].first, wireShares[gate.inputA].second};
            }
            counter++;
        }
        counter = 0;
        for (const auto &andTriple : ands){
            if(!verifyTripleWithoutOpening(andTriple, d.at(counter))){
                throw "ABORT: Triple Verification Failed";
            }
            counter++;
        }
        std::vector<bool> finalOutput;
        std::vector<std::pair<bool, bool>> result(wireShares.end() - 64, wireShares.end()); //TODO: exchange -1 with number of output wires
        for (auto &res : result) {
            auto tmp = reconstruct(0, res, -1);
            if(tmp.first == 0) {
                printf("%d", tmp.second);
            }
        }
        printf("\n");

    }catch (const char *err){
        printf("%s\n", err);
    }
}


CryptoPP::SecByteBlock Party::send() {
    return Party::key;
}

void Party::receive(const CryptoPP::SecByteBlock correlatedKey) {
    Party::correlatedKey = correlatedKey;
    Party::cbcEncryptionFromPrevious = new CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption(correlatedKey,
                                                                                         correlatedKey.size(),
                                                                                         iv);
}

void Party::sendToParty(int pid, bool v, int i) {
    std::mutex* outMtx = args.outMtx;
    std::condition_variable *outCv = args.outCv;
    if (pid == (partyNo + 1) % 3) {
        Party::out = args.outgoing;
        outMtx = args.outMtx;
        outCv = args.outCv;

    } else if (pid == ((3 + partyNo - 1) % 3)) {
        Party::out = args.outgoingPrevious;
        outMtx = args.inMtx;
        outCv = args.inCv;
    }
    std::unique_lock<std::mutex> lockOut(*outMtx);
    outCv->wait(lockOut, [this]() { return Party::out->empty(); }); //wait if element not taken
    out->push({v, i});
    lockOut.unlock();
    outCv->notify_one();
}

std::pair<bool, int> Party::receiveFromParty(int pid) {
    std::mutex *inMtx = args.inMtx;
    std::condition_variable *inCv = args.inCv;
    if (pid == (partyNo + 1) % 3) {
        Party::in = args.ingoingNext;
        inMtx = args.outMtx;
        inCv = args.outCv;
    } else if (pid == ((3 + partyNo - 1) % 3)) {
        Party::in = args.ingoing;
        inMtx = args.inMtx;
        inCv = args.inCv;
    }
    std::unique_lock<std::mutex> lockIn(*inMtx);
    inCv->wait(lockIn, [this]() { return !(in->empty()); }); // wait until not empty
    std::pair<bool, int> tFromPreviousParty = in->front();
    in->pop();
    lockIn.unlock();
    inCv->notify_one();
    return tFromPreviousParty;
}

std::pair<bool, int> Party::sendToNext(bool v, int i) {
    sendToParty((partyNo + 1) % 3, v, i);
    std::pair<bool, int> tFromPreviousParty = receiveFromParty((3 + partyNo - 1) % 3);
    return tFromPreviousParty;
}

bool Party::open(std::pair<bool, bool> share) {
    bool tFromPreviousParty = sendToNext(share.first, -1).first;

    return share.second ^ tFromPreviousParty;
}

std::pair<bool, int> Party::open(std::pair<bool, bool> share, int i){
    std::pair<bool, int> tFromPreviousParty = sendToNext(share.first, i);
    return {share.second ^ tFromPreviousParty.first, tFromPreviousParty.second};
}


//Right now naively recomputes the AES every time a bit is needed for fcr1
std::pair<bool, bool> Party::cr2() {

    CryptoPP::SecByteBlock cipher = CryptoPP::SecByteBlock(16);
    CryptoPP::SecByteBlock cipherPrevious = CryptoPP::SecByteBlock(16);

    Party::cbcEncryption->ProcessData(cipher, *Party::plainText, Party::messageLen);
    Party::cbcEncryptionFromPrevious->ProcessData(cipherPrevious, *Party::plainText, Party::messageLen);

    bool lastBit = (*cipher.BytePtr()) & 1u; // Use ivIter to take the next bit in every call.
    bool lastBitPrevious = (*cipherPrevious.BytePtr()) & 1u; //TODO Fix so it is viable for larger circuits.
    return {lastBitPrevious, lastBit};
}

bool Party::cr1() {
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
std::pair<std::pair<bool, bool>, int> Party::secMultAnd(std::pair<bool, bool> v, std::pair<bool, bool> u, int i) {
    bool crand = cr1();
    bool r = (v.first & u.first) ^ (v.second & u.second) ^ crand;
    std::pair<bool, int> rPrevious = Party::sendToNext(r, i);
    bool e = r ^rPrevious.first;
    //printf("PartyNo%d: e:%d, r:%d, rp:%d, [t:%d,s:%d], [u:%d,w:%d], cr:%d\n", partyNo,e,r,rPrevious.first,v.first,v.second,u.first,u.second, crand);
    return std::make_pair(std::make_pair(e, r), rPrevious.second);
}

/**
 * Generates shares of randomly selected value
 * @return share
 */
std::pair<bool, bool> Party::rand() {
    std::pair<bool, bool> cr = cr2();
    bool t = cr.first ^cr.second;
    return std::make_pair(t, cr.second);
}

/**
 * Generates a number of bits and distributes them between the parties.
 * @param bits : number of bits to generate.
 * @return : the vector of randomly generated bits.
 */
std::vector<bool> Party::coin(int bits) {
    std::vector<std::pair<bool, bool>> vShare(bits);
    for (int i = 0; i < bits; ++i) {
        vShare.emplace_back(rand());
    }
    bool v[bits];

    for (int j = 0; j < bits; ++j) {
        std::pair<bool, int> secret = open(vShare[j], j);
        v[secret.second] = secret.first;
    }
    std::vector<bool> outVec;
    outVec.assign(v, v + bits - 1);
    if (!compareView(outVec)) {
        throw "ABORT. Coins does not match.";
    }
    return outVec;
}

bool Party::compareView(std::vector<bool> values){
    std::vector<bool> received(values.size());
    for (int i = 0; i < values.size(); ++i) {
        std::pair<bool, int> r = sendToNext(values[i], i);
        received[r.second] = r.first;
    }
    return received == values;
}

std::vector<Party::triple> Party::perm(std::vector<triple> d) {
    for (int j = 1; j < d.size(); ++j) {

        //std::printf("%d ", partyNo);
        std::vector<bool> coins = coin(ceil(log2(j + 1)));
        unsigned int i = 0;
        for (const auto &c : coins) {
            i = i << 1u | c;
        }
        //std::printf("%d ", i);
        std::swap(d[i], d[j]);
    }
    return d;
}

/**
 * Reconstructs a secret to party pid from the parties' shares.
 * @param pid : the ID of the player to reconstruct the share to
 * @param share : The shares of the value to be reconstructed
 * @return : A pair of int, bool where:
 *          int=0 indicates the player is the receiver of the reconstruction.
 *          int=1 indicates the player is a sender (and thus the value can be ignored)
 *          exception indicates an abort.
 */
std::pair<int, bool> Party::reconstruct(int pid, std::pair<bool, bool> share, int i) {
    if (pid != Party::partyNo) {
        sendToParty(pid, share.first, i);
        return {1, false};
    } else {
        auto tNext = receiveFromParty((Party::partyNo + 1) % 3);
        auto tPrevious = receiveFromParty((3 + Party::partyNo - 1) % 3);
        if (share.first == (tNext.first ^ tPrevious.first)) {
            return {0, share.second ^ tPrevious.first};
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
    bool receivedVal = sendToNext(val, -1).first;
    return val == receivedVal;
}

/**
 * Robust sharing of a secret. Party pid shares a bool with the other two parties by giving them the correct shares.
 * @param pid : The ID of the party who is sharing (i.e. the Dealer).
 * @param v : The value (bool/bit) to be shared.
 * @return : Returns the share of the shared secret.
 */
std::pair<bool, bool> Party::shareSecret(int pid, bool v, int i) {
    std::pair<bool, bool> aShare = rand();
    std::pair<int, bool> a = reconstruct(pid, aShare, i);
    bool b;
    if (a.first == 0) { //I am the one who shares
        b = a.second ^ v;
        sendToParty((pid + 1) % 3, b, i);
        sendToParty((3 + (pid - 1)) % 3, b, i);
    } else {
        b = receiveFromParty(pid).first;
    }
    if (!compareView(b)) {
        throw "ABORT. Failed to share secret. Shares not consistent.";
    }
    return {a.first, a.second ^ b}; // XOR by constant
}

//TODO: Test if this works correctly.
/**
 * Verifies a triple by opening them.
 * @param t : The triple to verify.
 * @return : True if the triple is correct, else false (notice this does not throw an exception).
 */

bool Party::verifyTripleWithOpening(Party::triple t) {
    bool a = open(t.a);
    bool b = open(t.b);
    bool c = open(t.c);
    //printf("PartyNo%d: [%d,%d|%d,%d|%d,%d] opens to [%d,%d,%d]\n", partyNo, t.a.first, t.a.second, t.b.first, t.b.second,t.c.first, t.c.second,a,b,c);
    return c == (a & b);
}

//TODO: Test if this works correctly (most likely does).
/**
 * The parties send the first part of a share and compares the received part with the second part of its own share.
 * @param share : the share to compare with the other parties.
 * @return : True if t_{j-1} received is equal to s_j.
 */
bool Party::compareView(std::pair<bool, bool> share) {
    bool receivedVal = sendToNext(share.first, -1).first;
    return share.second == receivedVal;
}


//TODO: Test if this works correctly.
/**
 * Verifies that a triple is generated correctly without opening it. It does so by using another intermediate triple.
 * This is used for the cut-and-choose method when generating triples to verify security.
 * @param xyz : The triple to verify.
 * @param abc : The auxillary triple that is used to verify xyz.
 * @return : True if the triple xyz is consistent. Else false.
 */
bool Party::verifyTripleWithoutOpening(Party::triple xyz, Party::triple abc) {
    std::pair<bool, bool> rho = std::make_pair(xyz.a.first ^ abc.a.first, xyz.a.second ^ abc.a.second);
    std::pair<bool, bool> sigma = std::make_pair(xyz.b.first ^ abc.b.first, xyz.b.second ^ abc.b.second);

    bool rhoJ = open(rho);
    bool sigmaJ = open(sigma);

    if (!compareView(rhoJ) || !compareView(sigmaJ))
        throw "ABORT. Could not verify without opening. Views not equal.";

    //TODO check if the following is correct
    std::pair<bool, bool> tmp1 = {sigmaJ & abc.a.first, sigmaJ & abc.a.second};
    std::pair<bool, bool> tmp2 = {rhoJ & abc.b.first, rhoJ & abc.b.second};
    bool tmp3 = sigmaJ & rhoJ;
    std::pair<bool, bool> tjsj = {xyz.c.first ^ abc.c.first ^ tmp1.first ^ tmp2.first,
                                  xyz.c.second ^ abc.c.second ^ tmp1.second ^ tmp2.second ^ tmp3};
    return compareView(tjsj);
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

//TODO: Check that this works
/**
 * Generates multiplication triples that are verified to be valid.
 * @param noOfAndGates : Number of AND-gates in the circuit.
 * @return d : Vector of multiplication triples that are valid.
 */
std::vector<Party::triple> Party::generateTriples() { //N = number of AND-gates.
    int N = pow(2, ceil(log(Party::noOfAndGates) / log(2)));
    std::pair<int, int> best = parameterSearch(N);
    int B = best.first;
    int C = best.second;

    int M = N * B + C;

    //random sharings
    std::vector<std::pair<std::pair<bool, bool>, std::pair<bool, bool>>> randomSharings;
    for (int i = 0; i < M; i++) {
        randomSharings.emplace_back(std::make_pair(rand(), rand()));
    }
    //semi-honest mult
    std::vector<Party::triple> D(randomSharings.size());
    for (int j = 0; j < M; ++j) {
        //std::pair<bool, bool> ciShare = secMultAnd(randomSharings[j].first, randomSharings[j].second);
        std::pair<std::pair<bool, bool>, int> ciShare = secMultAnd(randomSharings.at(j).first, randomSharings.at(j).second, j);
        //printf("PartyNo%d: ")
        //D.emplace_back(Party::triple{randomSharings[j].first, randomSharings[j].second, ciShare});
        D[ciShare.second] = Party::triple{randomSharings[ciShare.second].first, randomSharings[ciShare.second].second, ciShare.first};
    }

    //Cut-and-Bucket
    //(a)
    D = perm(D);
    //(b)
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
    for (int m = 0; m < N; ++m) {
        for (int i = 1; i < B; ++i) {
            if (!verifyTripleWithoutOpening(DBuckets[m][0], DBuckets[m][i])) {
                std::printf("%d %d %d\n", i, m, B);
                throw "ABORT. Triple verification without opening failed in cut-and-bucket";
            }
        }
        d.emplace_back(DBuckets[m][0]);
    }
    return d;
}