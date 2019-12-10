//
// Created by czn on 29/11/2019.
//

#include "party.h"
#include <math.h>
#include <ctime>
#include <exception>

Party::Party(int partyNo, int noOfAndGates, inArgs args, Circuit *circuit, std::vector<std::pair<bool, bool>> test) {

    Party::testShares = test;

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
    /*
    std::vector<bool> tmpres = coin(4);
    for (const auto &res : tmpres){
        std::printf("%d ", (bool) res);
    }
    std::printf("\n");

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
    std::vector<std::pair<bool, bool>> result(wireShares.end() - 1, wireShares.end()); //TODO: exchange -1 with number of output wires
    std::vector<bool> finalOutput(1);
    for (auto &res : result){
        //finalOutput.emplace_back(open(res));
        std::printf("%d\n", (bool) open(res));
    }
    */


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

void Party::sendToParty(int pid, bool v) {
    std::mutex *outMtx;
    std::condition_variable *outCv;
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
    outCv->wait(lockOut, [this]() { return Party::out->size() < 1; }); //wait if element not taken
    out->push(v);
    lockOut.unlock();
    outCv->notify_one();
}

bool Party::receiveFromParty(int pid) {
    std::mutex *inMtx;
    std::condition_variable *inCv;
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
    bool tFromPreviousParty = in->front();
    in->pop();
    lockIn.unlock();
    inCv->notify_one();
    return tFromPreviousParty;
}

bool Party::sendToNext(bool share) {
    sendToParty((partyNo + 1) % 3, share);
    bool tFromPreviousParty = receiveFromParty((3 + partyNo - 1) % 3);
    return tFromPreviousParty;
}

bool Party::open(std::pair<bool, bool> share) {
    bool tFromPreviousParty = sendToNext(share.first);

    return share.second ^ tFromPreviousParty;
}

//Right now naively recomputes the AES every time a bit is needed for fcr1
std::pair<bool, bool> Party::cr2() {

    CryptoPP::SecByteBlock cipher = CryptoPP::SecByteBlock(16);
    CryptoPP::SecByteBlock cipherPrevious = CryptoPP::SecByteBlock(16);

    Party::cbcEncryption->ProcessData(cipher, *Party::plainText, Party::messageLen);
    Party::cbcEncryptionFromPrevious->ProcessData(cipherPrevious, *Party::plainText, Party::messageLen);

    bool lastBit = (*cipher.BytePtr()) & 1; // Use ivIter to take the next bit in every call.
    bool lastBitPrevious = (*cipherPrevious.BytePtr()) & 1; //TODO Fix so it is viable for larger circuits.
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
std::pair<bool, bool> Party::secMultAnd(std::pair<bool, bool> v, std::pair<bool, bool> u) {
    bool r = (v.first & u.first) ^(v.second & u.second) ^cr1();
    bool rPrevious = Party::sendToNext(r);
    bool e = r ^rPrevious;
    return {e, r};
}

/**
 * Generates shares of randomly selected value
 * @return share
 */
std::pair<bool, bool> Party::rand() {
    std::pair<bool, bool> cr = cr2();
    bool t = cr.first ^cr.second;
    return {t, cr.second};
}

/**
 * Generates a number of bits and distributes them between the parties.
 * @param bits : number of bits to generate.
 * @return : the vector of randomly generated bits.
 */
std::vector<bool> Party::coin(int bits) {
    std::vector<std::pair<bool, bool>> vShare;
    for (int i = 0; i < bits; ++i) {
        vShare.emplace_back(rand());
    }
    std::vector<bool> v;

    for (const auto &share : vShare) {
        bool secret = open(share);
        v.emplace_back(secret);
        if (!compareView(secret)) {
            throw "ABORT. Coins does not match.";
        }
    }
    return v;
}

std::vector<Party::triple> Party::perm(std::vector<triple> d) {
    for (int j = 1; j < d.size(); ++j) {
        std::vector<bool> coins = coin(ceil(log2(j)));
        int i = 0u;
        for (const auto &c : coins) {
            i = i << 1 | c;
        }
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
std::pair<int, bool> Party::reconstruct(int pid, std::pair<bool, bool> share) {
    if (pid != Party::partyNo) {
        sendToParty(pid, share.first);
        return {1, false};
    } else {
        bool tNext = receiveFromParty((Party::partyNo + 1) % 3);
        bool tPrevious = receiveFromParty((3 + Party::partyNo - 1) % 3);
        if (share.first == (tNext ^ tPrevious)) {
            return {0, share.second ^ tPrevious};
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
std::pair<bool, bool> Party::shareSecret(int pid, bool v) {
    std::pair<bool, bool> aShare = rand();
    std::pair<int, bool> a = reconstruct(pid, aShare);
    bool b;
    if (a.first == 0) { //I am the one who shares
        b = a.second ^ v;
        sendToParty((pid + 1) % 3, b);
        sendToParty((3 + (pid - 1)) % 3, b);
    } else {
        b = receiveFromParty(pid);
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
    return c == (a & b);
}

//TODO: Test if this works correctly (most likely does).
/**
 * The parties send the first part of a share and compares the received part with the second part of its own share.
 * @param share : the share to compare with the other parties.
 * @return : True if t_{j-1} received is equal to s_j.
 */
bool Party::compareView(std::pair<bool, bool> share) {
    bool receivedVal = sendToNext(share.first);
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
    std::pair<bool, bool> rho = {xyz.a.first ^ abc.a.first, xyz.a.second ^ abc.a.second};
    std::pair<bool, bool> sigma = {xyz.b.first ^ abc.b.first, xyz.b.second ^ abc.b.second};

    bool rhoJ = open(rho);
    bool sigmaJ = open(sigma);

    compareView(rhoJ);
    compareView(sigmaJ);

    //TODO check if the following is correct
    std::pair<bool, bool> tmp1 = {sigmaJ & abc.a.first, sigmaJ & abc.a.second};
    std::pair<bool, bool> tmp2 = {rhoJ & abc.b.first, rhoJ & abc.b.second};
    bool tmp3 = sigmaJ & rhoJ;
    std::pair<bool, bool> tjsj = {xyz.c.first ^ abc.c.first ^ tmp1.first ^ tmp2.first,
                                  xyz.c.second ^ abc.c.second ^ tmp1.second ^ tmp2.second ^ tmp3};
    return compareView(tjsj);
}

//TODO: Check that this works
/**
 * Generates multiplication triples that are verified to be valid.
 * @param noOfAndGates : Number of AND-gates in the circuit.
 * @return d : Vector of multiplication triples that are valid.
 */
 /*
std::vector<Party::triple> Party::generateTriples(int noOfAndGates) { //N = number of AND-gates.
    int N = pow(2, ceil(log(noOfAndGates) / log(2)));;
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
    int M = N * bestB + bestC;

    //random sharings
    std::vector<std::pair<bool, bool>, std::pair<bool, bool>> randomSharings(2 * M);
    for (int i = 0; i < M; i += 2) {
        randomSharings.emplace_back({rand(), rand()});
    }
    //semi-honest mult
    std::vector<Party::triple> D(2 * M);
    for (int j = 0; j < M; ++j) {
        std::pair<bool, bool> ciShare = secMultAnd(randomSharings[j].first, randomSharings[j].second);
        D.emplace_back({randomSharings[j].first, randomSharings[j].second, ciShare})
    }

    //Cut-and-Bucket
    //(a)
    D = perm(D);
    //(b)
    for (int k = 0; k < bestC; ++k) {
        if (!verifyTripleWithOpening(D[k])) {
            throw "ABORT. Triple verification failed in Cut-and-bucket";
        }
    }
    D.erase(D.begin(), D.begin() + bestC); //Erase the triples that were used to check
    //(c)
    std::vector<std::vector<Party::triple>> DBuckets(N);
    for (int l = 0; l < N; ++l) {
        for (int i = 0; i < bestB; ++i) {
            DBuckets[l].emplace_back(D.back());
            D.pop_back();
        }
        std::cout << "Bucket size: " << std::size(DBuckets[l]) << std::endl;
    }

    //check-buckets
    std::vector<Party::triple> d(N);
    for (int m = 0; m < N; ++m) {
        for (int i = 1; i < bestB; ++i) {
            if (!verifyTripleWithoutOpening(DBuckets[m][0], DBuckets[m][i])) {
                throw "ABORT. Triple verification without opening failed in cut-and-bucket";
            }
        }
        d.emplace_back(DBuckets[m][0]);
    }
    return d;

}
*/