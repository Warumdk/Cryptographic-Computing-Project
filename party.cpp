//
// Created by czn on 29/11/2019.
//

#include "party.h"
std::condition_variable cv;

Party::Party(std::string id, int noOfAndGates, inArgs args) {
    Party::id = id;
    Party::args = args;

}
bool Party::send(bool v){
    return v;
}
std::pair<bool, bool> Party::send(bool v1, bool v2){
    return std::pair<bool, bool> (v1, v2);
}
CryptoPP::SecByteBlock Party::send(CryptoPP::SecByteBlock correlatedKey){
    return Party::key;
}

void Party::receive(bool v){}
void Party::receive(bool v1, bool v2){}
void Party::receive(CryptoPP::SecByteBlock correlatedKey){
    Party::correlatedKey = correlatedKey;
}

void Party::open(std::pair<bool, bool> share){
    args.outgoing->push(share.first);
    std::unique_lock<std::mutex> lockIn(*Party::args.inMtx);
    std::unique_lock<std::mutex> lockOut(*Party::args.outMtx);
    args.outCv->notify_one();
    args.inCv->wait(lockIn);
    args.outCv->notify_one(); //Might be unnecessary.

    bool tFromPreviousParty = args.ingoing->front();
    args.ingoing->pop();

    //Add v to vector.
    Party::v.emplace_back(share.second ^ tFromPreviousParty);
}
