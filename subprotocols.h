//
// Created by czn on 19/11/2019.
//
#pragma once
#include <vector>
#include <utility>

// Til at include alle subprotocol headers I guess

// Hvis subprotocols bare er metoder, er det så bedre at have en header med alle deres signaturer?
// Dette er måske fint da alle subprotokollerne skal bruges. Måske bedre kun at have lokale subprotokoller her.

// Det er til diskussion om vi skal lade mail kalde subprotokollerne, som så får de tre parties med? (eller i hvert fald kalder parties herfra).

static std::pair<bool, bool> fRand();
static std::vector<bool> fCoin();  // nok return vector af v_1, ... , v_s i stedet for void
// void compareview()  --> ved ikke om denne metode skal holdes af parties
static std::vector<bool> fPerm();
static int fReconst();
static int fShare();
static int triVerifyWithOpen();
static int triVerifyWithoutOpen();
static std::vector<bool> fTriples(int N);
//TODO: securelyCompute();
