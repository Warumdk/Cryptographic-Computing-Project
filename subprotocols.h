//
// Created by czn on 19/11/2019.
//
#pragma once
#include <vector>
#include <pair>

// Til at include alle subprotocol headers I guess

// Hvis subprotocols bare er metoder, er det så bedre at have en header med alle deres signaturer?
// Dette er måske fint da alle subprotokollerne skal bruges. Måske bedre kun at have lokale subprotokoller her.

// Det er til diskussion om vi skal lade mail kalde subprotokollerne, som så får de tre parties med? (eller i hvert fald kalder parties herfra).

std::pair<bool, bool> fRand();
std::vector<bool> fCoin();  // nok return vector af v_1, ... , v_s i stedet for void
// void compareview()  --> ved ikke om denne metode skal holdes af parties
std::vector<bool> fPerm();
int fReconst();
int fShare();
int triVerifyWithOpen();
int triVerifyWithoutOpen();
std::vector<bool> fTriples(int N);
//TODO: securelyCompute();
