#pragma once

#include <string>
#include "BigNum.h"

class SRP6 {
public:
    SRP6(BigNum N, BigNum g, BigNum s, BigNum B, std::string username, std::string password);
    SRP6(BigNum N, BigNum g, BigNum s, BigNum B, std::string username, std::string password, BigNum a);

    BigNum calculate_session_key();
    BigNum calculate_proof();

private:
    void calculate_private_ephemeral();
    void calculate_public_ephemeral();
    void calculate_x();
    void calculate_u();
    void calculate_S();
    void calculate_interleaved();
    unsigned char* calculate_xor_hash();
    unsigned char* calculate_username_hash();

    BigNum a, k;
    BigNum N, g, B, s;
    BigNum x, u, K, A, S, M;
    std::string username, password;
};
