#include <string>
#include "BigNum.h"

BigNum::BigNum() {
    bn = BN_new();
}

BigNum::BigNum(const unsigned char* data, int length){
    bn = BN_new();

    from_bin(data, length);
}

BigNum::BigNum(const char* data){
    bn = BN_new();

    from_dec(data);
}

BigNum BigNum::from_bin(const unsigned char* data, int length){
    BN_lebin2bn(data, length, bn);

    return *this;
}

unsigned char* BigNum::to_bin(int length) {
    unsigned char* temp;
    temp = new unsigned char[length];

    BN_bn2lebinpad(bn, temp, length);

    return temp;
}

BigNum BigNum::from_dec(const char* data){
    BN_dec2bn(&bn, data);

    return *this;
}

std::string BigNum::to_dec() {
    char* dec_str = BN_bn2dec(bn);
    std::string result(dec_str);
    OPENSSL_free(dec_str);
    return result;
}

BigNum BigNum::from_hex(const char* data){
    BN_hex2bn(&bn, data);

    return *this;
}

char* BigNum::to_hex(){
    char* temp;
    temp = BN_bn2hex(bn);

    return temp;
}

BigNum BigNum::operator+(const BigNum &b) {
    BigNum temp;

    BN_add(temp.bn, bn, b.bn);

    return temp;
}

BigNum BigNum::operator-(const BigNum &b) {
    BigNum temp;

    BN_sub(temp.bn, bn, b.bn);

    return temp;
}

BigNum BigNum::operator*(const BigNum &b) {
    BigNum temp;

    BN_CTX* temp_ctx = BN_CTX_new();
    BN_mul(temp.bn, bn, b.bn, temp_ctx);
    BN_CTX_free(temp_ctx);

    return temp;
}

BigNum BigNum::operator/(const BigNum &b) {
    BigNum temp;

    BN_CTX* temp_ctx = BN_CTX_new();
    BN_div(temp.bn, nullptr, bn, b.bn, temp_ctx);
    BN_CTX_free(temp_ctx);

    return temp;
}

BigNum& BigNum::operator=(const BigNum &b) {
    bn = b.bn;

    return *this;
}

BigNum BigNum::mod_exp(const BigNum &b, const BigNum &c) {
    BigNum temp;

    BN_CTX* temp_ctx = BN_CTX_new();
    BN_mod_exp(temp.bn, bn, b.bn, c.bn, temp_ctx);
    BN_CTX_free(temp_ctx);

    return temp;
}

void BigNum::randomize(int bytes_amount) {
    BN_rand(bn, bytes_amount * 8, 0, 1);
}
