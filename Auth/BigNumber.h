/*
 * This file is part of the CMaNGOS Project. See AUTHORS file for Copyright information
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _AUTH_BIGNUMBER_H
#define _AUTH_BIGNUMBER_H

#include <vector>
#include <cstdint>

struct bignum_st;

class BigNumber
{
    public:
        BigNumber();
        BigNumber(const BigNumber& bn);
        BigNumber(uint32_t);
        ~BigNumber();

        void SetDword(uint32_t);
        void SetQword(uint64_t);
        void SetBinary(const uint8_t* bytes, int len);
        int SetHexStr(const char* str);

        void SetRand(int numbits);

        BigNumber& operator=(const BigNumber& bn);

        BigNumber& operator+=(const BigNumber& bn);
        BigNumber operator+(const BigNumber& bn)
        {
            BigNumber t(*this);
            return t += bn;
        }
        BigNumber& operator-=(const BigNumber& bn);
        BigNumber operator-(const BigNumber& bn)
        {
            BigNumber t(*this);
            return t -= bn;
        }
        BigNumber& operator*=(const BigNumber& bn);
        BigNumber operator*(const BigNumber& bn)
        {
            BigNumber t(*this);
            return t *= bn;
        }
        BigNumber& operator/=(const BigNumber& bn);
        BigNumber operator/(const BigNumber& bn)
        {
            BigNumber t(*this);
            return t /= bn;
        }
        BigNumber& operator%=(const BigNumber& bn);
        BigNumber operator%(const BigNumber& bn)
        {
            BigNumber t(*this);
            return t %= bn;
        }

        bool isZero() const;

        BigNumber ModExp(const BigNumber& bn1, const BigNumber& bn2);
        BigNumber Exp(const BigNumber&);

        int GetNumBytes(void) const;

        struct bignum_st* BN() { return _bn; }

        uint32_t AsDword() const;
        std::vector<uint8_t> AsByteArray(int minSize = 0, bool reverse = true) const;

        const char* AsHexStr() const;
        const char* AsDecStr() const;

    private:
        struct bignum_st* _bn;
        uint8_t* _array;
};
#endif
