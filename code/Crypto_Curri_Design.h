#pragma once
#include <iostream>
#include <time.h>
#include "AES.h"
#include "DES.h"
#include <fstream>
#include <NTL/ZZ.h>

using namespace std;

using namespace NTL;

typedef unsigned long long ULL;

void CBC_Encrypt(AES& aes, ZZ& IV, ifstream& fin, ofstream& fout);

void CBC_Decrypt(ZZ& IV, ifstream& fin, ofstream& fout, ZZ k_de);

//生成加密指数b
ZZ b_Generation(ZZ phi_n);

//生成解密指数a：phi_n*x+b*y=1,b:加密指数，y:解密指数a
void Extend_Euclidean(ZZ a, ZZ b, ZZ& x, ZZ& y);

//RSA加密明文x，得到密文y
ZZ RSA_Encrypt(ZZ x, ZZ b, ZZ n);

//RSA解密密文y，得到明文x
ZZ RSA_Decrypt(ZZ y, ZZ a, ZZ n);

//素性检测算法
bool MillerRabin(const ZZ& n, long t);

//生成随机素数
void Prime_Generation(ZZ& p, ZZ& q, int length, ULL Seed, ULL Key1, ULL Key2);

//ANSI随机数生成算法
ZZ ANSI(ULL s, int m, ULL k1, ULL k2);