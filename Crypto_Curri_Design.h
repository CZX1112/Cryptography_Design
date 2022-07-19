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

//���ɼ���ָ��b
ZZ b_Generation(ZZ phi_n);

//���ɽ���ָ��a��phi_n*x+b*y=1,b:����ָ����y:����ָ��a
void Extend_Euclidean(ZZ a, ZZ b, ZZ& x, ZZ& y);

//RSA��������x���õ�����y
ZZ RSA_Encrypt(ZZ x, ZZ b, ZZ n);

//RSA��������y���õ�����x
ZZ RSA_Decrypt(ZZ y, ZZ a, ZZ n);

//���Լ���㷨
bool MillerRabin(const ZZ& n, long t);

//�����������
void Prime_Generation(ZZ& p, ZZ& q, int length, ULL Seed, ULL Key1, ULL Key2);

//ANSI����������㷨
ZZ ANSI(ULL s, int m, ULL k1, ULL k2);