#include "Crypto_Curri_Design.h"

//生成加密指数b
ZZ b_Generation(ZZ phi_n)
{
	srand(time(0));
	ZZ b;
	while (1)
	{
		b = rand();
		if (GCD(b, phi_n) == 1)
			break;
	}
	return b;
}

//生成解密指数a：phi_n*x+b*y=1,b:加密指数，y:解密指数a
void Extend_Euclidean(ZZ a, ZZ b, ZZ& x, ZZ& y)
{
	ZZ m = to_ZZ(0), n = to_ZZ(1), t;
	x = 1, y = 0;
	while (b != to_ZZ(0))
	{
		t = m, m = x - a / b * m, x = t;
		t = n, n = y - a / b * n, y = t;
		t = b, b = a % b, a = t;
	}
}

//RSA加密明文x，得到密文y
ZZ RSA_Encrypt(ZZ x, ZZ b, ZZ n)
{
	ZZ y;
	y = PowerMod(x, b, n);
	return y;
}

//RSA解密密文y，得到明文x
ZZ RSA_Decrypt(ZZ y, ZZ a, ZZ n)
{
	ZZ x;
	x = PowerMod(y, a, n);
	return x;
}