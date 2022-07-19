#include "Crypto_Curri_Design.h"

//���ɼ���ָ��b
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

//���ɽ���ָ��a��phi_n*x+b*y=1,b:����ָ����y:����ָ��a
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

//RSA��������x���õ�����y
ZZ RSA_Encrypt(ZZ x, ZZ b, ZZ n)
{
	ZZ y;
	y = PowerMod(x, b, n);
	return y;
}

//RSA��������y���õ�����x
ZZ RSA_Decrypt(ZZ y, ZZ a, ZZ n)
{
	ZZ x;
	x = PowerMod(y, a, n);
	return x;
}