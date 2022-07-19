#include "Crypto_Curri_Design.h"

//素性检测算法
bool MillerRabin(const ZZ& n, long t)
{
	ZZ x;
	long i;
	bool flag = true;
	for (i = 0; i < t; i++)
	{
		x = RandomBnd(n);
		ZZ m, y, z;
		long j, k;
		if (x == 0)
			flag = true;
		else
		{
			k = 1;
			m = n / 2;
			while (m % 2 == 0)
			{
				k++;
				m /= 2;
			}
			z = PowerMod(x, m, n); // z = x^m % n
			if (z == 1)
				flag = true;
			else
			{
				j = 0;
				do {
					y = z;
					z = (y * y) % n;
					j++;
				} while (j < k && z != 1);
				if (z != 1 || y != n - 1)
					flag = false;
			}
		}

		if (flag == false)
			return false;
	}
	return flag;
}

//生成随机素数
void Prime_Generation(ZZ& p, ZZ& q, int length, ULL Seed, ULL Key1, ULL Key2)
{
	cout << "开始生成" << length << "bits的素数p，q" << endl;
	double Time = clock();
	while (1)
	{
		p = ANSI(Seed, length / 64, Key1, Key2);
		if (p % 2 == 0)
			p += 1;
		if (MillerRabin(p, length))
			break;
	}
	cout << "p = " << p << endl;
	while (1)
	{
		q = ANSI(Seed, length / 64, Key1, Key2);
		if (q % 2 == 0)
			q += 1;
		if (MillerRabin(q, length))
			break;
	}
	cout << "q = " << q << endl;
	Time = (clock() - Time) / 1000;
	cout << "生成的p，q通过素性检测, 用时 " << Time << 's';
	cout << endl;
}