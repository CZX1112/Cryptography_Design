#include "Crypto_Curri_Design.h"
#include <windows.h>

//��ȡϵͳ�ĵ�ǰʱ�䣬��λ΢��(us)
ULL GetSysTimeMicros()
{
#ifdef _WIN32
	// ��1601��1��1��0:0:0:000��1970��1��1��0:0:0:000��ʱ��(��λ100ns)
#define EPOCHFILETIME   (116444736000000000UL)
	FILETIME ft;
	LARGE_INTEGER li;
	ULL tt = 0;
	GetSystemTimeAsFileTime(&ft);
	li.LowPart = ft.dwLowDateTime;
	li.HighPart = ft.dwHighDateTime;
	// ��1970��1��1��0:0:0:000�����ڵ�΢����(UTCʱ��)
	tt = (li.QuadPart - EPOCHFILETIME) / 10;
	return tt;
#else
	timeval tv;
	gettimeofday(&tv, 0);
	return (int64_t)tv.tv_sec * 1000000 + (int64_t)tv.tv_usec;
#endif // _WIN32
	return 0;
}

//ZZ����תΪULL����
ULL ZZ_To_Uint64(ZZ a)
{
	ULL Temp = 0;
	for (int j = 0; j < 64; j++)
		if (bit(a, j) == 1)
			Temp += pow(2, j);
	return Temp;
}

//ULL����תΪZZ����
void Uint64_To_ZZ(ZZ& x, ULL n)
{
	const unsigned char* Temp = (const unsigned char*)(&n);
	ZZFromBytes(x, Temp, 8);
}

//ANSI����������㷨
ZZ ANSI(ULL s, int m, ULL k1, ULL k2)
{
	ZZ Result;
	Result = to_ZZ(0);
	ULL TempI, Xi;
	ULL D = GetSysTimeMicros();
	ZZ TempX;
	TempI = DES_Encrypt(DES_Decrypt(DES_Encrypt(D, k1), k2), k1);
	for (int i = 0; i < m; i++)
	{
		Xi = DES_Encrypt(DES_Decrypt(DES_Encrypt(TempI ^ s, k1), k2), k1);
		s = DES_Encrypt(DES_Decrypt(DES_Encrypt(Xi ^ TempI, k1), k2), k1);
		Uint64_To_ZZ(TempX, Xi);
		Result <<= 64;
		Result = Result + TempX;
	}
	return Result;
}

void Open_Input_File(ifstream& infile)
{
	char* p = new char[30];
	cout << "������Ҫ�򿪵Ķ�����Ϣ�ĵ��ļ�����";
	cin >> p;
	infile.open(p, ios::in);
	if (infile.is_open() == 0)
	{
		cout << "���ļ�ʧ��" << endl;
		exit(-1);
	}
}

void Open_Output_File(ofstream& fout)
{
	char* p = new char[30];
	cout << "������Ҫ�򿪵�д����Ϣ���ļ�����";
	cin >> p;
	fout.open(p, ios::out);
	if (fout.is_open() == 0)
	{
		cout << "���ļ�ʧ��" << endl;
		exit(-1);
	}
}

void Friendly_Menu(int select)
{
	if (select == 0)
	{
		int i;
		cout << "���ִ�����ѧ�γ���ơ���1952650  ������" << endl;
		for (i = 0; i < 50; i++)
		{
			cout << '*';
		}
		cout << endl;
		cout << "*\t\t ��Ŀģ��\t\t\t *\n";
		cout << "*\t\t1 Alice����RSA��Կ\t\t *\n";
		cout << "*\t\t2 Bob��������m������Alice\t *\n";
		cout << "*\t\t3 Alice���ָܻ�����m\t\t *\n";
		for (i = 0; i < 50; i++)
		{
			cout << '*';
		}
		cout << endl << endl;
	}
	if (select == 1)
	{
		int i;
		for (i = 0; i < 50; i++)
		{
			cout << '*';
		}
		cout << endl;
		cout << "*\tAlice����RSA��Կģ�飺��ʼ\t\t *\n";
		for (i = 0; i < 50; i++)
		{
			cout << '*';
		}
		cout << endl;
	}
	if (select == 2)
	{
		int i;
		for (i = 0; i < 50; i++)
		{
			cout << '*';
		}
		cout << endl;
		cout << "*\tAlice����RSA��Կģ�飺����\t\t *\n";
		for (i = 0; i < 50; i++)
		{
			cout << '*';
		}
		cout << endl << endl;
	}
	if (select == 3)
	{
		int i;
		for (i = 0; i < 50; i++)
		{
			cout << '*';
		}
		cout << endl;
		cout << "*\tBob�����ļ�m������Aliceģ�飺��ʼ\t *\n";
		for (i = 0; i < 50; i++)
		{
			cout << '*';
		}
		cout << endl;
	}
	if (select == 4)
	{
		int i;
		for (i = 0; i < 50; i++)
		{
			cout << '*';
		}
		cout << endl;
		cout << "*\tBob�����ļ�m������Aliceģ�飺����\t *\n";
		for (i = 0; i < 50; i++)
		{
			cout << '*';
		}
		cout << endl << endl;
	}
	if (select == 5)
	{
		for (int i = 0; i < 50; i++)
			cout << '*';
		cout << endl;
		cout << "*\tAlice���ָܻ�����mģ�飺��ʼ\t\t *\n";
		for (int i = 0; i < 50; i++)
			cout << '*';
		cout << endl;
		cout << "Alice���գ�c1,c2�������ܵ����Ĺ��̣���ʼ" << endl;
	}
	if (select == 6)
	{
		for (int i = 0; i < 50; i++)
			cout << '*';
		cout << endl;
		cout << "*\tAlice���ָܻ�����mģ�飺����\t\t *\n";
		for (int i = 0; i < 50; i++)
			cout << '*';
		cout << endl << endl;
	}
}

int main()
{
	Friendly_Menu(0);
	Friendly_Menu(1);
	cout << "Alice���ļ��������ӡ���Կ1����Կ2��" << endl;
	ULL seed_Alice(0), key1_Alice(0), key2_Alice(0);
	ZZ p, q;
	ifstream infile;
	Open_Input_File(infile);
	infile >> seed_Alice >> key1_Alice >> key2_Alice;
	cout << "Alice�Ѵ��ļ�INPUT_SEED_TWOKEY.txt�������ӡ���Կ1����Կ2��" << endl;
	infile.close();
	int len;
	cout << "������Ҫ�����������ȣ�512bits/1024bits����";
	cin >> len;
	Prime_Generation(p, q, len, seed_Alice, key1_Alice, key2_Alice);
	cout << "Alice����RSA��Կ���̣�" << endl;
	ZZ n, phi_n, b;
	n = p * q;
	cout << "n = " << n << endl;
	phi_n = p * q - p - q + 1;
	b = b_Generation(phi_n);
	cout << "b = " << b << endl;
	cout << "RSA��ԿΪ(n,b)Ϊ��(" << n << "," << b << ")" << endl;
	cout << "Alice��RSA��Կ������ļ��д���Bob��" << endl;
	ofstream fout;
	Open_Output_File(fout);
	fout << n << endl << b << endl;
	cout << "�ѽ�RSA��Կ������ļ�RSA_Public_Key.txt�С�" << endl;
	fout.close();
	Friendly_Menu(2);


	Friendly_Menu(3);
	ZZ n_Bob, b_Bob;
	cout << "Bob���ļ��ж���RSA��Կ(n,b)��" << endl;
	Open_Input_File(infile);
	infile >> n_Bob >> b_Bob;
	cout << "Bob�Ѵ��ļ�RSA_Public_Key.txt�ж���RSA��Կ(n,b)��" << endl;
	infile.close();
	cout << "n_Bob = " << n_Bob << endl;
	cout << "b_Bob = " << b_Bob << endl;
	cout << "Bob���ļ��������ӡ���Կ1����Կ2��" << endl;
	Open_Input_File(infile);
	ZZ k_Bob;
	ULL seed_Bob, Key1_Bob, Key2_Bob;
	infile >> seed_Bob >> Key1_Bob >> Key2_Bob;
	cout << "Alice�Ѵ��ļ�INPUT_SEED_TWOKEY.txt�������ӡ���Կ1����Կ2��" << endl;
	infile.close();
	cout << "Bob����AES��ʱ�Ự��Կk_Bob��" << endl;
	k_Bob = ANSI(seed_Bob, 2, Key1_Bob, Key2_Bob);
	cout << "Bob�Ѿ�����AES��ʱ�Ự��Կk_Bob = " << k_Bob << endl;
	cout << "Bobͨ��RSA��Կ������Կk_Bob��" << endl;
	ZZ c1_Bob;
	AES aes_Bob(k_Bob);
	c1_Bob = RSA_Encrypt(k_Bob, b_Bob, n_Bob);
	cout << "Bob��ͨ��RSA��Կ������Կk_Bob������c1_Bob = " << c1_Bob << endl;
	cout << "Bob������c1_Bob������ļ��У�" << endl;
	Open_Output_File(fout);
	fout << c1_Bob << endl;
	cout << "Bob�ѽ�����c1_Bob������ļ�Ciphertext_c1.txt�С�" << endl;
	fout.close();
	ZZ m, IV;
	cout << "Bob���ļ�Plaintext.txt�ж�������m����������AES��CBC��ģʽ���м��ܣ�" << endl;
	Open_Input_File(infile);
	Open_Output_File(fout);
	CBC_Encrypt(aes_Bob, IV, infile, fout);
	cout << "Bob�ѽ�����c2_Bob������ļ�Ciphertext_c2.txt�С�" << endl;
	infile.close();
	fout.close();
	Friendly_Menu(4);


	Friendly_Menu(5);
	ZZ k_Alice, c1_Alice;
	ZZ a, x;
	Extend_Euclidean(phi_n, b, x, a);
	cout << "Alice���ļ��ж�������c1_Alice��" << endl;
	Open_Input_File(infile);
	infile >> c1_Alice;
	cout << "Alice�Ѵ��ļ�Ciphertext_c1.txt�ж�������c1_Alice��" << endl;
	infile.close();
	cout << "Alice��RSA˽Կa����c1_Alice�õ�AES��ʱ�Ự��Կk_Alice��" << endl;
	k_Alice = RSA_Decrypt(c1_Alice, a, n);
	cout << "Alice��c1_Alice�õ�AES��ʱ�Ự��Կk_Alice = " << k_Alice << endl;
	cout << "Aliceʹ��AES��Կk_Alice��������c2_Alice�õ�����m_Alice��" << endl;
	Open_Input_File(infile);
	Open_Output_File(fout);
	CBC_Decrypt(IV, infile, fout, k_Alice);
	Friendly_Menu(6);

	return 0;
}