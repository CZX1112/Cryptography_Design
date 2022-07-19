#include "Crypto_Curri_Design.h"
#include <windows.h>

//获取系统的当前时间，单位微秒(us)
ULL GetSysTimeMicros()
{
#ifdef _WIN32
	// 从1601年1月1日0:0:0:000到1970年1月1日0:0:0:000的时间(单位100ns)
#define EPOCHFILETIME   (116444736000000000UL)
	FILETIME ft;
	LARGE_INTEGER li;
	ULL tt = 0;
	GetSystemTimeAsFileTime(&ft);
	li.LowPart = ft.dwLowDateTime;
	li.HighPart = ft.dwHighDateTime;
	// 从1970年1月1日0:0:0:000到现在的微秒数(UTC时间)
	tt = (li.QuadPart - EPOCHFILETIME) / 10;
	return tt;
#else
	timeval tv;
	gettimeofday(&tv, 0);
	return (int64_t)tv.tv_sec * 1000000 + (int64_t)tv.tv_usec;
#endif // _WIN32
	return 0;
}

//ZZ变量转为ULL变量
ULL ZZ_To_Uint64(ZZ a)
{
	ULL Temp = 0;
	for (int j = 0; j < 64; j++)
		if (bit(a, j) == 1)
			Temp += pow(2, j);
	return Temp;
}

//ULL变量转为ZZ变量
void Uint64_To_ZZ(ZZ& x, ULL n)
{
	const unsigned char* Temp = (const unsigned char*)(&n);
	ZZFromBytes(x, Temp, 8);
}

//ANSI随机数生成算法
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
	cout << "请输入要打开的读入信息的的文件名：";
	cin >> p;
	infile.open(p, ios::in);
	if (infile.is_open() == 0)
	{
		cout << "打开文件失败" << endl;
		exit(-1);
	}
}

void Open_Output_File(ofstream& fout)
{
	char* p = new char[30];
	cout << "请输入要打开的写入信息的文件名：";
	cin >> p;
	fout.open(p, ios::out);
	if (fout.is_open() == 0)
	{
		cout << "打开文件失败" << endl;
		exit(-1);
	}
}

void Friendly_Menu(int select)
{
	if (select == 0)
	{
		int i;
		cout << "《现代密码学课程设计》：1952650  陈子翔" << endl;
		for (i = 0; i < 50; i++)
		{
			cout << '*';
		}
		cout << endl;
		cout << "*\t\t 项目模块\t\t\t *\n";
		cout << "*\t\t1 Alice生成RSA密钥\t\t *\n";
		cout << "*\t\t2 Bob加密明文m并发给Alice\t *\n";
		cout << "*\t\t3 Alice解密恢复明文m\t\t *\n";
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
		cout << "*\tAlice生成RSA密钥模块：开始\t\t *\n";
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
		cout << "*\tAlice生成RSA密钥模块：结束\t\t *\n";
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
		cout << "*\tBob加密文件m并发给Alice模块：开始\t *\n";
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
		cout << "*\tBob加密文件m并发给Alice模块：结束\t *\n";
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
		cout << "*\tAlice解密恢复明文m模块：开始\t\t *\n";
		for (int i = 0; i < 50; i++)
			cout << '*';
		cout << endl;
		cout << "Alice接收（c1,c2）并解密得明文过程：开始" << endl;
	}
	if (select == 6)
	{
		for (int i = 0; i < 50; i++)
			cout << '*';
		cout << endl;
		cout << "*\tAlice解密恢复明文m模块：结束\t\t *\n";
		for (int i = 0; i < 50; i++)
			cout << '*';
		cout << endl << endl;
	}
}

int main()
{
	Friendly_Menu(0);
	Friendly_Menu(1);
	cout << "Alice从文件读入种子、密钥1、密钥2：" << endl;
	ULL seed_Alice(0), key1_Alice(0), key2_Alice(0);
	ZZ p, q;
	ifstream infile;
	Open_Input_File(infile);
	infile >> seed_Alice >> key1_Alice >> key2_Alice;
	cout << "Alice已从文件INPUT_SEED_TWOKEY.txt读入种子、密钥1、密钥2。" << endl;
	infile.close();
	int len;
	cout << "请输入要产生素数长度（512bits/1024bits）：";
	cin >> len;
	Prime_Generation(p, q, len, seed_Alice, key1_Alice, key2_Alice);
	cout << "Alice产生RSA密钥过程：" << endl;
	ZZ n, phi_n, b;
	n = p * q;
	cout << "n = " << n << endl;
	phi_n = p * q - p - q + 1;
	b = b_Generation(phi_n);
	cout << "b = " << b << endl;
	cout << "RSA公钥为(n,b)为：(" << n << "," << b << ")" << endl;
	cout << "Alice将RSA公钥输出到文件中传给Bob：" << endl;
	ofstream fout;
	Open_Output_File(fout);
	fout << n << endl << b << endl;
	cout << "已将RSA公钥输出到文件RSA_Public_Key.txt中。" << endl;
	fout.close();
	Friendly_Menu(2);


	Friendly_Menu(3);
	ZZ n_Bob, b_Bob;
	cout << "Bob从文件中读入RSA公钥(n,b)：" << endl;
	Open_Input_File(infile);
	infile >> n_Bob >> b_Bob;
	cout << "Bob已从文件RSA_Public_Key.txt中读入RSA公钥(n,b)。" << endl;
	infile.close();
	cout << "n_Bob = " << n_Bob << endl;
	cout << "b_Bob = " << b_Bob << endl;
	cout << "Bob从文件读入种子、密钥1、密钥2：" << endl;
	Open_Input_File(infile);
	ZZ k_Bob;
	ULL seed_Bob, Key1_Bob, Key2_Bob;
	infile >> seed_Bob >> Key1_Bob >> Key2_Bob;
	cout << "Alice已从文件INPUT_SEED_TWOKEY.txt读入种子、密钥1、密钥2。" << endl;
	infile.close();
	cout << "Bob生成AES临时会话密钥k_Bob：" << endl;
	k_Bob = ANSI(seed_Bob, 2, Key1_Bob, Key2_Bob);
	cout << "Bob已经生成AES临时会话密钥k_Bob = " << k_Bob << endl;
	cout << "Bob通过RSA公钥加密密钥k_Bob：" << endl;
	ZZ c1_Bob;
	AES aes_Bob(k_Bob);
	c1_Bob = RSA_Encrypt(k_Bob, b_Bob, n_Bob);
	cout << "Bob已通过RSA公钥加密密钥k_Bob得密文c1_Bob = " << c1_Bob << endl;
	cout << "Bob将密文c1_Bob输出到文件中：" << endl;
	Open_Output_File(fout);
	fout << c1_Bob << endl;
	cout << "Bob已将密文c1_Bob输出到文件Ciphertext_c1.txt中。" << endl;
	fout.close();
	ZZ m, IV;
	cout << "Bob从文件Plaintext.txt中读入明文m并对其利用AES（CBC）模式进行加密：" << endl;
	Open_Input_File(infile);
	Open_Output_File(fout);
	CBC_Encrypt(aes_Bob, IV, infile, fout);
	cout << "Bob已将密文c2_Bob输出到文件Ciphertext_c2.txt中。" << endl;
	infile.close();
	fout.close();
	Friendly_Menu(4);


	Friendly_Menu(5);
	ZZ k_Alice, c1_Alice;
	ZZ a, x;
	Extend_Euclidean(phi_n, b, x, a);
	cout << "Alice从文件中读入密文c1_Alice：" << endl;
	Open_Input_File(infile);
	infile >> c1_Alice;
	cout << "Alice已从文件Ciphertext_c1.txt中读入密文c1_Alice。" << endl;
	infile.close();
	cout << "Alice用RSA私钥a解密c1_Alice得到AES临时会话密钥k_Alice：" << endl;
	k_Alice = RSA_Decrypt(c1_Alice, a, n);
	cout << "Alice已c1_Alice得到AES临时会话密钥k_Alice = " << k_Alice << endl;
	cout << "Alice使用AES密钥k_Alice解密密文c2_Alice得到明文m_Alice：" << endl;
	Open_Input_File(infile);
	Open_Output_File(fout);
	CBC_Decrypt(IV, infile, fout, k_Alice);
	Friendly_Menu(6);

	return 0;
}