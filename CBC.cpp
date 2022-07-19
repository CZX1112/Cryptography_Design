#include "Crypto_Curri_Design.h"

//CBC加密
void CBC_Encrypt(AES& aes, ZZ& IV, ifstream& infile, ofstream& fout)
{
	ZZ Cipher_Text, Plain_Text;
	unsigned char str[16];

	IV = RandomBnd(128);
	Cipher_Text = IV;

	while (1)
	{
		if (infile.read((char*)str, 16).gcount() != 16)
			break;
		ZZFromBytes(Plain_Text, str, 16L);
		Plain_Text ^= Cipher_Text;
		aes.Encrypt(Cipher_Text, Plain_Text);
		BytesFromZZ(str, Cipher_Text, 16L);
		fout.write((const char*)str, 16);
	}

	//不足位填充
	int Filling = 16 - (int)infile.gcount();
	memset(str + infile.gcount(), Filling, Filling);
	ZZFromBytes(Plain_Text, str, 16L);
	Plain_Text ^= Cipher_Text;
	aes.Encrypt(Cipher_Text, Plain_Text);
	BytesFromZZ(str, Cipher_Text, 16L);
	fout.write((const char*)str, 16);
}

//CBC解密
void CBC_Decrypt(ZZ& IV, ifstream& infile, ofstream& fout, ZZ k_de)
{
	ZZ Cipher_Text, Plain_Text;
	unsigned char str[16];

	AES Alice(k_de);
	ZZ Past_Cipher_Text(IV);

	while (1)
	{
		infile.read((char*)str, 16);
		ZZFromBytes(Cipher_Text, str, 16L);

		Alice.Decrypt(Plain_Text, Cipher_Text);
		Plain_Text ^= Past_Cipher_Text;

		Past_Cipher_Text = Cipher_Text;
		BytesFromZZ(str, Plain_Text, 16L);
		if (infile.peek() != EOF)
			fout.write((const char*)str, 16);
		else
		{
			//最后一字节
			fout.write((const char*)str, 16 - str[15]);
			break;
		}
	}
}