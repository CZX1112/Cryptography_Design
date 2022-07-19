#include <NTL/ZZ.h>
#include "DES.h"

using namespace NTL;

DES::DES() {
	Secret_Key = 0;
	Encryp_Info = 0;
	Decrypt_Info = 0;
	Plain_Text = 0;
	for (int i = 0; i < 16; i++)
		Input_Key[i] = 0;
}

void DES::Set_Key(ULL k)
{
	Secret_Key = k;
}
void DES::Set_Plain_Text(ULL p)
{
	Plain_Text = p;
}
void DES::Set_Encryp_Info(ULL c)
{
	Encryp_Info = c;
}

ULL DES::Get_Secret_Key()
{
	return Secret_Key;
}

ULL DES::Get_Encryp_Info()
{
	return Encryp_Info;
}

ULL DES::Get_Decrypt_Info()
{
	return Decrypt_Info;
}

ULL DES::Get_Plain_Text()
{
	return Plain_Text;
}

ULL DES::Bit_Extension(ULL num, const int p[], int Max, int length)
{
	ULL Result = 0;
	int i;
	for (i = 0; i < length; i++)
	{
		Result <<= 1;
		Result |= (num >> (Max - p[i])) & 1;
	}
	return Result;
}

ULL DES::Transform(ULL key, int n)
{
	ULL Result = 0;
	ULL Left, Right;
	Left = (key & 0xFFFFFFF0000000LL) >> 28;
	Right = key & 0x0000000FFFFFFF;
	if (n == 1) {
		Left = ((Left & 0x7FFFFFF) << 1) | ((Left >> 27) & 1);
		Right = ((Right & 0x7FFFFFF) << 1) | ((Right >> 27) & 1);
		Result = (Left << 28) | Right;
	}
	else if (n == 2) {
		Left = ((Left & 0x3FFFFFF) << 2) | ((Left >> 26) & 3);
		Right = ((Right & 0x7FFFFFF) << 2) | ((Right >> 26) & 3);
		Result = (Left << 28) | Right;
	}
	return Result;
}

void DES::Generate_Key()
{
	ULL generate_key;
	generate_key = Bit_Extension(Secret_Key, Key_PC1, 64, 56);
	for (int i = 0; i < 16; i++)
	{
		generate_key = Transform(generate_key, Key_Schedule[i]);
		Input_Key[i] = Bit_Extension(generate_key, Compress_PC2, 56, 48);
	}
}

ULL DES::S_Boxes_Transform(ULL num)
{
	ULL temp, result = 0;
	for (int i = 0; i < 8; i++)
	{
		temp = (num >> ((7 - i) * 6)) & 0x3f;
		int x = ((temp >> 4) & 0x2) | (temp & 0x1) + i * 4;
		int y = (temp >> 1) & 0xf;
		temp = S_BOX[x][y];
		temp = temp << ((7 - i) * 4);
		result |= temp;
	}
	return result;
}

void DES::Encrypt()
{
	ULL L, R, temp_r, temp;

	temp = Bit_Extension(Plain_Text, IP_First, 64, 64);
	L = (temp & 0xFFFFFFFF00000000LL) >> 32;
	R = (temp & 0x00000000FFFFFFFFLL);
	temp_r = R;

	for (int i = 0; i < 16; i++)
	{
		temp_r = Bit_Extension(R, E, 32, 48);
		temp_r = temp_r ^ Input_Key[i];
		temp_r = S_Boxes_Transform(temp_r);
		temp_r = Bit_Extension(temp_r, P, 32, 32);
		temp_r ^= L;
		L = R;
		R = temp_r;
	}
	temp = (R << 32) | L;
	temp = Bit_Extension(temp, IP_Last, 64, 64);
	Encryp_Info = temp;
}

void DES::Decrypt()
{
	ULL L, R, temp_r, temp;

	temp = Bit_Extension(Encryp_Info, IP_First, 64, 64);
	L = (temp & 0xffffffff00000000LL) >> 32;
	R = (temp & 0x00000000ffffffffLL);
	temp_r = R;

	for (int i = 0; i < 16; i++)
	{
		temp_r = Bit_Extension(R, E, 32, 48);
		temp_r = temp_r ^ Input_Key[15 - i];
		temp_r = S_Boxes_Transform(temp_r);
		temp_r = Bit_Extension(temp_r, P, 32, 32);
		temp_r ^= L;
		L = R;
		R = temp_r;
	}
	temp = (R << 32) | L;
	temp = Bit_Extension(temp, IP_Last, 64, 64);
	Decrypt_Info = temp;
}

//DES加密过程
ULL DES_Encrypt(ULL Plain_Text, ULL Secret_Key)
{
	DES des;
	des.Set_Plain_Text(Plain_Text);
	des.Set_Key(Secret_Key);
	des.Generate_Key();
	des.Encrypt();
	return des.Get_Encryp_Info();
}

//DES解密过程
ULL DES_Decrypt(ULL Encryp_Info, ULL Secret_Key)
{
	DES des;
	des.Set_Encryp_Info(Encryp_Info);
	des.Set_Key(Secret_Key);
	des.Generate_Key();
	des.Decrypt();
	return des.Get_Decrypt_Info();
}