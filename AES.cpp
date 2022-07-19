#include <NTL/ZZ.h>
#include "AES.h"

using namespace NTL;

AES::AES(const ZZ& key)
{
	unsigned int temp;

	unsigned int* w = (unsigned int*)Round_Key;
	BytesFromZZ((unsigned char*)w, key, 16);
	Transpose((unsigned char*)w, 16);

	for (int i = 4; i < 44; ++i)
	{
		temp = w[i - 1];
		// 被4整除：低2位为0
		if (!(i & 0x3))
			temp = SubWord(RotWord(temp)) ^ Rcon[i / 4];

		w[i] = w[i - 4] ^ temp;
	}
}

void AES::Encrypt(ZZ& ciphertext, const ZZ& plaintext)
{
	BytesFromZZ(State, plaintext, 16);
	// 小字序转换成正序
	Transpose(State, 16);
	// 行列转换
	tranRowCol(State);

	AddRoundKey(Round_Key[0]);

	for (int i = 1; i <= 9; i++) {
		SubBytes();
		ShiftRows();
		MixColumns();
		AddRoundKey(Round_Key[i]);
	}

	SubBytes();

	ShiftRows();

	AddRoundKey(Round_Key[10]);

	// 正序转回小字序
	Transpose(State, 16);
	// 行列转换
	tranRowCol(State);
	ZZFromBytes(ciphertext, State, 16);
}

void AES::Decrypt(ZZ& plaintext, const ZZ& ciphertext)
{
	BytesFromZZ(State, ciphertext, 16);
	// 小字序转换成正序
	Transpose(State, 16);
	// 行列转换
	tranRowCol(State);

	AddRoundKey(Round_Key[10]);

	for (int round = 1; round <= 9; ++round) {
		Inv_ShiftRows();
		Inv_SubBytes();
		AddRoundKey(Round_Key[10 - round]);
		Inv_MixColumns();
	}

	Inv_ShiftRows();
	Inv_SubBytes();
	AddRoundKey(Round_Key[0]);

	// 正序转回小字序
	Transpose(State, 16);
	// 行列转换
	tranRowCol(State);
	ZZFromBytes(plaintext, State, 16);
}

void AES::tranRowCol(unsigned char* buf)
{
	unsigned char(*p)[4] = (unsigned char(*)[4])buf;
	unsigned char temp;
	for (int i = 0; i < 4; ++i)
		for (int j = i + 1; j < 4; ++j)
		{
			temp = p[i][j];
			p[i][j] = p[j][i];
			p[j][i] = temp;
		}
}

void AES::Transpose(unsigned char* State, int len)
{
	int t = len / 2;
	unsigned char temp;
	for (int i = 0; i < t; ++i)
	{
		temp = State[i];
		State[i] = State[len - i - 1];
		State[len - i - 1] = temp;
	}
}

void AES::SubBytes()
{
	for (int i = 0; i < 16; i++)
		State[i] = S_Box[(State[i] & 0xF0U) >> 4][State[i] & 0x0FU];
	//没用
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			state[i][j] = S_Box[i][j];
}

void AES::Inv_SubBytes()
{
	for (int i = 0; i < 16; i++)
		State[i] = INV_S_Box[(State[i] & 0xF0U) >> 4][State[i] & 0x0FU];
	//没用
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			state[i][j] = S_Box[i][j];
}

void AES::ShiftRows()
{
	unsigned char Mid;

	Mid = State[4];
	for (int i = 4; i < 7; ++i)
		State[i] = State[i + 1];
	State[7] = Mid;

	//交换State[8]和State[10]
	Mid = State[8];
	State[8] = State[10];
	State[10] = Mid;
	//交换State[9]和State[11]
	Mid = State[9];
	State[9] = State[11];
	State[11] = Mid;

	Mid = State[15];
	for (int i = 15; i > 12; --i)
		State[i] = State[i - 1];
	State[12] = Mid;

	//以下没用
	unsigned char t[4];
	int r, c;
	for (r = 1; r < 4; r++)
	{
		for (c = 0; c < 4; c++)
		{
			t[c] = state[r][(c + r) % 4];
		}
		for (c = 0; c < 4; c++)
		{
			state[r][c] = t[c];
		}
	}
}

void AES::Inv_ShiftRows()
{
	unsigned char Mid;

	Mid = State[7];
	for (int i = 7; i > 4; --i)
		State[i] = State[i - 1];
	State[4] = Mid;

	//交换State[8]和State[10]
	Mid = State[8];
	State[8] = State[10];
	State[10] = Mid;
	//交换State[9]和State[11]
	Mid = State[9];
	State[9] = State[11];
	State[11] = Mid;

	Mid = State[12];
	for (int i = 12; i < 15; ++i)
		State[i] = State[i + 1];
	State[15] = Mid;

	//以下没用
	unsigned char t[4];
	int r, c;
	for (r = 1; r < 4; r++)
	{
		for (c = 0; c < 4; c++)
		{
			t[c] = state[r][(c - r + 4) % 4];
		}
		for (c = 0; c < 4; c++)
		{
			state[r][c] = t[c];
		}
	}
}

unsigned char AES::GField_2_8_Mult(unsigned char x)
{
	if ((x & '\x80') != 0)
		return (x << 1) ^ '\x1b';
	else
		return x << 1;
}

unsigned char AES::FFmul(unsigned char a, unsigned char b)
{
	unsigned char res = 0;
	unsigned char x[4];
	int i;
	x[0] = b;
	for (i = 1; i < 4; i++)
	{
		x[i] = x[i - 1] << 1;
		if (x[i - 1] & 0x80)
		{
			x[i] ^= 0x1b;
		}
	}
	for (i = 0; i < 4; i++)
	{
		if ((a >> i) & 0x01)
		{
			res ^= x[i];
		}
	}
	return res;
}

void AES::MixColumns()
{
	unsigned char Inter_Variable[4];
	unsigned char(*TDPointer)[4] = (unsigned char(*)[4])State;

	for (int i = 0; i < 4; i++)
	{
		Inter_Variable[0] = TDPointer[0][i];
		Inter_Variable[1] = TDPointer[1][i];
		Inter_Variable[2] = TDPointer[2][i];
		Inter_Variable[3] = TDPointer[3][i];

		TDPointer[0][i] = Inter_Variable[1] ^ Inter_Variable[2] ^ Inter_Variable[3];
		TDPointer[1][i] = Inter_Variable[0] ^ Inter_Variable[2] ^ Inter_Variable[3];
		TDPointer[2][i] = Inter_Variable[0] ^ Inter_Variable[1] ^ Inter_Variable[3];
		TDPointer[3][i] = Inter_Variable[0] ^ Inter_Variable[1] ^ Inter_Variable[2];

		for (int j = 0; j < 4; j++)
			Inter_Variable[j] = GField_2_8_Mult(Inter_Variable[j]);

		TDPointer[0][i] = TDPointer[0][i] ^ Inter_Variable[0] ^ Inter_Variable[1];
		TDPointer[1][i] = TDPointer[1][i] ^ Inter_Variable[1] ^ Inter_Variable[2];
		TDPointer[2][i] = TDPointer[2][i] ^ Inter_Variable[2] ^ Inter_Variable[3];
		TDPointer[3][i] = TDPointer[3][i] ^ Inter_Variable[3] ^ Inter_Variable[0];
	}

	//以下没用
	unsigned char t[4];
	int r, c;
	for (c = 0; c < 4; c++)
	{
		for (r = 0; r < 4; r++)
		{
			t[r] = state[r][c];
		}
		for (r = 0; r < 4; r++)
		{
			state[r][c] = FFmul(0x02, t[r])
				^ FFmul(0x03, t[(r + 1) % 4])
				^ FFmul(0x01, t[(r + 2) % 4])
				^ FFmul(0x01, t[(r + 3) % 4]);
		}
	}
}

void AES::Inv_MixColumns()
{
	unsigned char Inter_Variable[4];
	unsigned char(*TDPointer)[4] = (unsigned char(*)[4])State;

	for (int i = 0; i < 4; ++i)
	{
		//将State中的值拷贝到中间变量Inter_Variable中
		Inter_Variable[0] = TDPointer[0][i];
		Inter_Variable[1] = TDPointer[1][i];
		Inter_Variable[2] = TDPointer[2][i];
		Inter_Variable[3] = TDPointer[3][i];

		TDPointer[0][i] = Inter_Variable[1] ^ Inter_Variable[2] ^ Inter_Variable[3];
		TDPointer[1][i] = Inter_Variable[0] ^ Inter_Variable[2] ^ Inter_Variable[3];
		TDPointer[2][i] = Inter_Variable[0] ^ Inter_Variable[1] ^ Inter_Variable[3];
		TDPointer[3][i] = Inter_Variable[0] ^ Inter_Variable[1] ^ Inter_Variable[2];

		for (int j = 0; j < 4; j++)
			Inter_Variable[j] = GField_2_8_Mult(Inter_Variable[j]);

		TDPointer[0][i] = TDPointer[0][i] ^ Inter_Variable[0] ^ Inter_Variable[1];
		TDPointer[1][i] = TDPointer[1][i] ^ Inter_Variable[1] ^ Inter_Variable[2];
		TDPointer[2][i] = TDPointer[2][i] ^ Inter_Variable[2] ^ Inter_Variable[3];
		TDPointer[3][i] = TDPointer[3][i] ^ Inter_Variable[3] ^ Inter_Variable[0];

		Inter_Variable[0] = GField_2_8_Mult(Inter_Variable[0] ^ Inter_Variable[2]);
		Inter_Variable[1] = GField_2_8_Mult(Inter_Variable[1] ^ Inter_Variable[3]);

		TDPointer[0][i] ^= Inter_Variable[0];
		TDPointer[1][i] ^= Inter_Variable[1];
		TDPointer[2][i] ^= Inter_Variable[0];
		TDPointer[3][i] ^= Inter_Variable[1];

		Inter_Variable[0] = GField_2_8_Mult(Inter_Variable[0] ^ Inter_Variable[1]);

		TDPointer[0][i] ^= Inter_Variable[0];
		TDPointer[1][i] ^= Inter_Variable[0];
		TDPointer[2][i] ^= Inter_Variable[0];
		TDPointer[3][i] ^= Inter_Variable[0];
	}

	//以下没用
	unsigned char t[4];
	int r, c;
	for (c = 0; c < 4; c++)
	{
		for (r = 0; r < 4; r++)
		{
			t[r] = state[r][c];
		}
		for (r = 0; r < 4; r++)
		{
			state[r][c] = FFmul(0x0e, t[r])
				^ FFmul(0x0b, t[(r + 1) % 4])
				^ FFmul(0x0d, t[(r + 2) % 4])
				^ FFmul(0x09, t[(r + 3) % 4]);
		}
	}
};

void AES::AddRoundKey(const unsigned char* key)
{
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			State[i * 4 + j] ^= key[j * 4 + i];
}

ULL AES::SubWord(ULL in)
{
	unsigned char* p = (unsigned char*)&in;
	p[0] = S_Box[(p[0] & 0xF0U) >> 4][p[0] & 0x0FU];
	p[1] = S_Box[(p[1] & 0xF0U) >> 4][p[1] & 0x0FU];
	p[2] = S_Box[(p[2] & 0xF0U) >> 4][p[2] & 0x0FU];
	p[3] = S_Box[(p[3] & 0xF0U) >> 4][p[3] & 0x0FU];

	return in;
}

ULL AES::RotWord(ULL in)
{
	unsigned char* Pointer = (unsigned char*)&in;
	unsigned char Mid = Pointer[0];
	Pointer[0] = Pointer[1];
	Pointer[1] = Pointer[2];
	Pointer[2] = Pointer[3];
	Pointer[3] = Mid;
	return in;
}