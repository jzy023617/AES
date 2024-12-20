#include <string.h>
#include "AES.h"
#include "stdio.h"
#include "stdlib.h"
#include "stdint.h"

#define debug_GCM
#define debug_GMAC
#define debug_GMAC_Y
#define debug_Din
#define debug_H
#define debug_EY0
// c10018a0003b81008006000000000000
// a80e0210000000000000000000000000
unsigned char input_Date0[32] = {0xc1, 0x00, 0x18, 0xa0, 0x00, 0x3b, 0x81, 0x00, 0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								 0xa8, 0x0e, 0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
unsigned char Attach0[20] = {0xc1, 0x00, 0x18, 0xa0, 0x00, 0x47, 0x81, 0x00, 0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// 300ACF300ACF300ACF303CFC303CFC30
// 3CFC304CFB304CFB304CFB3056FA30
unsigned char input_Date1[31] = {0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x3C, 0xFC, 0x30, 0x3C, 0xFC, 0x30,
								 0x3C, 0xFC, 0x30, 0x4C, 0xFB, 0x30, 0x4C, 0xFB, 0x30, 0x4C, 0xFB, 0x30, 0x56, 0xFA, 0x30};
unsigned char Attach1[20] = {0xc1, 0x00, 0x18, 0xa0, 0x00, 0x46, 0x81, 0x00, 0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// 300ACF300ACF300ACF303CFC303CFC30
// 3CFC304CFB304CFB304CFB3056FA
unsigned char input_Date2[30] = {0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x3C, 0xFC, 0x30, 0x3C, 0xFC, 0x30,
								 0x3C, 0xFC, 0x30, 0x4C, 0xFB, 0x30, 0x4C, 0xFB, 0x30, 0x4C, 0xFB, 0x30, 0x56, 0xFA};
unsigned char Attach2[20] = {0xc1, 0x00, 0x18, 0xa0, 0x00, 0x45, 0x81, 0x00, 0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// 300ACF300ACF300ACF303CFC303CFC30
// 3CFC304CFB304CFB304CFB3056
unsigned char input_Date3[29] = {0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x3C, 0xFC, 0x30, 0x3C, 0xFC, 0x30,
								 0x3C, 0xFC, 0x30, 0x4C, 0xFB, 0x30, 0x4C, 0xFB, 0x30, 0x4C, 0xFB, 0x30, 0x56};
unsigned char Attach3[20] = {0xc1, 0x00, 0x18, 0xa0, 0x00, 0x44, 0x81, 0x00, 0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// 300ACF300ACF300ACF303CFC303CFC30
// 3CFC304CFB304CFB304CFB30
unsigned char input_Date4[28] = {0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x3C, 0xFC, 0x30, 0x3C, 0xFC, 0x30,
								 0x3C, 0xFC, 0x30, 0x4C, 0xFB, 0x30, 0x4C, 0xFB, 0x30, 0x4C, 0xFB, 0x30};
unsigned char Attach4[20] = {0xc1, 0x00, 0x18, 0xa0, 0x00, 0x43, 0x81, 0x00, 0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// 300ACF300ACF300ACF303CFC303CFC30
// 3CFC304CFB304CFB304CFB
unsigned char input_Date5[27] = {0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x3C, 0xFC, 0x30, 0x3C, 0xFC, 0x30,
								 0x3C, 0xFC, 0x30, 0x4C, 0xFB, 0x30, 0x4C, 0xFB, 0x30, 0x4C, 0xFB};
unsigned char Attach5[20] = {0xc1, 0x00, 0x18, 0xa0, 0x00, 0x42, 0x81, 0x00, 0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// 300ACF300ACF300ACF303CFC303CFC30
// 3CFC304CFB304CFB304C
unsigned char input_Date6[26] = {0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x3C, 0xFC, 0x30, 0x3C, 0xFC, 0x30,
								 0x3C, 0xFC, 0x30, 0x4C, 0xFB, 0x30, 0x4C, 0xFB, 0x30, 0x4C};
unsigned char Attach6[20] = {0xc1, 0x00, 0x18, 0xa0, 0x00, 0x41, 0x81, 0x00, 0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// 300ACF300ACF300ACF303CFC303CFC30
// 3CFC304CFB304CFB30
unsigned char input_Date7[25] = {0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x3C, 0xFC, 0x30, 0x3C, 0xFC, 0x30,
								 0x3C, 0xFC, 0x30, 0x4C, 0xFB, 0x30, 0x4C, 0xFB, 0x30};
unsigned char Attach7[20] = {0xc1, 0x00, 0x18, 0xa0, 0x00, 0x40, 0x81, 0x00, 0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// 300ACF300ACF300ACF303CFC303CFC30
// 3CFC304CFB304CFB
unsigned char input_Date8[24] = {0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x3C, 0xFC, 0x30, 0x3C, 0xFC, 0x30,
								 0x3C, 0xFC, 0x30, 0x4C, 0xFB, 0x30, 0x4C, 0xFB};
unsigned char Attach8[20] = {0xc1, 0x00, 0x18, 0xa0, 0x00, 0x3f, 0x81, 0x00, 0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// 300ACF300ACF300ACF303CFC303CFC30
// 3CFC304CFB304C
unsigned char input_Date9[23] = {0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x3C, 0xFC, 0x30, 0x3C, 0xFC, 0x30,
								 0x3C, 0xFC, 0x30, 0x4C, 0xFB, 0x30, 0x4C};
unsigned char Attach9[20] = {0xc1, 0x00, 0x18, 0xa0, 0x00, 0x3e, 0x81, 0x00, 0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// 300ACF300ACF300ACF303CFC303CFC30
// 3CFC304CFB30
unsigned char input_Date10[22] = {0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x3C, 0xFC, 0x30, 0x3C, 0xFC, 0x30,
								  0x3C, 0xFC, 0x30, 0x4C, 0xFB, 0x30};
unsigned char Attach10[20] = {0xc1, 0x00, 0x18, 0xa0, 0x00, 0x3d, 0x81, 0x00, 0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// 300ACF300ACF300ACF303CFC303CFC30
// 3CFC304CFB
unsigned char input_Date11[21] = {0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x3C, 0xFC, 0x30, 0x3C, 0xFC, 0x30,
								  0x3C, 0xFC, 0x30, 0x4C, 0xFB};
unsigned char Attach11[20] = {0xc1, 0x00, 0x18, 0xa0, 0x00, 0x3c, 0x81, 0x00, 0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// 300ACF300ACF300ACF303CFC303CFC30
// 3CFC304C
unsigned char input_Date12[20] = {0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x3C, 0xFC, 0x30, 0x3C, 0xFC, 0x30,
								  0x3C, 0xFC, 0x30, 0x4C};
unsigned char Attach12[20] = {0xc1, 0x00, 0x18, 0xa0, 0x00, 0x3b, 0x81, 0x00, 0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// 300ACF300ACF300ACF303CFC303CFC30
// 3CFC30
unsigned char input_Date13[19] = {0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x3C, 0xFC, 0x30, 0x3C, 0xFC, 0x30,
								  0x3C, 0xFC, 0x30};
unsigned char Attach13[20] = {0xc1, 0x00, 0x18, 0xa0, 0x00, 0x3a, 0x81, 0x00, 0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// 300ACF300ACF300ACF303CFC303CFC30
// 3CFC
unsigned char input_Date14[18] = {0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x3C, 0xFC, 0x30, 0x3C, 0xFC, 0x30,
								  0x3C, 0xFC};
unsigned char Attach14[20] = {0xc1, 0x00, 0x18, 0xa0, 0x00, 0x39, 0x81, 0x00, 0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// 300ACF300ACF300ACF303CFC303CFC30
// 3C
unsigned char input_Date[17] = {0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x0A, 0xCF, 0x30, 0x3C, 0xFC, 0x30, 0x3C, 0xFC, 0x30,
								0x3C};
unsigned char Attach[20] = {0xc1, 0x00, 0x18, 0xa0, 0x00, 0x38, 0x81, 0x00, 0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// bd14f821d953ce230fa60774c6fc2398b059bef9d8bf61dbe9e600489540a677
unsigned char input_Key[32] = {0xbd, 0x14, 0xf8, 0x21, 0xd9, 0x53, 0xce, 0x23, 0x0f, 0xa6, 0x07, 0x74, 0xc6, 0xfc, 0x23, 0x98,
							   0xb0, 0x59, 0xbe, 0xf9, 0xd8, 0xbf, 0x61, 0xdb, 0xe9, 0xe6, 0x00, 0x48, 0x95, 0x40, 0xa6, 0x77};

// 0000000000000000000000aa
unsigned char IV[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA};
unsigned char Mask[2] = {0xff, 0xff};

unsigned char input_Key_L[240] = {0};
unsigned char Binary[8] = {0};
unsigned char Biy_8[8] = {0, 0, 0, 1, 1, 0, 1, 1};
unsigned char Y[4][8] = {0};
unsigned char KK[4][60] = {0};
unsigned char input_Key_Square[4][60];
int i = 0, t = 0;

/**
 * @brief transfer hex to binary
 * @param x: hex
 * @return Binary[7]
 */
unsigned char Hex2Bin(unsigned char x)
{
	int t, i, y;
	t = x % 16;
	y = (x - t) / 16;
	for (i = 0; i < 4; i++)
	{
		Binary[3 - i] = y % 2;
		y = y / 2;
	}
	for (i = 0; i < 4; i++)
	{
		Binary[7 - i] = t % 2;
		t = t / 2;
	}
	return Binary[7];
}

/**
 * @brief transfer binary to Decimal
 * @param TT: binary
 * @return unsiged char
 */
unsigned char Bin2Dec(unsigned char TT[8])
{
	int t, i, y;
	t = TT[0] * 8 + TT[1] * 4 + TT[2] * 2 + TT[3] * 1;
	y = TT[4] * 8 + TT[5] * 4 + TT[6] * 2 + TT[7] * 1;
	i = t * 16 + y;
	return i;
}

/**
 * @brief GF(A*B)
 * @param A: hex; B: hex
 * @return void
 */
void Multiple(unsigned char A, unsigned char B)
{
	int a = 0, b = 0, c = 0, d = 0, e = 0;
	unsigned char Bin[6][8] = {0};
	unsigned char i, t;
	unsigned char Binary1[8] = {0};
	Hex2Bin(A); // transfer A to binary ,store in Binary
	for (i = 0; i < 8; i++)
	{
		Binary1[i] = Binary[i];
	}
	for (i = 0; i < 8; i++)
	{
		Bin[1][i] = Binary1[i];
	}
	for (t = 0; t < 4; t++) // repeat 4 times
	{
		if (Binary[0] == 1) // MSB == 1, left shift 1 bit
		{
			for (i = 0; i < 7; i++)
			{
				Binary[i] = Binary[i + 1];
			}
			Binary[7] = 0;
		}
		else // MSB != 1,left shift 1 bit and XOR with 0x1b
		{
			for (i = 0; i < 7; i++)
			{
				Binary[i] = Binary[i + 1];
			}
			Binary[7] = 0;
			for (i = 0; i < 8; i++)
			{
				Binary[i] = Binary[i] ^ Biy_8[i];
			}
		}
		for (i = 0; i < 8; i++)
		{
			Bin[t + 2][i] = Binary[i];
		}
	}

	if (B == 15)
	{
		a = 1;
		b = 1;
		c = 1;
		d = 1;
	}
	else if (B == 14)
	{

		b = 1;
		c = 1;
		d = 1;
	}
	else if (B == 13)
	{
		a = 1;
		c = 1;
		d = 1;
	}
	else if (B == 12)
	{
		c = 1;
		d = 1;
	}
	else if (B == 11)
	{
		a = 1;
		b = 1;
		d = 1;
	}
	else if (B == 10)
	{
		b = 1;
		d = 1;
	}
	else if (B == 9)
	{
		a = 1;
		d = 1;
	}
	else if (B == 8)
	{
		d = 1;
	}
	else if (B == 7)
	{
		a = 1;
		b = 1;
		c = 1;
	}
	else if (B == 6)
	{
		b = 1;
		c = 1;
	}
	else if (B == 5)
	{
		a = 1;
		c = 1;
	}
	else if (B == 4)
	{
		c = 1;
	}
	else if (B == 3)
	{
		a = 1;
		b = 1;
	}
	else if (B == 2)
	{
		b = 1;
	}
	else if (B == 1)
	{
		a = 1;
	}

	for (i = 0; i < 8; i++)
	{
		Binary[i] = Bin[a * 1][i] ^ Bin[b * 2][i] ^ Bin[c * 3][i] ^ Bin[d * 4][i] ^ Bin[e * 5][i];
	}
}

void RoundKey(unsigned char key[32], unsigned char ExtKey[4][60])
{
	unsigned char i, t, x = 0;
	unsigned char KK[4] = {0};
	unsigned char K[4] = {0};
	unsigned char KKK[4] = {0};
	for (i = 0; i < 8; i++)
	{
		for (t = 0; t < 4; t++)
		{
			ExtKey[t][i] = key[x];
			x++;
		}
	}
	for (i = 8; i < 60; i++)
	{
		if (i % 8 != 0)
		{
			if (i % 8 != 4)
			{
				for (t = 0; t < 4; t++)
				{
					ExtKey[t][i] = ExtKey[t][i - 8] ^ ExtKey[t][i - 1];
				}
			}
			else if (i % 8 == 4)
			{
				for (t = 0; t < 4; t++)
				{
					KKK[t] = S_Box[ExtKey[t][i - 1]];
				}
				for (t = 0; t < 4; t++)
				{
					ExtKey[t][i] = ExtKey[t][i - 8] ^ KKK[t];
				}
			}
		}
		else if (i % 8 == 0)
		{
			for (t = 0; t < 4; t++)
			{
				KK[t] = S_Box[ExtKey[t][i - 1]];
			}
			K[0] = KK[1];
			K[1] = KK[2];
			K[2] = KK[3];
			K[3] = KK[0];
			for (t = 0; t < 4; t++)
			{
				ExtKey[t][i] = ExtKey[t][i - 8] ^ K[t] ^ T_Box[t][(i / 8) - 1];
			}
		}
	}
}

void Initial_Round(unsigned char input[16], unsigned char output[16], unsigned char key[32])
{
	unsigned char i;
	for (i = 0; i < 16; i++)
	{
		output[i] = input[i] ^ input_Key[i];
	}
}

void ByteSub(unsigned char input[16], unsigned char output[16])
{
	unsigned char i;
	short Mix_Bit;
	for (i = 0; i < 16; i++)
	{
		Mix_Bit = input[i];
		output[i] = S_Box[Mix_Bit];
	}
}

void ShiftRow(unsigned char input[16], unsigned char output[4][4])
{
	output[0][0] = input[0];  // ����
	output[1][0] = input[5];  // output_ByteSub[5]
	output[2][0] = input[10]; // output_ByteSub[10]
	output[3][0] = input[15]; // output_ByteSub[15]
	output[0][1] = input[4];  // ����
	output[1][1] = input[9];  // output_ByteSub[9]
	output[2][1] = input[14]; // output_ByteSub[14]
	output[3][1] = input[3];  // output_ByteSub[3]
	output[0][2] = input[8];  // ����
	output[1][2] = input[13]; // output_ByteSub[13]
	output[2][2] = input[2];  // output_ByteSub[2]
	output[3][2] = input[7];  // output_ByteSub[7]
	output[0][3] = input[12]; // ����
	output[1][3] = input[1];  // output_ByteSub[1]
	output[2][3] = input[6];  // output_ByteSub[6]
	output[3][3] = input[11]; // output_ByteSub[11]
}

void MixColumn(unsigned char input[4][4], unsigned char output[4][4])
{
	unsigned char i, t, y, j;
	unsigned char S[8] = {0};
	for (y = 0; y < 4; y++)
	{
		for (i = 0; i < 4; i++)
		{

			for (t = 0; t < 4; t++)
			{
				Multiple(input[t][i], Fixed[y][t]);
				for (j = 0; j < 8; j++)
				{
					Y[t][j] = Binary[j];
				}
			}
			for (j = 0; j < 8; j++)
			{
				S[j] = Y[0][j] ^ Y[1][j] ^ Y[2][j] ^ Y[3][j];
			}
			output[y][i] = Bin2Dec(S);
		}
	}
}

void AddRoundKey(unsigned char input[4][4], unsigned char output[4][4], unsigned char ttt)
{
	unsigned char i, t;
	for (i = 0; i < 4; i++)
	{
		for (t = 0; t < 4; t++)
		{
			output[t][i] = input_Key_Square[t][i + 4 + ttt * 4] ^ input[t][i];
		}
	}
}

void Inv_AddRoundKey(unsigned char intput[4][4], unsigned char output[4][4], unsigned char ttt)
{
	unsigned char i, t;
	for (i = 0; i < 4; i++)
	{
		for (t = 0; t < 4; t++)
		{
			output[t][i] = input_Key_Square[t][56 + i - ttt * 4] ^ intput[t][i];
		}
	}
}

void Inv_ShiftRow_Box(unsigned char input[4][4], unsigned char output[4][4])
{
	output[0][0] = Inv_S_Box[input[0][0]];
	output[0][1] = Inv_S_Box[input[0][1]];
	output[0][2] = Inv_S_Box[input[0][2]];
	output[0][3] = Inv_S_Box[input[0][3]];
	output[1][0] = Inv_S_Box[input[1][3]];
	output[1][1] = Inv_S_Box[input[1][0]];
	output[1][2] = Inv_S_Box[input[1][1]];
	output[1][3] = Inv_S_Box[input[1][2]];
	output[2][0] = Inv_S_Box[input[2][2]];
	output[2][1] = Inv_S_Box[input[2][3]];
	output[2][2] = Inv_S_Box[input[2][0]];
	output[2][3] = Inv_S_Box[input[2][1]];
	output[3][0] = Inv_S_Box[input[3][1]];
	output[3][1] = Inv_S_Box[input[3][2]];
	output[3][2] = Inv_S_Box[input[3][3]];
	output[3][3] = Inv_S_Box[input[3][0]];
}

void Inv_MixColumn(unsigned char input[4][4], unsigned char output[4][4])
{
	unsigned char i, t, y, j;
	unsigned char YY[4][8] = {0};
	unsigned char SS[8] = {0};
	for (y = 0; y < 4; y++)
	{
		for (i = 0; i < 4; i++)
		{
			for (t = 0; t < 4; t++)
			{
				Multiple(input[t][i], Inv_FIxed[y][t]);
				for (j = 0; j < 8; j++)
				{
					YY[t][j] = Binary[j];
				}
			}
			for (j = 0; j < 8; j++)
			{
				SS[j] = YY[0][j] ^ YY[1][j] ^ YY[2][j] ^ YY[3][j];
			}
			output[y][i] = Bin2Dec(SS);
		}
	}
}

void AES_Encrypted(unsigned char key[32], unsigned char input[16], unsigned char output[4][4])
{
	int i = 0, j = 0, k = 0;

	unsigned char input_data[16] = {0};
	unsigned char output_ByteSub[16] = {0};
	unsigned char output_ShiftRow[4][4] = {0};
	unsigned char output_AddRoundKey[4][4] = {0};
	unsigned char output_MixColumn[4][4] = {0};

	RoundKey(key, input_Key_Square);
#ifdef debug_key
	for (i = 0; i < 60; i++)
	{
		(i % 4 == 0) ? printf("\nkey[%d]=\n", i / 4) : i = i;
		for (j = 0; j < 4; j++)
		{
			printf("%02x", input_Key_Square[j][i]);
		}
	}
#endif

	Initial_Round(input, input_data, key);

#ifdef debug_key
	printf("\n1_RoundKey:\n");
	for (i = 0; i < 16; i++)
	{
		printf("%02x", input_data[i]);
	}
#endif // DEBUG

	for (i = 0; i < 13; i++)
	{
		ByteSub(input_data, output_ByteSub);
#ifdef debug_key
		printf("\nByteSub:\n");
		for (j = 0; j < 16; j++)
		{
			printf("%02x", output_ByteSub[j]);
		}
#endif // DEBUG
		ShiftRow(output_ByteSub, output_ShiftRow);

#ifdef debug_key
		printf("\nShiftRow:\n");
		for (j = 0; j < 4; j++)
		{
			for (k = 0; k < 4; k++)
			{
				printf("%02x", output_ShiftRow[k][j]);
			}
			printf("\n");
		}
#endif // DEBUG

		MixColumn(output_ShiftRow, output_MixColumn);

#ifdef debug_key
		printf("\nMixColumn:\n");
		for (j = 0; j < 4; j++)
		{
			for (k = 0; k < 4; k++)
			{
				printf("%02x", output_MixColumn[k][j]);
			}
			printf("\n");
		}
#endif // DEBUG

		AddRoundKey(output_MixColumn, output_AddRoundKey, i);

#ifdef debug_key
		printf("\nAddRoundKey:\n");
		for (j = 0; j < 4; j++)
		{
			for (k = 0; k < 4; k++)
			{
				printf("%02x", output_AddRoundKey[k][j]);
			}
			printf("\n");
		}
#endif // DEBUG

		for (j = 0; j < 4; j++)
		{
			for (k = 0; k < 4; k++)
			{
				input_data[j * 4 + k] = output_AddRoundKey[k][j];
			}
		}
	}
	ByteSub(input_data, output_ByteSub);

#ifdef debug_key
	printf("\nlast_ByteSub:\n");
	for (j = 0; j < 16; j++)
	{
		printf("%02x", output_ByteSub[j]);
	}
#endif

	ShiftRow(output_ByteSub, output_ShiftRow);

#ifdef debug_key
	printf("\nlast_ShiftRow:\n");
	for (j = 0; j < 4; j++)
	{
		for (k = 0; k < 4; k++)
		{
			printf("%02x", output_ShiftRow[k][j]);
		}
		printf("\n");
	}
#endif

	AddRoundKey(output_ShiftRow, output, 13);

#ifdef debug_key
	printf("\nlast_AddRoundKey:\n");
	for (j = 0; j < 4; j++)
	{
		for (k = 0; k < 4; k++)
		{
			printf("%02x", output[k][j]);
		}
		printf("\n");
	}
#endif
}

void AES_Decrypt(unsigned char key[32], unsigned char input[4][4], unsigned char output[4][4])
{
	int i = 0, j = 0, k = 0;
	unsigned char output_Inv_AddRoundKey[4][4];
	unsigned char output_Inv_ShiftRow[4][4];
	unsigned char output_Inv_MixColumn[4][4];
	unsigned char output_Inv_ShiftRow1[4][4];
	RoundKey(input_Key, input_Key_Square);
	Inv_AddRoundKey(input, output_Inv_AddRoundKey, 0);

	Inv_ShiftRow_Box(output_Inv_AddRoundKey, output_Inv_ShiftRow);

	for (i = 0; i < 13; i++)
	{
		Inv_AddRoundKey(output_Inv_ShiftRow, output_Inv_AddRoundKey, i + 1);
		Inv_MixColumn(output_Inv_AddRoundKey, output_Inv_MixColumn);
		Inv_ShiftRow_Box(output_Inv_MixColumn, output_Inv_ShiftRow);
	}
	Inv_AddRoundKey(output_Inv_ShiftRow, output, 14);
}

void xor_128(unsigned char a[16], unsigned char b[16], unsigned char out[16])
{
	char i;
	for (i = 0; i < 16; i++)
	{
		out[i] = a[i] ^ b[i];
	}
}

void xor_128_dif(unsigned char a[4][4], unsigned char b[16], unsigned char out[16])
{
	int j, k;
	for (j = 0; j < 4; j++)
	{
		for (k = 0; k < 4; k++)
		{
			out[j * 4 + k] = a[k][j] ^ b[j * 4 + k];
		}
	}
}

void leftshift_onebit(unsigned char input[16], unsigned char output[16])
{
	int i, j, k;
	unsigned char overflow = 0;
	for (i = 15; i >= 0; i--)
	{
		output[i] = input[i] << 1;
		output[i] |= overflow;
		overflow = (input[i] & 0x80) ? 1 : 0;
	}
	return;
}

void generate_subkey(unsigned char key[32], unsigned char K1[16], unsigned char K2[16])
{
	unsigned char K1_input[16] = {0};
	unsigned char K1_output[16] = {0};
	unsigned char K1_out[4][4] = {0};
	unsigned char const_Rb[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87};
	unsigned char tmp[16] = {0};
	char i, j, k;

	AES_Encrypted(key, K1_input, K1_out);
	for (j = 0; j < 4; j++)
	{
		for (k = 0; k < 4; k++)
		{
			// printf("%x  ", K1_out[j][k]);
			K1_output[j * 4 + k] = K1_out[k][j];
		}
		// printf("\n");
	}
	// printf("%x  ", K1_output[0]);
	if (K1_output[0] < 128)
	{ /* If MSB(L) = 0, then K1 = L << 1 */
		leftshift_onebit(K1_output, K1);
	}
	else
	{ /* Else K1 = ( L << 1 ) (+) Rb */
		leftshift_onebit(K1_output, tmp);
		xor_128(tmp, const_Rb, K1);
	}

	if (K1[0] < 128)
	{
		leftshift_onebit(K1, K2);
	}
	else
	{
		leftshift_onebit(K1, tmp);
		xor_128(tmp, const_Rb, K2);
	}
	return;
}

void Multiple_128(unsigned char A[16], unsigned char B[16], unsigned char X[16])
{
	unsigned char value1[128] = {0};
	unsigned char value2[128] = {0};
	unsigned char value3[128] = {0};
	unsigned char value4[128] = {0};
	int i, t, k, w;
	unsigned char Binn[128] = {1, 1, 1, 0, 0, 0, 0, 1};
	unsigned char PP[8] = {0};
	for (t = 0; t < 16; t++)
	{
		Hex2Bin(A[t]);
		for (i = 0; i < 8; i++)
		{
			value1[i + t * 8] = Binary[i];
		}
	}
	for (t = 0; t < 16; t++)
	{
		Hex2Bin(B[t]);
		for (i = 0; i < 8; i++)
		{

			value2[i + t * 8] = Binary[i];
		}
	}
	for (i = 0; i < 128; i++)
	{
		if (i > 0)
		{
			if (value1[127] == 0)
			{
				for (t = 0; t < 127; t++)
				{
					value1[127 - t] = value1[126 - t];
				}
				value1[0] = 0;
			}
			else if (value1[127] == 1)
			{
				for (t = 0; t < 127; t++)
				{
					value1[127 - t] = value1[126 - t];
				}
				value1[0] = 0;
				for (k = 0; k < 128; k++)
				{
					value1[k] = value1[k] ^ Binn[k];
				}
			}
		}
		if (value2[i] == 1)
		{
			for (w = 0; w < 128; w++)
			{
				value4[w] = value1[w] ^ value4[w];
			}
		}
	}

	for (i = 0; i < 16; i++)
	{
		for (t = 0; t < 8; t++)
		{
			PP[t] = value4[t + 8 * i];
		}
		X[i] = Bin2Dec(PP);
	}
}

void AES_CMAC(unsigned char key[32], unsigned char input[], int len, unsigned char output[16])
{
	unsigned char K1[16], K2[16];
	int i, j, k;
	unsigned char input_da[2000] = {0};
	unsigned char in_state[16];
	unsigned char xor_state[16];
	unsigned char xor_state_last[16];
	unsigned char out_state[4][4] = {0};
	int Din_Block_num = len / 6;
	int num_remainder;
	unsigned char keyyy[32] = {0};
	for (i = 0; i < 32; i++)
	{
		keyyy[i] = key[i];
	}
	generate_subkey(keyyy, K1, K2);

	for (i = 0; i < len; i++)
	{
		input_da[i] = input[i];
	}
	num_remainder = len % 16;
	if (num_remainder > 0)
	{
		Din_Block_num = Din_Block_num++;
		for (i = 0; i < 16 - num_remainder; i++)
		{
			if (i == 0)
				input_da[len + i] = 0x80;
			else
				input_da[len + i] = 0x00;
		}
	}
	for (i = 0; i < Din_Block_num; i++)
	{
		if (i == 0 && i != Din_Block_num - 1)
		{
			for (j = 0; j < 16; j++)
			{
				in_state[j] = input_da[j];
			}
			AES_Encrypted(keyyy, in_state, out_state);
		}
		else if (i > 0 && i != Din_Block_num - 1)
		{
			for (j = 0; j < 16; j++)
			{
				in_state[j] = input_da[i * 16 + j];
			}
			xor_128_dif(out_state, in_state, xor_state);
			AES_Encrypted(keyyy, xor_state, out_state);
		}
		else if (i == Din_Block_num - 1)
		{
			for (j = 0; j < 16; j++)
			{
				in_state[j] = input_da[i * 16 + j];
			}
			xor_128_dif(out_state, in_state, xor_state);
			if (num_remainder == 0)
				xor_128(xor_state, K1, xor_state_last);
			else if (num_remainder != 0)
				xor_128(xor_state, K2, xor_state_last);
			AES_Encrypted(keyyy, xor_state_last, out_state);
		}
	}

	for (j = 0; j < 4; j++)
	{
		for (k = 0; k < 4; k++)
		{
			output[j * 4 + k] = out_state[k][j];
		}
	}
}

void GCTR(unsigned char key[32], unsigned char J[16], unsigned char input[], int input_len, unsigned char output[])
{
	unsigned char Cipher_tmp[4][4];
	int i, j, k;
	int Din_Block_num = (input_len + 16) / 16;
	for (i = 0; i < Din_Block_num + 1; i++)
	{
		// CIPH(CB,K)
		AES_Encrypted(key, J, Cipher_tmp);
		// data_in XOR CIPH(CB,K)
		for (j = 0; j < 4; j++) // transform 2 dimension array to 1 dimension EY0
		{
			for (k = 0; k < 4; k++)
			{
				output[j * 4 + k + (i - 1) * 16] = Cipher_tmp[k][j] ^ input[j * 4 + k + (i - 1) * 16];
			}
		}
		// increment J
		for (j = 15; j >= 0; j--)
		{
			if (J[j] == 0xFF)
				J[j] = 0;
			else
			{
				J[j] += 1;
				break;
			}
		}
	}
	memset(output + input_len, 0x00, 16 - (input_len % 16));
}

int countBits(unsigned char byte)
{
	int count = 0;
	while (byte)
	{
		count += byte & 1;
		byte >>= 1;
	}
	return count;
}

void AES_GCM(unsigned char key[32], unsigned char attach[20], unsigned char IV[12], unsigned char input[], unsigned char Mask[2],
			 int len_data, int len_A, unsigned char output[], unsigned char GMAC[16])
{
	unsigned char Cipher_tmp[4][4];	  // ciphertext temp
	unsigned char Y_result[16] = {0}; // GMAC Y_result
	unsigned char xor_tmp[16] = {0};  // multiple output
	unsigned char Attach_1[16] = {0}; // attach block 1
	unsigned char Attach_2[16] = {0}; // attach block 2
	unsigned char H[16] = {0};		  // H = AES-256(K, 0)
	unsigned char INPUT[2000] = {0};  // plain text
	unsigned char J[16] = {0};		  // J = IV || 0^31 || 0^8 || 0^1	        ( Len(IV) == 96bit )
	int AA, CC, Mask_cnt;			  // AA: attach length, CC: cipher length  ( bits length of valid bytes )
	unsigned char Length[16] = {0};	  // Length = (AA || CC)                   ( 128bit )
	unsigned char EY0[16] = {0};	  // CIPH(J0,K)
	int Din_Block_num;
	int i, j, k;

	memset(Length, 0x00, 16);
	memset(Y_result, 0x00, 16);
	Mask_cnt = countBits(Mask[0]) + countBits(Mask[1]);
	CC = len_data * 8;
	AA = len_A * 8 + Mask_cnt;
	Din_Block_num = (len_data + 15) / 16;

	for (i = 7; i >= 0; i--)
	{
		Length[i] = AA % 256;
		AA /= 256;
	}
	for (i = 7; i >= 0; i--)
	{
		Length[i + 8] = CC % 256;
		CC /= 256;
	}
	memset(output, 0x00, Din_Block_num * 16);
	memcpy(INPUT, input, len_data);
	memset(INPUT + len_data, 0x00, 2000 - len_data);
	// divide attach to 2 parts and padding
	memcpy(Attach_1, attach, 16);
	memcpy(Attach_2, attach + 16, len_A % 16);
	memset(Attach_2 + len_A % 16, 0x00, 16 - (len_A % 16));

#ifdef debug_Din
	printf("\nlen_data = %d\n", len_data);
	printf("len_A = %d\n", len_A);
	printf("CC = %d\n", CC);
	printf("AA = %d\n", AA);
	for (i = 0; i < 16; i++)
	{
		i == 0 ? printf("AA_l: \n") : i = i;
		i == 8 ? printf("\nCC_l: \n") : i = i;
		printf("0x%02X ,", Length[i]);
	}
	printf("\n");
	printf("\nDin_Block_num: \n%d\n", Din_Block_num);
	printf("INPUT data: ");
	for (i = 0; i < len_data; i++)
	{
		if (i % 16 == 0)
			printf("\n");
		printf("0x%02X ,", INPUT[i]);
	}
	printf("\n");
	printf("Attach_1: \n");
	for (i = 0; i < 16; i++)
		printf("0x%02X ,", Attach_1[i]);
	printf("\n");
	printf("Attach_2: \n");
	for (i = 0; i < 16; i++)
		printf("0x%02X ,", Attach_2[i]);
	printf("\n");
#endif

	/********************************************compute GCM*****************************************************/
	//  C = GCTR(J,P,K)
	//  note: CIPHER = MSBlen_data(output)
	memcpy(J, IV, 12);
	memset(J + 12, 0x00, 3);
	J[15] = 0x01;

#ifdef debug_GCM_J
	printf("J0: \n");
	for (i = 0; i < 16; i++)
		printf("0x%02X ,", J[i]);
	printf("\n");
#endif
	// GCTR(J0+1,P,K)
	for (i = 0; i < Din_Block_num + 1; i++)
	{
		// CIPH(CB,K)
		AES_Encrypted(key, J, Cipher_tmp);
		if (!i) // EY0 used for GMAC
		{
			for (j = 0; j < 4; j++)
			{
				for (k = 0; k < 4; k++)
				{
					EY0[j * 4 + k] = Cipher_tmp[k][j];
				}
			}

#ifdef debug_EY0
			printf("EY0%d: \n", i + 1);
			for (j = 0; j < 16; j++)
				printf("0x%02X ,", EY0[j]);
			printf("\n");
#endif
		}

		else // used for generate ciphertext
		{
			// data_in XOR CIPH(CB,K)
			for (j = 0; j < 4; j++)
			{
				for (k = 0; k < 4; k++)
				{
					output[j * 4 + k + (i - 1) * 16] = Cipher_tmp[k][j] ^ INPUT[j * 4 + k + (i - 1) * 16];
				}
			}

#ifdef debug_GCM_Y
			printf("GCM_Y%d: \n", i);
			for (j = 16 * (i - 1); j < 16 * i; j++)
				printf("0x%02X ,", output[j]);
			printf("\n");
#endif
		}

		// increment J
		for (j = 15; j >= 0; j--)
		{
			if (J[j] == 0xFF)
				J[j] = 0;
			else
			{
				J[j] += 1;
				break;
			}
		}

#ifdef debug_GCM_J
		printf("J incresment%d: \n", i + 1);
		for (j = 0; j < 16; j++)
			printf("0x%02X ,", J[j]);
		printf("\n");
#endif
	}
	// padding GCM to complete block
	memset(output + len_data, 0x00, 16 - (len_data % 16));

	/**************************************************end*******************************************************/

	/********************************************compute GMAC****************************************************/

	// 2-1. H = CIPH(K, 0)
	AES_Encrypted(key, Y_result, Cipher_tmp);

	for (j = 0; j < 4; j++) // transform 2 dimension array to 1 dimension array for H
		for (k = 0; k < 4; k++)
			H[j * 4 + k] = Cipher_tmp[k][j];

#ifdef debug_H
	printf("H: \n");
	for (i = 0; i < 16; i++)
		printf("0x%02X ,", H[i]);
	printf("\n");
#endif

	// 2-2. GHASH(A, H)
	Multiple_128(Attach_1, H, Y_result); // A1 * H = Y1

#ifdef debug_GMAC_Y
	printf("Y1: ");
	for (i = 0; i < 16; i++)
		(i % 16 == 0) ? printf("\n0x%02X ,", Y_result[i]) : printf("0x%02X ,", Y_result[i]);
#endif

	if (len_A > 16)
	{
		xor_128(Attach_2, Y_result, xor_tmp);
#ifdef debug_GMAC_Y
		printf("Y1 ^ A2: ");
		for (i = 0; i < 16; i++)
			(i % 16 == 0) ? printf("\n0x%02X ,", xor_tmp[i]) : printf("0x%02X ,", xor_tmp[i]);
#endif
		Multiple_128(xor_tmp, H, Y_result); //(A2 ^ Y1) * H = Y2
	}

#ifdef debug_GMAC_Y
	printf("Y2: ");
	for (i = 0; i < 16; i++)
		(i % 16 == 0) ? printf("\n0x%02X ,", Y_result[i]) : printf("0x%02X ,", Y_result[i]);
#endif

	// 2-3. GHASH(C, H)
	for (i = 0; i < Din_Block_num; i++) // (Cn ^ Yn+1) * H = Yn+2
	{
		xor_128(output + i * 16, Y_result, xor_tmp);
#ifdef debug_GMAC_Y
		printf("Y%d ^ C%d: ", i + 2, i + 1);
		for (j = 0; j < 16; j++)
			(j % 16 == 0) ? printf("\n0x%02X ,", xor_tmp[j]) : printf("0x%02X ,", xor_tmp[j]);
		printf("\n");
#endif
		Multiple_128(xor_tmp, H, Y_result);

#ifdef debug_GMAC_Y
		printf("Y%d: ", i + 3);
		for (j = 0; j < 16; j++)
			(j % 16 == 0) ? printf("\n0x%02X ,", Y_result[j]) : printf("0x%02X ,", Y_result[j]);
#endif // debug_GMAC
	}

	// 2-4. GHASH(AA, CC, H)
	xor_128(Length, Y_result, xor_tmp);
#ifdef debug_GMAC_Y
	printf("Y%d ^ len: ", i + 3);
	for (j = 0; j < 16; j++)
		(j % 16 == 0) ? printf("\n0x%02X ,", xor_tmp[j]) : printf("0x%02X ,", xor_tmp[j]);
#endif
	Multiple_128(xor_tmp, H, Y_result); // (len ^ Yn+2) * H = Yn+3

#ifdef debug_GMAC_Y
	printf("Y%d: ", i + 3);
	for (j = 0; j < 16; j++)
		(j % 16 == 0) ? printf("\n0x%02X ,", Y_result[j]) : printf("0x%02X ,", Y_result[j]);
	printf("EY0:\n");
	for (int j = 0; j < 16; j++)
		printf("0x%02X ,", EY0[j]);
#endif // debug_GMAC

	// 2-5  GMAC = GCTR(Yn+3,J0, K)
	xor_128(EY0, Y_result, GMAC);

	/**************************************************end*******************************************************/
}

void crc16(unsigned char input_data[], int length, unsigned char output_crc[2])
{
	uint16_t crc = 0xFFFF;		  // 初始化 CRC 值
	uint16_t polynomial = 0x1021; // CRC 多项式

	for (size_t i = 0; i < length; i++)
	{
		crc ^= (input_data[i] << 8); // 更新 CRC
		for (int j = 0; j < 8; j++)
		{
			if (crc & 0x8000)
			{
				crc = (crc << 1) ^ polynomial; // 进行多项式除法
			}
			else
			{
				crc <<= 1;
			}
			crc &= 0xFFFF; // 确保 CRC 仍在 16 位内
		}
	}

	output_crc[0] = (crc >> 8) & 0xFF; // 高字节
	output_crc[1] = crc & 0xFF;		   // 低字节
}

int main()
{
	unsigned char Encrypted_Result[4][4];
	unsigned char Decrypt_Result[4][4];
	unsigned char CMAC[16] = {0};
	unsigned char GMAC[16] = {0};
	unsigned char GCM[10000];
	int t;
	int len_data;
	int len_A;
	len_data = sizeof(input_Date);
	len_A = sizeof(Attach);
	AES_CMAC(input_Key, input_Date, len_data, CMAC);
	AES_GCM(input_Key, Attach, IV, input_Date, Mask, len_data, len_A, GCM, GMAC);

	// 打印0x形式的输入数据
	printf("Input(0x):\n");
	for (t = 0; t < len_data; t++)
	{
		printf("0x%02X, ", input_Date[t]);
		if ((t + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n");
#ifdef debug_GCM
	// 打印0x形式的GCM数据
	printf("GCM(0x):\n");
	for (t = 0; t < len_data; t++)
	{
		printf("0x%02X, ", GCM[t]);
		if ((t + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n");

	// 打印联合数据GCM
	printf("GCM:\n");
	for (t = 0; t < len_data; t++)
	{
		printf("%02X", GCM[t]);
	}
	printf("\n");
#endif

#ifdef debug_CMAC
	// 打印0x形式的CMAC数据
	printf("CMAC(0x):\n");
	for (t = 0; t < 16; t++)
	{
		printf("0x%02X, ", CMAC[t]);
	}
	printf("\n");

	// 打印联合CMAC数据
	printf("CMAC:\n");
	for (t = 0; t < 16; t++)
	{
		printf("%02X", CMAC[t]);
	}
	printf("\n");
#endif

#ifdef debug_GMAC
	// 打印0x形式的GMAC数据
	printf("GMAC(0x):\n");
	for (t = 0; t < 16; t++)
	{
		printf("0x%02X, ", GMAC[t]);
	}
	printf("\n");

	// 打印联合GMAC数据
	printf("GMAC:\n");
	for (t = 0; t < 16; t++)
	{
		printf("%02X", GMAC[t]);
	}
	printf("\n");

#endif

	return 0;
}