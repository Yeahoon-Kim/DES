#include "des.h"

//학번_이름
char SUBMISSION_INFO[256] = "0000000000_000\0";

// 함수 정의 //typedef uint64_t DES_STATE_t;

typedef union keyHandler
{
	DES_STATE_t wholeKey;
	uint32_t halfKey[2];
	uint8_t block[8];
} DES_KEY_HANDLER;

typedef union bitHandler
{
	DES_STATE_t whole;
	uint32_t half[2];
	uint8_t block[8];
} DES_BIT_HANDLER;

char SBox[8][4][16] = {
		{
			{14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
			{ 0, 15,  7,  4 ,14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
			{ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
			{15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
		},
		{
			{15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
			{ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
			{ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
			{13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
		},
		{
			{10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
			{13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
			{13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
			{ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
		},
		{
			{ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
			{13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
			{10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
			{ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
		},
		{
			{ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
			{14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
			{ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
			{11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
		},
		{
			{12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
			{10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
			{ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
			{ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
		},
		{
			{ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
			{13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
			{ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
			{ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
		},
		{
			{13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
			{ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
			{ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
			{ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
		}
};

DES_KEY_HANDLER Round_Key[16] = { 0 };

DES_STATE_t InitialPermutation(DES_STATE_t P)
{
	char IP[64] = { 58, 50, 42, 34, 26, 18, 10, 2,
					60, 52, 44, 36, 28, 20, 12, 4,
					62, 54, 46, 38, 30, 22, 14, 6,
					64, 56, 48, 40, 32, 24, 16, 8,
					57, 49, 41, 33, 25, 17,  9, 1,
					59, 51, 43, 35, 27, 19, 11, 3,
					61, 53, 45, 37, 29, 21, 13, 5,
					63, 55, 47, 39, 31, 23, 15, 7 };

	DES_STATE_t temp = 0;

	for (char i = 0; i < 64; i++)
	{
		temp += ((P >> (64 - IP[i])) & 0x01);

		if (i == 63) break;
		temp <<= 1;
	}
	return temp;
}

DES_STATE_t permutedChoice_1(DES_STATE_t K)
{
	char PCBox[64] = { 57, 49, 41, 33, 25, 17,  9,  0,
					    1, 58, 50, 42, 34, 26, 18,  0,
					   10,  2, 59, 51, 43, 35, 27,  0,
					   19, 11,  3, 60, 52, 44, 36,  0,
					   63, 55, 47, 39, 31, 23, 15,  0,
					    7, 62, 54, 46, 38, 30, 22,  0,
					   14,  6, 61, 53, 45, 37, 29,  0,
					   21, 13,  5, 28, 20, 12,  4,  0 };

	DES_KEY_HANDLER tempKey = { 0 };

	for (char i = 0; i < 64; i++)
	{
		if (!PCBox[i]) continue;
		tempKey.block[i / 8] |= (K >> (64 - PCBox[i])) & 0x1;
		tempKey.block[i / 8] <<= 1;
	}

	return tempKey.wholeKey;
}

DES_STATE_t keyCirculerForDec(DES_STATE_t K, char round)
{
	DES_KEY_HANDLER tempKey;
	tempKey.wholeKey = K;
	char tempBit[4] = { 0 }, i, j, k;

	for (k = 0; k < round; k++)
	{
		for (i = 0; i < 2; i++)
		{
			for (j = 0; j < 4; j++)
			{
				tempBit[j] = (tempKey.block[i * 4 + j] & 0x02) << 6;
				tempKey.block[i * 4 + j] >>= 1;
				tempKey.block[i * 4 + j] &= 0x7e;
			}

			for (j = 0; j < 4; j++)
			{
				tempKey.block[i * 4 + j] |= tempBit[(j + 3) % 4];
			}
		}
	}

	return tempKey.wholeKey;
}

DES_STATE_t keyCirculer(DES_STATE_t K, char round)
{
	DES_KEY_HANDLER tempKey;
	tempKey.wholeKey = K;
	char tempBit[4] = { 0 }, i, j, k;

	for (k = 0; k < round; k++)
	{
		for (i = 0; i < 2; i++)
		{
			for (j = 0; j < 4; j++)
			{
				tempBit[j] = ((tempKey.block[i * 4 + j] & 0x80) >> 6) & 0x02;
				tempKey.block[i * 4 + j] <<= 1;
				tempKey.block[i * 4 + j] &= 0xfc;
			}

			for (j = 0; j < 4; j++)
			{
				tempKey.block[i * 4 + j] |= tempBit[(j + 1) % 4];
			}
		}
	}
	
	return tempKey.wholeKey;
}

DES_STATE_t permutedChoice_2(DES_STATE_t K)
{
	char PCBox[56] = { 14, 17, 11, 24,  1,  5,  0,
					    3, 28, 15,  6, 21, 10,  0,
					   23, 19, 12,  4, 26,  8,  0,
					   16,  7, 27, 20, 13,  2,  0,
					   41, 52, 31, 37, 47, 55,  0,
					   30, 40, 51, 45, 33, 48,  0,
					   44, 49, 39, 56, 34, 53,  0,
					   46, 42, 50, 36, 29, 32,  0 };
	DES_KEY_HANDLER tempKey = { 0 };
	DES_KEY_HANDLER tempKey2;
	char i, tmp;

	tempKey2.wholeKey = K;

	for (i = 0; i < 56; i++)
	{
		if (!PCBox[i]) {
			continue;
		}

		tmp = PCBox[i] % 7;
		if (!tmp) tmp = 7;

		tempKey.block[i / 7] |= (tempKey2.block[(PCBox[i] - 1) / 7] >> (8 - tmp)) & 0x01;
		tempKey.block[i / 7] <<= 1;
	}

	return tempKey.wholeKey; // 배열의 순서, 메모리 순서 아님
}

uint64_t bitExtension(uint32_t half)
{
	char EBox[56] = {  32,  1,  2,  3,  4,  5,  0,
					    4,  5,  6,  7,  8,  9,  0,
					    8,  9, 10, 11, 12, 13,  0,
					   12, 13, 14, 15, 16, 17,  0,
					   16, 17, 18, 19, 20, 21,  0,
					   20, 21, 22, 23, 24, 25,  0,
					   24, 25, 26, 27, 28, 29,  0, 
					   28, 29, 30, 31, 32,  1,  0 };
	DES_BIT_HANDLER tempBit = { 0 };
	char i;

	for (i = 0; i < 56; i++)
	{
		if (!EBox[i]) {
			continue;
		}
		tempBit.block[i / 7] |= (half >> (32 - EBox[i])) & 0x01;
		tempBit.block[i / 7] <<= 1;
	}
	
	// 배열의 순서, 메모리의 순서 아님
	return tempBit.whole;
}

char SBoxProcessing(uint8_t temp, char num)
{
	char row, column;
	row = ((temp & 0x40) >> 5) | ((temp & 0x02) >> 1);
	column = (temp & 0x3c) >> 2;

	return SBox[num][row][column];
}

uint32_t processP(uint32_t SBoxResult)
{
	char P[32] = { 16,  7, 20, 21,
				   29, 12, 28, 17,
					1, 15, 23, 26,
					5, 18, 31, 10,
					2,  8, 24, 14,
				   32, 27,  3,  9,
				   19, 13, 30,  6,
				   22, 11,  4, 25 };
	char i;
	uint32_t result = 0;

	for (i = 0; i < 32; i++)
	{
		result |= (SBoxResult >> (32 - P[i])) & 0x01;
		if (i == 31) break;

		result <<= 1;
	}
	return result;
}

uint32_t SBoxFunction(uint64_t roundedKey, uint32_t half) // roundedKey : 배열의 순서
{
	uint32_t SBoxResult = 0;
	DES_BIT_HANDLER temp = { 0 };
	char i;

	temp.whole = bitExtension(half); // 배열의 순서, Clear

	temp.whole ^= roundedKey; // 배열의 순서, Clear

	for (i = 0; i < 8; i++)
	{
		SBoxResult |= SBoxProcessing(temp.block[i], i);

		if (i == 7) break;
		SBoxResult <<= 4;
	}

	SBoxResult = processP(SBoxResult);

	return SBoxResult; // 메모리 순서, Clear
}

DES_STATE_t roundSixteen(DES_STATE_t temp, DES_STATE_t K)
{
	DES_KEY_HANDLER tempKey, roundedKey;
	DES_BIT_HANDLER tempBit;
	char keyRounder[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
	char i;
	uint32_t SBoxResult = 0;
	uint8_t extendedBit[8] = { 0 };
	uint32_t tmpInt;
	
	tempBit.whole = temp;
	tempKey.wholeKey = permutedChoice_1(K); // Clear
	
	for (i = 0; i < 16; i++)
	{
		// 라운드키 생성
		tempKey.wholeKey = keyCirculer(tempKey.wholeKey, keyRounder[i]); // Clear
		roundedKey.wholeKey = permutedChoice_2(tempKey.wholeKey); // Clear

		(Round_Key[i]).wholeKey = roundedKey.wholeKey;

		SBoxResult = SBoxFunction(roundedKey.wholeKey, tempBit.half[0]);

		SBoxResult ^= tempBit.half[1];
		tmpInt = tempBit.half[0];
		tempBit.half[0] = SBoxResult;
		tempBit.half[1] = tmpInt;

		if (i == 15)
		{
			tmpInt = tempBit.half[1];
			tempBit.half[1] = tempBit.half[0];
			tempBit.half[0] = tmpInt;
		}
		
	}

	return tempBit.whole;
}

DES_STATE_t InitialPermutationInverse(DES_STATE_t temp)
{
	char IP[64] = { 40,  8, 48, 16, 56, 24, 64, 32,
			  	    39,  7, 47, 15, 55, 23, 63, 31,
				    38,  6, 46, 14, 54, 22, 62, 30,
				    37,  5, 45, 13, 53, 21, 61, 29,
				    36,  4, 44, 12, 52, 20, 60, 28,
				    35,  3, 43, 11, 51, 19, 59, 27,
				    34,  2, 42, 10, 50, 18, 58, 26,
				    33,  1, 41,  9, 49, 17, 57, 25 };

	DES_STATE_t tmp = 0;

	for (char i = 0; i < 64; i++)
	{
		tmp |= ((temp >> (64 - IP[i])) & 0x01);

		if (i == 63) break;
		tmp <<= 1;
	}
	return tmp;
}

DES_STATE_t roundSixteenForDec(DES_STATE_t temp, DES_STATE_t K)
{
	DES_KEY_HANDLER tempKey, roundedKey;
	DES_BIT_HANDLER tempBit;
	char keyRounder[16] = { 4, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1, 1 };
	char i;
	uint32_t SBoxResult = 0;
	uint8_t extendedBit[8] = { 0 };
	uint32_t tmpInt;

	tempBit.whole = temp;
	tempKey.wholeKey = permutedChoice_1(K);

	for (i = 0; i < 16; i++)
	{
		SBoxResult = SBoxFunction((Round_Key[15 - i]).wholeKey, tempBit.half[0]);

		SBoxResult ^= tempBit.half[1];
		tmpInt = tempBit.half[0];
		tempBit.half[0] = SBoxResult;
		tempBit.half[1] = tmpInt;

		if (i == 15)
		{
			tmpInt = tempBit.half[1];
			tempBit.half[1] = tempBit.half[0];
			tempBit.half[0] = tmpInt;
		}

	}

	return tempBit.whole;
}

void DES_enc(DES_STATE_t * C, DES_STATE_t P, DES_STATE_t K)
{
	DES_STATE_t temp;

	temp = InitialPermutation(P); // 완벽
	temp = roundSixteen(temp, K);
	*C = InitialPermutationInverse(temp);
}

void DES_dec(DES_STATE_t * P, DES_STATE_t C, DES_STATE_t K)
{
	DES_STATE_t temp;

	temp = InitialPermutation(C);
	temp = roundSixteenForDec(temp, K);
	*P = InitialPermutationInverse(temp);
}
