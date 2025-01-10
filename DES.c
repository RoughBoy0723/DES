#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

/*
 * DES는 키 길이가 64 bit 하지만 실제 사용하는건 56bit, 8bit는 parity bit로 사용된다. 
 * 블록 크기는 64bit
 * 
 * 
 * 
 */

const int message_initial_permutation[64] = {
	58, 50, 42, 34, 26, 18, 10, 02,
	60, 52, 44, 36, 28, 20, 12, 04,
	62, 54, 46, 38, 30, 22, 14, 06,
	57, 49, 41, 33, 25, 17, 9, 01,
	59, 51, 43, 35, 27, 19, 11, 03,
	61, 53, 45, 37, 29, 21, 13, 05,
	63, 55, 47, 39, 31, 23, 15, 07
};

const int inverse_message_final_permutation[64] = {
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 07, 47, 15, 55, 23, 63, 31,
	38, 06, 46, 14, 54, 22, 62, 30,
	37, 05, 45, 13, 53, 21, 61, 29,
	36, 04, 44, 12, 52, 20, 60, 28,
	35, 03, 43, 11, 51, 19, 59, 27,
	34, 02, 42, 10, 50, 18, 58, 26,
	33, 01, 41, 9, 49, 17, 57, 25
};

const int expansion_p_box[48] = {
	32, 01, 02, 03, 04, 05,
	04, 05, 06, 07, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 01
};

const int straight_p_box[32] = {
	16, 07, 20, 21, 
	29, 12, 28, 17,
	01, 15, 23, 26, 
	05, 18, 31, 10,
	02, 8, 24, 14, 
	32, 27, 03, 9,
	19, 13, 30, 06, 
	22, 11, 04, 25
};

const int left_shift[16] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 
};

const int S1[4][16] = {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
			 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
			 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
			15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 
};

const int S2[4][16] = { 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
			 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
			 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
			13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 
};

const int S3[4][16] = { 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
			13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
			13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
			 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 
};

const int S4[4][16] = { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
			13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
			10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
			 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 
};

const int S5[4][16] = { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
			14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
			 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
			11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 
};

const int S6[4][16] = { 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
			10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
			 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
			 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 
};

const int S7[4][16] = { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
			13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
			 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
			 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 
};

const int S8[4][16] = { 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
			 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
			 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
			 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 
};

const int permuted_choice1[56] = {
	57, 49, 41, 33, 25, 17, 9,
	01, 58, 50, 42, 34, 26, 18,
	10, 02, 59, 51, 43, 35, 27,
	19, 11, 03, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	07, 62, 54, 46, 38, 30, 22,
	14, 06, 61, 53, 45, 37, 29,
	21, 13, 05, 28, 20, 12, 04
};

const int permuted_choice2[48] = {
	14, 17, 11, 24, 01, 05,
	03, 28, 15, 06, 21, 10,
	23, 19, 12, 04, 26, 8,
	16, 07, 27, 20, 13, 02,
	41, 52, 31 ,37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

// char 2byte, int 4byte 
// 16bit * 4 , 32bit * 2
// DES는 64bit 블록 암호화 구현


unsigned long long Key_Generation() {
	unsigned long long key = 0;

	// BCryptGenRandom 함수 호출로 암호학적으로 안전한 난수 생성
	if (BCryptGenRandom(NULL, (PUCHAR)&key, sizeof(key), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
		fprintf(stderr, "Error generating random bytes\n");
		exit(EXIT_FAILURE);
	}

	return key;
}


//치환 함수 좀 더 분석할것
unsigned long long Permuter_Choice(unsigned long long var, const int pc[], int number) {
	int a;
	unsigned long long numb = 0x00;
	unsigned long long aft_ch = 0x00;

	for (a = 0; a < number; a++) { // (컴퓨터는 0부터 센다)
		numb = var >> ((number + 8) - pc[a]); // 원하는 자리의 비트를 63번째까지 shift(뒤에 비트를 삭제해줌)
		if (number == 56) // 64->56(pc1)
		{
			numb = numb << (number + 7); // 63번째 비트를 0번째 자리로 가져간다.
			numb = numb >> (a + 8);      // long long은 64비트로 이뤄져 있기 때문에 56비트를 만들기 위해서는 8을 더해줌
			aft_ch = (aft_ch | numb);
		}
		else // number = 48 // 56->48(pc2)
		{
			numb = var >> ((number + 8) - pc[a]);
			numb = numb << (number + 15);
			numb = numb >> (a + 16);
			aft_ch = (aft_ch | numb);
		}
	}
	return aft_ch;
}

//이것도 더 분석 할것 치환 알고리즘에 대한 이해가 부족
unsigned long long Expansion_Bit(unsigned long R) {
	unsigned long long res = 0;
	for (int i = 0; i < 48; i++) {
		if ((R >> (31 - expansion_p_box[i])) & 1) {
			res |= (1ULL << (47 - i));
		}
	}
	return res;
}

unsigned long Rotation(unsigned long num, unsigned int n) {
	return (((num << n) & 0xffffffff) | (num >> (28 - n)));
}

void Key_Schedule(unsigned long long key, unsigned long long *sub_key) {
	unsigned long long tmp = 0;
	
	unsigned long K = 0, D = 0;
	tmp = Permuter_Choice(key, permuted_choice1, 56);

	K = tmp >> 28;
	D = (tmp << 28) >> 28;
	for (int i = 0; i < 16; i++) {
		K = Rotation(K, left_shift[i]);
		D = Rotation(D, left_shift[i]);

		tmp = (unsigned long long)K << 28;
		tmp |= D;

		sub_key[i] = Permuter_Choice(tmp, permuted_choice2, 48);
	}

}

unsigned long long S_Box(unsigned long long num) {

	//num 은 48 bit니까 S_box 들어가기전 6비트 8개로 쪼개줘야함

	unsigned char rows[8], cols[8];

	unsigned long long res = 0x00;

	for (int i = 7; i >= 0; i--) {
		rows[i] = num & 0b00100001;
		rows[i] = (rows[i] & 0b00000001) | (rows[i] >> 4);

		cols[i] = (num & 0b00011110) >> 1;

		num = num >> 6;
	}

	//S-Box를 3차원으로 만들고 이것도 for문으로 변경
	res |= S8[rows[7]][cols[7]];
	res |= (unsigned long long)S7[rows[6]][cols[6]] << 4;
	res |= (unsigned long long)S6[rows[5]][cols[5]] << 8;
	res |= (unsigned long long)S5[rows[4]][cols[4]] << 12;
	res |= (unsigned long long)S4[rows[3]][cols[3]] << 16;
	res |= (unsigned long long)S3[rows[2]][cols[2]] << 20;
	res |= (unsigned long long)S2[rows[1]][cols[1]] << 24;
	res |= (unsigned long long)S1[rows[0]][cols[0]] << 28;
	
	return res;
}

unsigned long long Initial_Permuter(unsigned long long plain_text) {
	unsigned long long aftpt = 0;
	for (int i = 0; i < 64; i++) {
		aftpt |= ((plain_text >> (64 - message_initial_permutation[i])) & 0x01) << (63 - i);
	}
	return aftpt;
}

unsigned long long Inverse_Initial_Permuter(unsigned long long cipher_text) {
	unsigned long long aftct = 0;
	for (int i = 0; i < 64; i++) {
		aftct |= ((cipher_text >> (64 - inverse_message_final_permutation[i])) & 0x01) << (63 - i);
	}
	return aftct;
}

unsigned long Primitive(unsigned long num) {
	unsigned long res = 0;
	for (int i = 0; i < 32; i++) {
		if ((num >> (31 - straight_p_box[i])) & 1) {
			res |= (1UL << (31 - i));
		}
	}
	return res;
}

void Enc(unsigned long long* plain_text, unsigned long long* cipher_text, unsigned long long key) {
	unsigned long long tmp = 0x00;
	unsigned long long sub_key[16];
	unsigned long long L_tmp = 0;

	Key_Schedule(key, sub_key);
	// 32bit R, L로 나누기

	tmp = Initial_Permuter(*plain_text);

	/*****************************************************/

	unsigned long L, R;

	L = tmp >> 32;
	R = (tmp << 32) >> 32;

	for (int i = 0; i < 16; i++) {
		L_tmp = L;

		tmp = Expansion_Bit(R);
		tmp ^= sub_key[i];
		R = S_Box(tmp);
		R = Primitive(R); // P-박스 추가
		R ^= L_tmp;

		L = R;
		R = L_tmp;
	}

	// Final swap after the loop
	tmp = R;
	R = L;
	L = tmp;

	tmp = ((unsigned long long)L << 32) | R;
	*cipher_text = Inverse_Initial_Permuter(tmp);
}

void Dec(unsigned long long* cipher_text, unsigned long long* plain_text, unsigned long long key) {
	unsigned long long tmp = 0x00;
	unsigned long long sub_key[16];
	unsigned long long L_tmp = 0;

	Key_Schedule(key, sub_key);
	// 32bit R, L로 나누기

	tmp = Inverse_Initial_Permuter(*cipher_text);

	/*****************************************************/

	unsigned long L, R;

	L = tmp >> 32;
	R = (tmp << 32) >> 32;

	for (int i = 15; i >= 0; i--) { // Reverse subkey order
		L_tmp = L;

		tmp = Expansion_Bit(R);
		tmp ^= sub_key[i];
		R = S_Box(tmp);
		R = Primitive(R); // P-box *before* XOR
		R ^= L_tmp;

		L = R;
		R = L_tmp; // Swap L and R for next round, but not the last round
	}

	// Final swap after the loop
	tmp = R;
	R = L;
	L = tmp;

	tmp = ((unsigned long long)L << 32) | R;
	*plain_text = Initial_Permuter(tmp);
}

int main()
{
	// Key 생성

	unsigned long long key = Key_Generation();


	//평문
	unsigned long long plain_text = 0x0123456789ABCDEF;

	unsigned long long cipher_text = 0;

	unsigned long long decrypt_text = 0;
	
	printf("Plain Text : %llx\n", plain_text);
	printf("Key : %llx\n", key);

	Enc(&plain_text, &cipher_text, key);

	printf("Cipher Text : %llx\n", cipher_text);
	
	Dec(&cipher_text, &decrypt_text, key);

	printf("Decrypt Text : %llx\n", decrypt_text);
	// 정수를 초기치환

	// 정수를 L, R로 나누기

	// R을 P-box로 32 -> 48비트로 확장

	// R을 Key(48bit)와 xor연산
	
	// S-Boxes로 32bit로 축소

	//단순 치환 P-Box 32bit -> 32bit 

	// L, R swap (마지막 스왑은 생략)
	
	//16번 반복

	// 암호문 최종 치환

	//암호문 출력

	// K
}