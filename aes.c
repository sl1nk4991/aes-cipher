#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

void KeyExpansion(byte *key, word *w, byte aes) {
	word temp;
	byte nk, nr;

	switch (aes) {
		case AES128:
			nk = NK128;
			break;
		case AES192:
			nk = NK192;
			break;
		case AES256:
			nk = NK256;
			break;
		default:
			fprintf(stderr, "unknown aes key length\nexiting...\n");
			exit(EXIT_FAILURE);
	}

	nr = nk + 6;

	memcpy(w, key, aes);

	int i = nk;

	while (i < NB * (nr + 1)) {
		temp = w[i-1];
		if(i % nk == 0)
			temp = SubWord(RotWord(temp)) ^ Rcon[i/nk];
		else if(nk > 6 && i % nk == 4)
			temp = SubWord(temp);
		w[i] = w[i-nk] ^ temp;
		i++;
	}
}

void Cipher128(byte *state, word *w) {
	AddRoundKey(state, w);

	for(int i = 1; i <= NR128 - 1; i++) {
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, &w[i * NB]);
	}

	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, &w[NR128 * NB]);
}

void InvCipher128(byte *state, word *w) {
	AddRoundKey(state, &w[NR128 * NB]);

	for(int i = NR128 - 1; i >= 1; i--) {
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(state, &w[i * NB]);
		InvMixColumns(state);
	}

	InvShiftRows(state);
	InvSubBytes(state);
	AddRoundKey(state, w);
}

void AddRoundKey(byte *state, word *rkey) {
	for(int i = 0; i < BLKSIZ; i++) {
		state[i] ^= ((byte*)rkey)[i];
	}
}

void SubBytes(byte *state) {
	static uint8_t x, y;

	for(int i =  0; i < BLKSIZ; i++) {
		x = (state[i] & ~15) >> 4;
		y = state[i] & 15;
		state[i] = sbox[x][y];
	}
}

void InvSubBytes(byte *state) {
	static uint8_t x, y;

	for(int i =  0; i < BLKSIZ; i++) {
		x = (state[i] & ~15) >> 4;
		y = state[i] & 15;
		state[i] = rsbox[x][y];
	}
}

void ShiftRows(byte *state) {
	static uint8_t temp;

	for(int i = 1; i < NB; i++) {
		byte *row = &state[NB*i];

		for(int j = 0; j < i; j++) {
			temp = row[0];

			for(int k = 0; k < NB - 1; k++) {
				row[k] = row[k+1];
			}

			row[3] = temp;
		}
	}
}

void InvShiftRows(byte *state) {
	static uint8_t temp;

	for(int i = 1; i < NB; i++) {
		byte *row = &state[NB*i];

		for(int j = 0; j < i; j++) {
			temp = row[3];

			for(int k = NB -1; k > 0; k--) {
				row[k] = row[k-1];
			}

			row[0] = temp;
		}
	}
}

uint8_t GMul(byte a, byte b);

void MixColumn(byte *column) {
	byte a[4];

	for(int i = 0; i < 4; i++) {
		a[i] = column[i];
	}

	column[0] = GMul(2, a[0]) ^ GMul(3, a[1]) ^ a[2]          ^ a[3];
	column[1] = a[0]          ^ GMul(2, a[1]) ^ GMul(3, a[2]) ^ a[3];
	column[2] = a[0]          ^ a[1]          ^ GMul(2, a[2]) ^ GMul(3, a[3]);
	column[3] = GMul(3, a[0]) ^ a[1]          ^ a[2]          ^ GMul(2, a[3]);
}

void MixColumns(byte *state) {
	byte a[4];

	for(int i = 0; i < 4; i++) {
		for(int j = 0; j < 4; j++) {
			a[j] = state[i+NB*j];
		}

		state[i+NB*0] = GMul(2, a[0]) ^ GMul(3, a[1]) ^ a[2]          ^ a[3];
		state[i+NB*1] = a[0]          ^ GMul(2, a[1]) ^ GMul(3, a[2]) ^ a[3];
		state[i+NB*2] = a[0]          ^ a[1]          ^ GMul(2, a[2]) ^ GMul(3, a[3]);
		state[i+NB*3] = GMul(3, a[0]) ^ a[1]          ^ a[2]          ^ GMul(2, a[3]);
	}
}

void InvMixColumn(byte *column) {
	byte a[4];

	for(int i = 0; i < 4; i++) {
		a[i] = column[i];
	}

	column[0] = GMul(14, a[0]) ^ GMul(11, a[1]) ^ GMul(13, a[2]) ^ GMul(9,  a[3]);
	column[1] = GMul(9,  a[0]) ^ GMul(14, a[1]) ^ GMul(11, a[2]) ^ GMul(13, a[3]);
	column[2] = GMul(13, a[0]) ^ GMul(9,  a[1]) ^ GMul(14, a[2]) ^ GMul(11, a[3]);
	column[3] = GMul(11, a[0]) ^ GMul(13, a[1]) ^ GMul(9,  a[2]) ^ GMul(14, a[3]);
}

void InvMixColumns(byte *state) {
	byte a[4];

	for(int i = 0; i < 4; i++) {
		for(int j = 0; j < 4; j++) {
			a[j] = state[i+NB*j];
		}

		state[i+NB*0] = GMul(14, a[0]) ^ GMul(11, a[1]) ^ GMul(13, a[2]) ^ GMul(9,  a[3]);
		state[i+NB*1] = GMul(9,  a[0]) ^ GMul(14, a[1]) ^ GMul(11, a[2]) ^ GMul(13, a[3]);
		state[i+NB*2] = GMul(13, a[0]) ^ GMul(9,  a[1]) ^ GMul(14, a[2]) ^ GMul(11, a[3]);
		state[i+NB*3] = GMul(11, a[0]) ^ GMul(13, a[1]) ^ GMul(9,  a[2]) ^ GMul(14, a[3]);
	}
}

word SubWord(word __word) {
	byte x, y, *in = (byte*)&__word;

	for(int i = 0; i < 4; i++) {
		x = (in[i] & ~15) >> 4;
		y = in[i] & 15;
		in[i] = sbox[x][y];
	}

	return *((word*)in);
}

word RotWord(word __word) {
	byte temp, *in = (byte*)&__word;

	temp = in[0];

	for(int i = 0; i < 3; i++) {
		in[i] = in[i+1];
	}

	in[3] = temp;

	return *((word*)in);
}

uint8_t GMul(byte a, byte b) {
	byte h, p = 0;

	for(int i = 0; b != 0; i++) {
		if((b & 1) != 0) {
			p ^= a;
		}

		h = (a >> 7) & 1;
		a <<= 1;
		a ^= h * 0x1b;
		b >>= 1;
	}

	return p;
}
