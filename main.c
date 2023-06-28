#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int main(int argc, char *argv[]) {
	uint32_t w[NB*(NR128+1)];
	uint8_t key[AES128], block[BLKSIZ];

	FILE *fp = fopen("key", "rb");
	fread(key, 1, AES128, fp);
	fclose(fp);

	fp = fopen("block", "rb");
	fread(block, 1, BLKSIZ, fp);
	fclose(fp);

	KeyExpansion(key, w, AES128);

	Cipher128(block, w);

	printf("%s\n", block);

	return 0;
}
