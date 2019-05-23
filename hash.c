#include <stdio.h>
#include "hash.h"

typedef unsigned long long u_int64;

u_int64 AwareHash(u_char* data, u_int64 n,
        u_int64 hash, u_int64 scale, u_int64 hardener) {

	while (n) {
		hash *= scale;
		hash += *data++;
		n--;
	}
	return hash ^ hardener;
}


void mangle(const u_char* key, u_char* ret_key,
		int nbytes) {
	for (int i=0; i<nbytes; ++i) {
		ret_key[i] = key[nbytes-i-1];
	}

    if (nbytes == 13) {
		ret_key[0] = key[5];
		ret_key[1] = key[11];
		ret_key[2] = key[7];
		ret_key[3] = key[6];
		ret_key[4] = key[1];
		ret_key[5] = key[9];
		ret_key[6] = key[10];
		ret_key[7] = key[4];
		ret_key[8] = key[2];
		ret_key[9] = key[8];
		ret_key[10] = key[12];
		ret_key[11] = key[0];
		ret_key[12] = key[3];
    }
}

void unmangle(const u_char* key, u_char* ret_key,
		int nbytes) {
	for (int i=0; i<nbytes; ++i) {
		ret_key[i] = key[nbytes-i-1];
	}

    if (nbytes == 13) {
		ret_key[0] = key[11];
		ret_key[1] = key[4];
		ret_key[2] = key[8];
		ret_key[3] = key[12];
		ret_key[4] = key[7];
		ret_key[5] = key[0];
		ret_key[6] = key[3];
		ret_key[7] = key[2];
		ret_key[8] = key[9];
		ret_key[9] = key[5];
		ret_key[10] = key[6];
		ret_key[11] = key[1];
		ret_key[12] = key[10];
    }
}


u_int64 seed = 0;
u_int64 GenHashSeed(int index) {
   
    if (seed == 0) {
        seed = rand();
    }
    u_int64 x, y = seed + index;
    mangle((const u_char*)&y, (u_char*)&x, 8);
    return AwareHash((u_int8*)&y, 8, 388650253, 388650319, 1176845762);
}

int is_prime(int num) {
    int i;
    for (i=2; i<num; i++) {
        if ((num % i) == 0) {
            break;
        }
    }
    if (i == num) {
        return 1;
    }
    return 0;
}

int calc_next_prime(int num) {
    while (!is_prime(num)) {
        num++;
    }
    return num;
}