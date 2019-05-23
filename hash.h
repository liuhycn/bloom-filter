#include <stdint.h>
#include <stdlib.h>

u_int64 AwareHash(unsigned char* data, u_int64 n,
        u_int64 hash, u_int64 scale, u_int64 hardener);
u_int64 AwareHash_debug(unsigned char* data, u_int64 n,
        u_int64 hash, u_int64 scale, u_int64 hardener);

u_int64 GenHashSeed(int index);

int is_prime(int num);
int calc_next_prime(int num);

void mangle(const u_char* key, u_char* ret_key,
		int nbytes);

void unmangle(const u_char* key, u_char* ret_key,
		int nbytes);