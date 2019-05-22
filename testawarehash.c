
#include <pcap/pcap.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace std;




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

int main()
{
	char name[] = "deltoid";
    unsigned long seed = AwareHash((u_char*)name, strlen(name), 13091204281, 228204732751, 6620830889);
    printf("%u\n", seed);
}