#include "bloomfilter.h"
#include <time.h>


u_int64 n;
u_int64 k;
u_int64 m;

u_int64 AwareHash(u_char* data, u_int64 n,
        u_int64 hash, u_int64 scale, u_int64 hardener) {

	while (n) {
		hash *= scale;
		hash += *data++;
		n--;
	}
	return (hash ^ hardener) % m;
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


struct fiveTuple_t pktTuplebuf[38000001];						//store 5-tuple of pkt in memory
u_int64 hashIndex[21];										//store k hash values
//struct awareHash hashfuctions[11];							//store k hash functions

int main()
{
	srand(time(NULL));

	char * fname = "test2.pcap";
	extracter a;
	a.extract(fname,pktTuplebuf,10000);
	//printf("1\n");
	
	n = 5000;
	m = 50000;
	

	
	for (k = 1;k<=20;k++)
	{
		u_int64 *hash     = new u_int64[k];
		u_int64 *scale    = new u_int64[k];
		u_int64 *hardener = new u_int64[k];

		u_int64 seed = 3752863345;
	

		for (int i=0; i<k; i++) 
		{
    	    hash[i] = GenHashSeed(seed++);
  	 	}
   		 for (int i=0; i<k; i++) 
   	 	{
        	scale[i] = GenHashSeed(seed++);
    	}
    	for (int i=0; i<k; i++) 
    	{
       	 	hardener[i] = GenHashSeed(seed++);
    	}

		u_int64 errorCnt = 0;
		bloomFilter bf(m,k);

		for (int i = 1; i<=n; i++)
		{
			memset(hashIndex,0,sizeof(hashIndex));
			for (int j = 0;j<k;j++)
			{
				hashIndex[j] = AwareHash(pktTuplebuf[i].str, 13, hash[j], scale[j], hardener[j]);
			}
			bf.insert(hashIndex);

		}

		for (int i = n+1;i<=2*n;i++)
		{
			memset(hashIndex,0,sizeof(hashIndex));
			for (int j = 0;j<k;j++)
			{
				
				hashIndex[j] = AwareHash(pktTuplebuf[i].str, 13, hash[j], scale[j], hardener[j]);
			}
			bool flag = bf.query(hashIndex);
			if (flag == 1)
			{
				errorCnt++;
			}
		}
		//printf("1\n");
		//printf("there are %d flows in this pcap file\n", flowcnt);
		//printf("error is : %u\n", errorCnt);


		//printf("case n = %d\n", n);


		//printf("\n");
		//double fillRate = (bf.getFill() * 1.0) / m;

		//printf("fill rate: %.4lf%% \n", fillRate*100.0);
		//printf("err times is : %u\n", errorCnt);
		double errrte = (errorCnt*1.0) / (n);
		printf("%.4lf%% \n",errrte*100.0);

		//printf("err rate of %d is : %.4lf%% \n", err);
		//printf("\n");
	}

	return 0;
}