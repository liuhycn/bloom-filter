#include "bloomfilter.h"

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


struct fiveTuple_t pktTuplebuf[150001];						//store 5-tuple of pkt in memory
u_int64 hashIndex[11];										//store k hash values
//struct awareHash hashfuctions[11];							//store k hash functions


bool check(int index)
{
	
	for (int i = 1;i<=index-1;i++)
	{
		int flag = 0;
		for (int j = 0;j<13;j++)
		{
			if (pktTuplebuf[i].str[j] != pktTuplebuf[index].str[j])
			{
				flag = 1;
				break;
			}
		}
		if (flag == 0)
		{
			return true;
		}
	}
	return false;
}



int main()
{
	srand(time(NULL));

	u_int64 flowcnt = 0;

	printf("plz input the size of this bloom filter(n) : \n");
	scanf("%u",&n);
	printf("plz input the number of hash fuctions(k) : \n");
	scanf("%u",&k);
	printf("plz input the length of the bits array(m) : \n");
	scanf("%u",&m);

	//printf("%u\n", n);
	//printf("%u\n", k);
	//printf("%u\n", m);


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
	

	//gennerater a bloom filer with m bits array
	bloomFilter bf(m,k);

	char * fname = "test.pcap";
	extracter a;
	a.extract(fname,pktTuplebuf,n);

	for (int i = 1; i<=n; i++)
	{

		printf("info of pkt %d\n", i);
		pktTuplebuf[i].printinfo();


		for (int j = 0;j<k;j++)
		{
			printf("the no : %d hash value of pkt %d is %d \n", j,i,(AwareHash(pktTuplebuf[i].str, 13, hash[j], scale[j], hardener[j])));
			hashIndex[j] = AwareHash(pktTuplebuf[i].str, 13, hash[j], scale[j], hardener[j]);
		}

		bool setFlag = check(i);
		{
			if (setFlag == 1)
			{
				printf("turely exist !\n");
			}
			else 
			{
				printf("no !\n");
			}
		}


		bool flag = bf.query(hashIndex);
		if (flag == 0)
		{
			flowcnt++;
			printf("there is not exist pkt %d \n", i);
			bf.insert(hashIndex);
		}
		else
		{
			printf("pkt %d is already exist\n", i);
		}

		if (setFlag == 0 && flag == 1)
		{
			
		}
	}

	printf("there are %d flows in this pcap file\n", flowcnt);

	return 0;
}