#include "bloomfilter.h"
#include "hash.h"


struct fiveTuple_t pktTuplebuf[150001];				//store 5-tuple of pkt in memory
u_int64 hashIndex[11];										//store k hash values
struct awareHash hashfuctions[11];							//store k hash functions

int main()
{
	srand(time(NULL));
	u_int64 n;
	u_int64 k;
	u_int64 m;
	u_int64 flowcnt = 0;

	printf("plz input the size of this bloom filter(n) : \n");
	scanf("%u",&n);
	printf("plz input the number of hash fuctions(k) : \n");
	scanf("%u",&k);
	printf("plz input the length of the bits array(m) : \n");
	scanf("%u",&m);



	u_int64 *hash     = new u_int64[k];
	u_int64 *scale    = new u_int64[k];
	u_int64 *hardener = new u_int64[k];

	u_int64 seed = 3752863345;

	for (int i=0; i<depth; i++) 
	{
        skl->hash[i] = GenHashSeed(seed++);
    }
    for (int i=0; i<depth; i++) 
    {
        skl->scale[i] = GenHashSeed(seed++);
    }
    for (int i=0; i<depth; i++) 
    {
        skl->hardner[i] = GenHashSeed(seed++);
    }
	


	//prepare k hash functions
	for (int i = 0;i<k;i++)
	{
		hashfuctions[i] = hashMap(m,rand());
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
			printf("the no : %d hash value of pkt %d is %d \n", j,i,hashfuctions[j].hash(pktTuplebuf[i]));
			hashIndex[j] = hashfuctions[j].hash(pktTuplebuf[i]);
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
	}

	printf("there are %d flows in this pcap file\n", flowcnt);

	return 0;
}