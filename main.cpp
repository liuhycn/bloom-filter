#include "bloomfilter.h"

struct fiveTuple_t pktTuplebuf[1001];
int hashIndex[10000];
struct hashMap hashfuctions[10000];

int main()
{
	srand(time(NULL));
	int n;
	int k;
	int m;

	printf("plz input the size of this bloom filter(n) : \n");
	scanf("%d",&n);
	printf("plz input the number of hash fuctions(k) : \n");
	scanf("%d",&k);
	printf("plz input the length of the bits array(m) : \n");
	scanf("%d",&m);

	for (int i = 0;i<k;i++)
	{
		hashfuctions[i] = hashMap(m,rand());

	}

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
			printf("there is not exist pkt %d \n", i);
			bf.insert(hashIndex);
		}
		else
		{
			printf("pkt %d is already exist\n", i);
		}
	}

	return 0;
}