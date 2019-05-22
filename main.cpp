#include "bloomfilter.h"

struct fiveTuple_t pktTuplebuf[15001];
int hashIndex[10000];
struct hashMap hashfuctions[10000];

bool check(int index)
{
	u_int8 str1[13] = {0};
	generater g;
	g.generateKey(pktTuplebuf[index], str1);

	for (int i = 1; i<=index-1;i++)
	{
		u_int8 str2[13] = {0};
		int flag = 0;
		g.generateKey(pktTuplebuf[i], str2);
		for (int j = 0;j<13;j++)
		{
			if (str1[j] != str2[j])
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
	int n;
	int k;
	int m;
	int flowcnt = 0;
	int errorcnt = 0;

	printf("plz input the size of this bloom filter(n) : \n");
	scanf("%d",&n);
	printf("plz input the number of hash fuctions(k) : \n");
	scanf("%d",&k);
	printf("plz input the length of the bits array(m) : \n");
	scanf("%d",&m);

	printf("\n");

	//prepare k hash functions
	for (int i = 0;i<k;i++)
	{
		hashfuctions[i] = hashMap(m,rand());
	}

	//generate a bloom filer with a m bits array
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

		bool setflag = check(i);

		if (setflag == 0)
		{
			printf("no !\n");
		}
		else
		{
			printf("yes !\n");
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

		if (setflag != flag)
		{
			errorcnt++;
			printf("error !\n");
		}

		printf("\n");

	}

	printf("there are %d flows in this pcap file\n", flowcnt);
	printf("error count : %d\n", errorcnt);
	return 0;
}