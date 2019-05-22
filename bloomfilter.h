#include "getpkt.h"
#define LENGTH 100000


using namespace std;

class bloomFilter
{
private:
    u_int8 *bitArray;
    int m;   		  //The number of bit Array for BloomFilter
    int k;            //The number of Hash Function
public:
    void insert(int *hashIndex);
    bool query(int *hashIndex);
    bloomFilter(){}
    bloomFilter(int m,int k)
    {
		this->m = m;
		this->k = k;
		int temp = m / 8;
		this->bitArray = new u_int8[temp];
    }
};


void bloomFilter::insert(int *hashIndex)
{
	for (int i = 0; i < this->k; i++)
	{
		int index1 = hashIndex[i] / 8;
		int index2 = hashIndex[i] % 8;
		u_int8 x = 0x80 >> index2;
		this->bitArray[index1] = this->bitArray[index1] | x;
	}
}

bool bloomFilter::query(int *hashIndex)
{
	bool ans = true;
	for (int i = 0; i < this->k; i++)
	{
		int index1 = hashIndex[i] / 8;
		int index2 = hashIndex[i] % 8;
		u_int8 x = 0x80 >> index2;
		u_int8 flag = this->bitArray[index1] & x;
		if(flag == 0)
		{
			ans = false;
			break;
		}
	}
	return ans;
}

class generater
{
public:
	void generateKey(fiveTuple_t pktTuple, u_char * str);
};

void generater::generateKey(fiveTuple_t pktTuple, u_int8 * str)
{
	str[0] = pktTuple.srcIP[0];
	str[1] = pktTuple.srcIP[1];
	str[2] = pktTuple.srcIP[2];
	str[3] = pktTuple.srcIP[3];

	str[4] = pktTuple.dstIP[0];
	str[5] = pktTuple.dstIP[1];
	str[6] = pktTuple.dstIP[2];
	str[7] = pktTuple.dstIP[3];

	str[8] = pktTuple.protocol;

	str[9] = pktTuple.srcPort[0];
	str[10] = pktTuple.srcPort[1];

	str[11] = pktTuple.dstPort[0];
	str[12] = pktTuple.dstPort[1];
}

class hashMap
{
private:
	int m;
	int seed;
public:
	hashMap(){}
	hashMap(int m,int seed)
	{
		this->m = m;
		this->seed = seed;
		//printf("%d\n", this->seed);
	}
	int hash(fiveTuple_t pktTuple);
};


int hashMap::hash(fiveTuple_t pktTuple)
{
	u_int8 value[13] = {0};
	generater g;
	g.generateKey(pktTuple, value);
	int ans = 0;


	for (int i = 0;i<13;i++)
	{
		ans += this->seed * ans + value[i];
	}

	ans = (this->m - 1) & ans;
	return ans;
}