#include "getpkt.h"

using namespace std;

class bloomFilter
{
private:
    u_int8 *bitArray;
    u_int64 m;   		  //The number of bit Array for BloomFilter
    u_int64 k;            //The number of Hash Function
public:
    void insert(u_int64 *hashIndex);
    bool query(u_int64 *hashIndex);
    bloomFilter(){}
    bloomFilter(u_int64 m,u_int64 k)
    {
		this->m = m;
		this->k = k;
		u_int64 temp = m / 8 + 1;
		this->bitArray = new u_int8[temp];
    }
};


void bloomFilter::insert(u_int64 *hashIndex)
{
	for (int i = 0; i < this->k; i++)
	{
		u_int64 index1 = hashIndex[i] / 8;
		u_int64 index2 = hashIndex[i] % 8;
		u_int8 x = 0x80 >> index2;
		this->bitArray[index1] = this->bitArray[index1] | x;
	}
}

bool bloomFilter::query(u_int64 *hashIndex)
{
	bool ans = true;
	for (int i = 0; i < this->k; i++)
	{
		u_int64 index1 = hashIndex[i] / 8;
		u_int64 index2 = hashIndex[i] % 8;
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

