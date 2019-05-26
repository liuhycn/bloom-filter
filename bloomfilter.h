#include "getpkt.h"

using namespace std;

class bloomFilter
{
private:
    u_int8 *bitArray;
    u_int64 m;   		  //The number of bit Array for BloomFilter
    u_int64 k;            //The number of Hash Function
    u_int64 fill = 0;
public:
    void insert(u_int64 *hashIndex);
    bool query(u_int64 *hashIndex);
    u_int64 getFill();
    bloomFilter(){}
    bloomFilter(u_int64 m,u_int64 k)
    {
		this->m = m;
		this->k = k;
		u_int64 temp = m / 8 + 1;
		this->bitArray = new u_int8[temp];
		for (u_int64 i =0; i<temp;i++)
		{
			bitArray[i] = 0;
		}
    }
};


u_int64 bloomFilter::getFill()
{
	u_int64 length = this->m / 8 + 1;
	//printf("%u\n", length);
	u_int64 i;
	for (i = 0;i<length;i++)
	{
		u_int8 temp = this->bitArray[i];
		//printf("%u\n", temp);
		int cnt = 0;
		while (temp != 0)
		{
			if (temp % 2 == 1)
			{
				this->fill++;
				cnt++;
			}
			temp = temp / 2;
			//printf("1\n");
		}
		//printf("%d\n", cnt);
		if (cnt > 8)
		{
			printf("error !!!!!!\n");
		}
	}
	return this->fill;
}

void bloomFilter::insert(u_int64 *hashIndex)
{
	for (int i = 0; i < this->k; i++)
	{
		//printf("change %u bit \n", hashIndex[i]);
		u_int64 index1 = hashIndex[i] / 8;
		u_int64 index2 = hashIndex[i] % 8;
		//printf("index1 = %u\n",index1);
		//printf("index2 = %u\n",index2);
		u_int8 x = 0x80 >> index2;
		//printf("temp x = %u\n",x);
		//printf("\n");
		this->bitArray[index1] = this->bitArray[index1] | x;
	}
}

bool bloomFilter::query(u_int64 *hashIndex)
{
	bool ans = true;
	for (int i = 0; i < this->k; i++)
	{
		//printf("query %u bit \n", hashIndex[i]);
		u_int64 index1 = hashIndex[i] / 8;
		u_int64 index2 = hashIndex[i] % 8;
		//printf("index1 = %u\n",index1);
		//printf("index2 = %u\n",index2);
		u_int8 x = 0x80 >> index2;
		//printf("temp x = %u\n",x);
		//printf("\n");
		u_int8 flag = this->bitArray[index1] & x;
		if(flag == 0)
		{
			ans = false;
			break;
		}
	}
	return ans;
}

