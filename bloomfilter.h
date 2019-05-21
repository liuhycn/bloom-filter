#include "getpkt.h"
#define LENGTH 100000


using namespace std;

class bloomFilter
{
private:
    char bitArray[LENGTH];
    int m = LENGTH * 8;   //The number of bit Array for BloomFilter
    int k = 3;            //The number of Hash Function
public:
    void insert(pktData pkt);
    bool query(pktData pkt);
    bloomFilter();
    ~bloomfilter();
}

class hashFuction
{
public:
	hashFuction();
	~hashFuction();
	int hash_1(fiveTuple_t pktTuple);
	int hash_2(fiveTuple_t pktTuple);
	int hash_3(fiveTuple_t pktTuple);
}

int hashFuction::hash_1(fiveTuple_t pktTuple)
{
	int hashVal = 0;

	return hashval;
}


int hashFuction::hash_2(fiveTuple_t pktTuple)
{
	int hashVal = 0;

	return hashval;
}


int hashFuction::hash_3(fiveTuple_t pktTuple)
{
	int hashVal = 0;

	return hashval;
}