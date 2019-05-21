#include "getpkt.h"
#include "bloomfilter.h"

struct fiveTuple_t pktTuplebuf[1001];

int main()
{
	char * fname = "test.pcap";
	extracter a;
	a.extract(fname,pktTuplebuf,10);
	return 0;
}