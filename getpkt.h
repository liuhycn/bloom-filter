#include <pcap/pcap.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace std;


typedef u_int32_t u_int32;
typedef u_int16_t u_int16;
typedef u_int8_t u_int8;

void bin1(u_int8 A)
{
	for (int i = 1<<31; i > 0; i >>= 1)
    {
        (i & A)?printf("1"): printf("0");	
    }
    printf("\n");
}

void bin2(u_int8 A)
{
    if (A > 0)
    {
        bin2(A/2);
    }
	
    (A & 1)?printf("1"): printf("0");
}

struct etherHeader_t
{ //Pcap捕获的数据帧头
    u_int8 dstMAC[6]; 		//目的MAC地址
    u_int8 srcMAC[6]; 		//源MAC地址
    u_int16 frameType;    	//帧类型
};

//IP数据报头
struct ipHeader_t
{ //IP数据报头
    u_int8 Ver_HLen;       	//版本+报头长度
    u_int8 TOS;           	//服务类型
    u_int8 TotalLen[2];     //总长度
    u_int8 ID[2]; 			//标识
    u_int8 Flag_Segment[2]; //标志+片偏移
    u_int8 ttl;            	//生存周期
    u_int8 protocol;       	//协议类型
    u_int8 checksum[2];     //头部校验和
    u_int8 srcIP[4]; 		//源IP地址
    u_int8 dstIP[4]; 		//目的IP地址
};

//TCP数据报头
struct tcpHeader_t
{ //TCP数据报头
    u_int8 srcPort[2];		//源端口
    u_int8 dstPort[2];		//目的端口
    u_int8 SeqNO[4];			//序号
    u_int8 AckNO[4]; 			//确认号
    u_int8 HeaderLen; 		//数据报头的长度(4 bit) + 保留(4 bit)
    u_int8 Flags; 			//标识TCP不同的控制消息
    u_int8 Window[2]; 		//窗口大小
    u_int8 checksum[2]; 		//校验和
    u_int8 UrgentPointer[2];  //紧急指针
};

//UDP数据
struct udpHeader_t
{
    u_int8 srcPort[2];     	// 源端口号16bit
    u_int8 dstPort[2];    	// 目的端口号16bit
    u_int8 len[2];        	// 数据包长度16bit
    u_int8 checkSum[2];   	// 校验和16bit
};


//数据包五元组
struct fiveTuple_t
{
	u_int8 srcIP[4];		//源IP地址
	u_int8 dstIP[4]; 		//目的IP地址
	u_int8 protocol;       	//协议类型
	u_int8 srcPort[2];     	// 源端口号16bit
	u_int8 dstPort[2];    	// 目的端口号16bit
};


int pktCounter = 0;


char errbuf[PCAP_ERRBUF_SIZE];


class extracter
{
private:
	int pktCounter = 0;
public:
	void extract(char * fname, struct fiveTuple_t *fiveTupleFuf,int n);
};


void extracter::extract(char * fname, struct fiveTuple_t *fiveTupleFuf,int n)
{

	pcap_t * pcap;
	pcap = pcap_open_offline(fname, errbuf);			
	struct pcap_pkthdr pkthdr;								

	struct etherHeader_t *etherHeader;
	struct ipHeader_t *ipHeader;
	struct tcpHeader_t *tcpHeader;
	struct udpHeader_t *udpHeader;

	

	int size_ethernet = sizeof(struct etherHeader_t);
	int size_ip = sizeof(struct ipHeader_t);
	int size_tcp = sizeof(struct tcpHeader_t);
	int size_udp = sizeof(struct udpHeader_t);



	while (1)
	{
		const u_char *pktStr = pcap_next(pcap, &pkthdr);	
		if (pktStr == NULL)
		{
			printf("pcap end!\n");
			exit(1);
		}
		else
		{
			pktCounter++;

			etherHeader = (struct etherHeader_t*)(pktStr);



			ipHeader = (struct ipHeader_t*)(pktStr + size_ethernet);

			
			memcpy(fiveTupleFuf[pktCounter].srcIP,ipHeader->srcIP,4);
			memcpy(fiveTupleFuf[pktCounter].dstIP,ipHeader->dstIP,4);
			fiveTupleFuf[pktCounter].protocol = ipHeader->protocol;


			if (ipHeader->protocol == 0x06)
			{

				//printf("this is a tcp packet !\n");
				tcpHeader = (struct tcpHeader_t*)(pktStr + size_ethernet + size_ip);

				memcpy(fiveTupleFuf[pktCounter].srcPort,tcpHeader->srcPort,2);
				memcpy(fiveTupleFuf[pktCounter].dstPort,tcpHeader->dstPort,2);

			}
			else if (ipHeader->protocol == 0x11)
			{
				
				udpHeader = (struct udpHeader_t*)(pktStr + size_ethernet + size_ip);
				memcpy(fiveTupleFuf[pktCounter].srcPort,udpHeader->srcPort,2);
				memcpy(fiveTupleFuf[pktCounter].dstPort,udpHeader->dstPort,2);
			}
			
			// print
			printf("pkt no : %d\n", pktCounter);

			for (int i = 0; i<4;i++)
			{
				printf("%02x ", fiveTupleFuf[pktCounter].srcIP[i]);
			}
			printf("\n");
			for (int i = 0; i<4;i++)
			{
				printf("%02x ", fiveTupleFuf[pktCounter].dstIP[i]);
			}
			printf("\n");
			printf("%02x\n", fiveTupleFuf[pktCounter].protocol);
			for (int i = 0; i<2;i++)
			{
				printf("%02x ", fiveTupleFuf[pktCounter].srcPort[i]);
			}
			printf("\n");
			for (int i = 0; i<2;i++)
			{
				printf("%02x ", fiveTupleFuf[pktCounter].dstPort[i]);
			}
			
			printf("\n");


		}

		printf("\n");

		if(pktCounter == n)
		{
			break;
		}

	}
	pcap_close(pcap);
}