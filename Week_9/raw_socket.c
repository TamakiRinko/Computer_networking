#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>
#include <netdb.h>
#include <sys/time.h>

#define BUFFER_MAX 2048
#define MAX_ROUTE_INFO 20
#define MAX_ARP_SIZE 20

unsigned short checksum(unsigned short* addr,int length);
unsigned short little_endian(unsigned short x);
void sub(struct timeval* rec,struct timeval* sen);

//------------------------------- 结构定义 ----------------------------------------------------
//ICMP头部，总长度8字节
typedef struct ICMP_HEAD{
    unsigned char type;
    unsigned char code;
    unsigned short check_sum;
    /*uint8_t type;//类型
    uint8_t code//报文类型子码
    uint16_t check_sum;//检验和*/
    unsigned short id;
    unsigned short seq;
	struct timeval data;//时间值
    /*uint32_t timestamp;//时间戳
    unsigned int other;//其余4字节*/
}Icmp_h;

//IP头部，总长度20字节
typedef struct IP_HEAD{
    unsigned char version: 4;	//版本
	unsigned char hlen: 4;      //头长度
	unsigned char tos;          //服务类型
	unsigned short total_len;   //数据报总长度
	unsigned short id;          //数据报ID
    unsigned char flags: 3;     //分段标志
	unsigned short frag_off: 13;//分片偏移
	unsigned char ttl;          //生存期
	unsigned char protocol;     //协议
	unsigned short check_sum;   //检验和
	struct in_addr src_addr;    //源IP地址
	struct in_addr dst_addr;    //目的IP地址
}Ip_h;

/*
//arp头部，总长度
typedef struct ARP_HEAD{
	unsigned short arp_hrd;		//硬件类型
	unsigned short arp_pro;		//协议类型
	unsigned char arp_hln;		//硬件地址长度
	unsigned char arp_pln;		//协议地址长度
	unsigned short arp_op;		//???
	unsigned char arp_sha[6];	//源MAC
	unsigned long arp_spa;		//源IP
	unsigned char arp_tha[6];	//目的MAC
	unsigned long arp_tpa;		//目的IP
}Arp_h;
*/
//ARP表
struct ARP_TABLE_ITEM{
    char ip_addr[16];
    char mac_addr[18];
}Arp_table[MAX_ARP_SIZE];
int arp_item_index = 0;

//本设备接口与MAC地址的对应关系
struct DEVICE_ITEM{
	char interface[14];
	char mac_addr[18];
}Device[MAX_DEVICE];
int device_index = 0;

//以太网头部
typedef struct ETH_HEAD{
	unsigned char eth_dst[6];   /* destination ethernet addrress */
	unsigned char eth_src[6];   /* source ethernet addresss */
	unsigned short eth_type;   /* ethernet pachet type */
}Eth_h;
//---------------------------------------------------------------------------------------------------

int main(int argc,char* argv[]){
//--------------------------- arp table && device --------------------------------------------------
	strcpy(Arp_table[0].ip_addr, "192.168.100.1");
	strcpy(Arp_table[0].mac_addr, "00:0c:29:84:0b:6c");
	arp_item_index++;
	strcpy(Device[0].interface, "eth0");
	strcpy(Device[0].mac_addr, "00:0c:29:c5:1c:c8");
//--------------------------------------------------------------------------------------------------

//------------------------------- open --------------------------------------------------------------
	int sock_send;
	int sock_receive;
	if((sock_receive=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){//打开接收
        printf("error create raw receive socket\n");
        return -1;
    }
    if((sock_send=socket(AF_INET, SOCK_RAW, IPPROTO_ICMP))<0){//打开发送
        printf("error create raw send socket\n");
        return -1;
    }
//---------------------------------------------------------------------------------------------------

	//--------------------------- 配置 host 获得 IP 地址 ---------------------------------------------
	
	unsigned int myaddr = inet_addr(argv[1]);
	struct hostent* host;//配置host
	struct sockaddr_in dest_addr;
	memset(&dest_addr,0,sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;
	
	if( myaddr == INADDR_NONE ){
		if( (host = gethostbyname(argv[1]) ) == NULL){//是主机名
	    	perror("gethostbyname error");
            return -1;
        }
        memcpy( (char *)&dest_addr.sin_addr,host->h_addr,host->h_length);
    }
    else{
    	dest_addr.sin_addr.s_addr = myaddr;
    	//memcpy( (char *)&dest_addr,(char *)&myaddr,host->h_length);
    	//printf("addr = %s\n", inet_ntoa(dest_addr.sin_addr));
    }
        
	//-----------------------------------------------------------------------------------------------

//------------------------------- 变量定义 -----------------------------------------------------------
    int proto;//协议类型
    int n_read;
    unsigned char buffer[BUFFER_MAX];//接收字符串
	char buffer_send[4096] = "\0";//发送字符串
    Icmp_h icmp_h;//ICMP头，用于存储获得的icmp头
    Ip_h ip_h;//IP头，同上
    char *eth_head;
    char *ip_head;
    char *icmp_head;
    unsigned char *p;
	unsigned seq = 1;//icmp_seq
	int flag = 1;
//---------------------------------------------------------------------------------------------------

    while(1){
//---------------------------------- send -----------------------------------------------------------
		
	//------------------------------ fill ETH, IP, ICMP head ----------------------------------------
	if(flag){
	//------------------------------ ETH ------------------------------------------------------------
		Eth_h* eth;
		eth = (Eth_h* )buffer_send;
		strcpy(eth->eth_dst, Arp_table[0].mac_addr);
		strcpy(eth->eth_src, Device[0].mac_addr);
		eth->eth_type = 0x800;//??????????????
	//-----------------------------------------------------------------------------------------------
	//------------------------------ IP -------------------------------------------------------------
		
	//-----------------------------------------------------------------------------------------------
		Icmp_h* icmp;
		struct timeval tsend;
        icmp = (Icmp_h* )buffer_send;
        icmp->type = ICMP_ECHO;//请求报文，类型为8
		//icmp->type = 13;
        icmp->code = 0;//code = 0
        icmp->check_sum = 0;
        icmp->id = 0;
        icmp->seq = seq;
		seq++;
		gettimeofday(&tsend,NULL); //记录发送时间
		icmp->data = tsend;//存放到icmp数据中
		//printf("seq = %d, sec = %x, usec = %x\n", icmp->seq, (int)(send.tv_sec), (int)(send.tv_usec));
		char* mydata = buffer_send + 16;
		strcpy(mydata, "Hello World! With my sincerity! ");//传输的data为Hello World! With my sincerity! 
        icmp->check_sum = checksum( (unsigned short *)icmp, 64);
	//-----------------------------------------------------------------------------------------------
        if( sendto(sock_send, buffer_send, 64, 0, (struct sockaddr *)&dest_addr,sizeof(dest_addr) )<0){       
            printf("sendto fail!\n");
        }
		flag = 0;
	}
        
//---------------------------------------------------------------------------------------------------

//---------------------------------- receive --------------------------------------------------------
        n_read = recvfrom(sock_receive, buffer, 2048, 0, NULL, NULL);
        if(n_read < 42)
        {
            printf("error when recv msg \n");
            return -1;
        }

		/*int i = 0;
		for(; i < 98; ++i)
			printf("%x ", (unsigned)buffer[i]);*/
		eth_head = buffer;
        ip_head = eth_head + 14;
		icmp_head = ip_head + 20;
        proto = (ip_head + 9)[0];//8位协议
		int icmp_type = icmp_head[0];//接收or发送，发送为8
        if(proto == IPPROTO_ICMP && icmp_type == 0){//icmp_type
			flag = 1;
			p = ip_head + 12;
			struct timeval temp;//发送的时间
			memcpy(&icmp_h, buffer + 34, 8);//赋值icmp头
			memcpy(&ip_h, buffer + 14, 20);//赋值ip头
			memcpy(&temp, buffer + 42, 8);//赋值时间
			double time_tran;
			struct timeval tvrecv;//接收的时间
			gettimeofday(&tvrecv,NULL); //记录接收时间
			sub(&tvrecv, &(temp)); //时间差
			time_tran = tvrecv.tv_sec*1000+tvrecv.tv_usec * 1.0/1000; //1.0勿忘，tv_usec为long型
			if(icmp_h.seq == 1 && host != NULL){
				printf("PING %s (%d.%d.%d.%d) 56(84) bytes of data.\n", host->h_name, p[0], p[1], p[2], p[3]);
			}
        	/*printf("IP:%d.%d.%d.%d==> %d.%d.%d.%d\n", p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7]);
			//printf("check_sum = %x\n", icmp_h.check_sum);
            printf("icmp_head:  type = %u,   code = %u,   check_sum = 0x%x,   icmp_req = %d\n", icmp_h.type, icmp_h.code, little_endian(icmp_h.check_sum), icmp_h.seq);
			//首部长度Header Length：4位，表示IP数据报头的长度，最小20字节，最大69字节。0101 = 5　5X4=20字节
			//printf("check_sum = %x\n", ip_h.check_sum);
			//printf("total_len = %x\n", ip_h.total_len);
            printf("ip_head:  version = %u,   hlen = %u,   total_len = %u,   ttl = %u,   protocol = ICMP,   check_sum = 0x%x   data = %s\n\n", 
            ip_h.version, ip_h.hlen * 4, little_endian(ip_h.total_len), ip_h.ttl, little_endian(ip_h.check_sum), buffer + 42);*/
			printf("64 bytes from %d.%d.%d.%d: icmp_req=%u ttl=%u time=%.1fms\n", p[0], p[1], p[2], p[3], icmp_h.seq, ip_h.ttl, time_tran);
			sleep(1);//停1秒
        }
    //---------------------------------------------------------------------------------------------------

		//sleep(1);//停1秒
    }
    return -1;
}

//大端小端转换
unsigned short little_endian(unsigned short x){
	unsigned short low = x >> 8;
	unsigned short high = x & 0xff;
	unsigned short result = (high << 8) + low;//括号！
	return result;
}


unsigned short checksum(unsigned short* addr,int length){
    unsigned sum = 0;
    unsigned short* temp = addr;
    unsigned short result = 0;
    //每2字节累加一次，共32次
    while(length > 0){
        sum += *temp;
		temp++;
        length -= 2;
		if((sum >> 16) == 1){//需要回卷的部分
			sum = 1 + (sum & 0xffff);
		}
    }
    result = ~sum;
    return result;
}


void sub(struct timeval* rec,struct timeval* sen)
{
	if(rec->tv_usec < sen->tv_usec){//借位
		rec->tv_usec = rec->tv_usec - sen->tv_usec;
		rec->tv_sec = rec->tv_sec - 1;
		rec->tv_usec += 1000000;
	}
	else	rec->tv_usec = rec->tv_usec - sen->tv_usec;
	rec->tv_sec = rec->tv_sec - sen->tv_sec;
}



