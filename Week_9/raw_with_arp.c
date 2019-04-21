#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>	//ETH_ALEN(6),ETH_HLEN(14),ETH_FRAME_LEN(1514)
#include <netdb.h>
#include <sys/time.h>

#include <errno.h>//errno
#include <linux/if_packet.h>  	//struct sockaddr_ll
#include <sys/ioctl.h> 			//ioctl()
#include <linux/if.h>			//struct ifreq

#define BUFFER_MAX 2048
#define MAX_ROUTE_INFO 20
#define MAX_ARP_SIZE 20
#define MAX_DEVICE 5
const char myip[16] = "192.168.100.2";

unsigned short checksum(unsigned short* addr,int length);
unsigned short little_endian(unsigned short x);
void sub(struct timeval* rec,struct timeval* sen);
int get_nic_index(int fd, const char* nic_name);
void SendARP(int& sock_send_arp, char* dst_ip);

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

/*
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

//以太网头部
typedef struct ETH_HEAD{
	unsigned char eth_dst[6];	//destination ethernet addrress
	unsigned char eth_src[6];	//source ethernet addresss
	unsigned short eth_type;	//ethernet pachet type
}Eth_h;
*/

//ARP表
struct ARP_TABLE_ITEM{
    unsigned char ip_addr[16];
    unsigned char mac_addr[18];
}Arp_table[MAX_ARP_SIZE];
int arp_item_index = 0;

//本设备接口与MAC地址的对应关系
struct DEVICE_ITEM{
	unsigned char interface[14];//自身接口的名称
	unsigned char mac_addr[18];//自身接口的MAC地址
}Device[MAX_DEVICE];
int device_index = 0;

//以太网头部
typedef struct ETH_HEAD{
    struct ethhdr header;
}Eth_h;
//---------------------------------------------------------------------------------------------------

int main(int argc,char* argv[]){
//------------------------------- 变量定义 -----------------------------------------------------------
    int proto;//协议类型
    int n_read;
    unsigned char buffer[BUFFER_MAX];//接收字符串
	unsigned char buffer_send[4096] = "\0";//发送字符串
    Icmp_h icmp_h;//ICMP头，用于存储获得的icmp头
    //Ip_h ip_h;//IP头，同上
	struct ip ip_h2;
    char* eth_head;
    char* ip_head;
    char* icmp_head;
    char* arp_head;
    Arp_h* arp_head2;//????????????????????????暂定
    unsigned char *p;
	unsigned seq = 1;//icmp_seq
	int flag = 1;

	struct ip* ip_h;
	int ip_flags[4];//ip's flags
//---------------------------------------------------------------------------------------------------

//--------------------------- arp table && device set -----------------------------------------------
	//unsigned char gate_mac[7] = {0x00, 0x0c, 0x29, 0x84, 0x0b, 0x6c};
	//unsigned char my_mac[7] = {0x00, 0x0c, 0x29, 0xc5, 0x1c, 0xc8};
	//strcpy(Arp_table[0].ip_addr, "192.168.100.1");
	//memcpy(Arp_table[0].mac_addr, /*gate_mac*/"00:0c:29:84:0b:6c", 18);
	//arp_item_index++;
	strcpy(Device[0].interface, "eth0");
	memcpy(Device[0].mac_addr, /*my_mac*/"00:0c:29:c5:1c:c8", 18);
	device_index++;
//---------------------------------------------------------------------------------------------------

//------------------------------- open --------------------------------------------------------------
	int sock_send;
	int sock_receive;
    int sock_receive_arp;
    int sock_send_arp;
	int val = 1;
	if((sock_receive=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){//打开接收
        printf("error create raw receive socket\n");
        return -1;
    }
    if((sock_send=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0){//打开发送
        printf("error create raw send socket\n");
        return -1;
    }
    if((sock_send_arp=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0){//打开ARP发送
        printf("error create raw send arp socket\n");
        return -1;
    }
    if((sock_receive_arp=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ARP)))<0){//打开ARP接收
        printf("error create raw receive arp socket\n");
        return -1;
    }
	
	//链路层不需要开启???
	//if(setsockopt(sock_send, IPPROTO_IP, IP_HDRINCL, (char *)&val, sizeof(val))/*==SOCKET_ERROR*/ < 0)//开启IP_HDRINGL
	//{
	//	printf("failed to set socket in raw mode.");
	//	return 0;
	//}
//---------------------------------------------------------------------------------------------------

//--------------------------- 配置链路层发送结构 ------------------------------------------------------
    int m;
    //-------------------------- 判断MAC地址是否在ARP表中 ---------------------------------------------
    int arp_flag = 0;
    int arp_index = -1;
    for(m = 0; m < arp_item_index; ++m){
        if(strcmp(argv[1], Arp_table[m].ip_addr) == 0){
            arp_flag = 1;
            break;
        }
    }
    if(arp_flag == 1){//ARP表中有该项，使用该项
        arp_index = m;
    }
    else{//ARP表中无该项，发送ARP请求报文
        int arp_send_flag = 1;
        int len_arp;//收到ARP包的长度
        unsigned char buffer_rece_arp[BUFFER_MAX];
        while(!arp_flag){//还未收到ARP回复报文
            if(arp_send_flag == 1){
                for(m = 0; m < 10; ++m){//暂时实现为发送10个ARP包
                    SendARP(sock_send_arp, argv[1]);
                }
                arp_send_flag = 0;
            }
            len_arp = recvfrom(sock_receive_arp, buffer_rece_arp, 2048, 0, NULL, NULL);
            if(len_arp != 42)   continue;
            eth_head = buffer_rece_arp;
            arp_head = buffer_rece_arp + 14;
            arp_head2 = buffer_rece_arp + 14;
            if(arp_head[7] != 2)    continue;//不是ARP响应
            //------------------- 判断是否为对应的MAC地址 ---------------------------------------------
            int match = 1;
            for(m = 0; m < 6; ++m){
                if(arp_head[m + 18] != (strtol(Device[0].mac_addr + 3 * m, NULL, 16))){//匹配我方MAC地址
                    match = 0;
                    break;
                }
            }
            if(arp_head2->arp_spa != inet_addr(argv[1])){//匹配目的IP地址
                match = 0;
            }
            if(!match)  continue;
            //---------------------------------------------------------------------------------------

            //-------------------- 匹配，添加表项并跳出循环 -------------------------------------------
            strcpy(Arp_table[arp_item_index].ip_addr, argv[1]);
            sprintf(Arp_table[arp_item_index].mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",//not sure!!!!!!!!!!!!!!!!!!!
                arp_head[13], arp_head[12], arp_head[11], arp_head[10], arp_head[9], arp_head[8]);
            arp_index = arp_item_index;
            arp_item_index++;
            arp_flag = 1;
            //---------------------------------------------------------------------------------------
        }
    }
    //-----------------------------------------------------------------------------------------------

	struct sockaddr_ll saddrll;//链路层需要用此结构
    memset(&saddrll, 0, sizeof(saddrll));
    saddrll.sll_family = PF_PACKET;
	//saddrll.sll_protocol = ETH_P_IP;//????
    saddrll.sll_ifindex = get_nic_index(sock_send, Device[0].interface);//获得本接口对应的类型
    saddrll.sll_halen = ETH_ALEN;
	for(m = 0; m < 6; ++m){//目的MAC地址
		saddrll.sll_addr[m] = strtol(Arp_table[arp_index].mac_addr + 3 * m, NULL, 16);//字符串转16进制数
		//printf("%x  ", saddrll.sll_addr[m]);
	}
    //memcpy(saddrll.sll_addr, dest, ETH_ALEN);
        
//---------------------------------------------------------------------------------------------------

    while(1){
//---------------------------------- send -----------------------------------------------------------
	
	//------------------------------ fill ETH, IP, ICMP head ----------------------------------------
	if(flag){
	//------------------------------ ETH ------------------------------------------------------------
		Eth_h* eth;
		eth = (Eth_h* )buffer_send;
		int t;
		for(t = 0; t < 6; ++t){//目的MAC地址，源MAC地址，使用转换
			eth->header.h_dest[t] = strtol(Arp_table[0].mac_addr + 3 * t, NULL, 16);
			eth->header.h_source[t] = strtol(Device[0].mac_addr + 3 * t, NULL, 16);
			//printf("mac1 = %x    mac2 = %x\n", eth->header.h_dest[t], eth->header.h_source[t]);
		}
		/*for(t = 0; t < 12; ++t){
			printf("buffer = %x   ", buffer_send[t]);
		}*/
		eth->header.h_proto = htons((short)0x0800);
	//-----------------------------------------------------------------------------------------------
	//------------------------------ IP -------------------------------------------------------------
		//htons是将整型变量从主机字节顺序转变成网络字节顺序， 就是整数在地址空间存储方式变为高位字节存放在内存的低地址处。
		//inet_addr方法可以转化字符串，主要用来将一个十进制的数转化为二进制的数，用途多于ipv4的IP转化。
		//ip_flags = allocate_intmem(4);
		ip_h = (struct ip* )(buffer_send + 14);
		ip_h->ip_hl = 5;//5 * 4 = 20
  		ip_h->ip_v = 4;//Internet Protocol version (4 bits): IPv4
  		ip_h->ip_tos = 0;//Type of service (8 bits)
		ip_h->ip_len = htons(84);//ip_head + icmp_head + mydata = 98 - eth_head = 84
		ip_h->ip_id = htons(0);//ID sequence number (16 bits): unused, since single datagram
		ip_flags[0] = 0;// Zero (1 bit) = 0
		ip_flags[1] = 1;// Do not fragment flag (1 bit) = 1
		ip_flags[2] = 0;// More fragments following flag (1 bit) = 0
		ip_flags[3] = 0;// Fragmentation offset (13 bits)
		ip_h->ip_off = htons((ip_flags[0] << 15)+ (ip_flags[1] << 14)//off + flags
                    + (ip_flags[2] << 13)+  ip_flags[3]);
		ip_h->ip_ttl = 64;//time to live
		ip_h->ip_p = IPPROTO_ICMP;//next proto: ICMP(1)
		ip_h->ip_sum = 0;//temporarily 0
		ip_h->ip_src.s_addr = inet_addr(myip);//myip, fixed
		ip_h->ip_dst.s_addr = inet_addr(argv[1]);//dst's ip, from argv[1]
		ip_h->ip_sum = checksum((unsigned short* )ip_h, 20);//ip_header's checksum
	//------------------------------ ICMP -----------------------------------------------------------
		Icmp_h* icmp;
		struct timeval tsend;
        icmp = (Icmp_h* )(buffer_send + 34);
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
		char* mydata = buffer_send + 50;
		strcpy(mydata, "Hello World! With my sincerity! ");//传输的data为Hello World! With my sincerity! 
        icmp->check_sum = checksum( (unsigned short *)icmp, 64);
		int i = 0;
		/*for(; i < 98; ++i)
			printf("%x ", (unsigned)buffer_send[i]);
		printf("\n");*/
		//printf("111\n");
	//-----------------------------------------------------------------------------------------------
        if( sendto(sock_send, buffer_send, 98, 0, (struct sockaddr*)&saddrll, sizeof(saddrll)) < 0){//发送
            printf("now in icmp_send, sendto fail!  error = %x, decimal = %d\n", errno, errno);//发送失败，获得最后错误代码
			return -1;
        }
		sleep(1);
		//printf("222\n");
		//flag = 0;
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
			memcpy(&ip_h2, buffer + 14, 20);//赋值ip头
			memcpy(&temp, buffer + 42, 8);//赋值时间
			double time_tran;
			struct timeval tvrecv;//接收的时间
			gettimeofday(&tvrecv,NULL); //记录接收时间
			sub(&tvrecv, &(temp)); //时间差
			time_tran = tvrecv.tv_sec*1000+tvrecv.tv_usec * 1.0/1000; //1.0勿忘，tv_usec为long型
			/*if(icmp_h.seq == 1 && host != NULL){//不需要host了，链路层直接控制
				printf("PING %s (%d.%d.%d.%d) 56(84) bytes of data.\n", host->h_name, p[0], p[1], p[2], p[3]);
			}*/
        	/*printf("IP:%d.%d.%d.%d==> %d.%d.%d.%d\n", p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7]);
			//printf("check_sum = %x\n", icmp_h.check_sum);
            printf("icmp_head:  type = %u,   code = %u,   check_sum = 0x%x,   icmp_req = %d\n", icmp_h.type, icmp_h.code, little_endian(icmp_h.check_sum), icmp_h.seq);
			//首部长度Header Length：4位，表示IP数据报头的长度，最小20字节，最大69字节。0101 = 5　5X4=20字节
			//printf("check_sum = %x\n", ip_h.check_sum);
			//printf("total_len = %x\n", ip_h.total_len);
            printf("ip_head:  version = %u,   hlen = %u,   total_len = %u,   ttl = %u,   protocol = ICMP,   check_sum = 0x%x   data = %s\n\n", 
            ip_h.version, ip_h.hlen * 4, little_endian(ip_h.total_len), ip_h.ttl, little_endian(ip_h.check_sum), buffer + 42);*/
			printf("64 bytes from %d.%d.%d.%d: icmp_req=%u ttl=%u time=%.1fms\n", p[0], p[1], p[2], p[3], icmp_h.seq, ip_h2.ip_ttl, time_tran);
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


void sub(struct timeval* rec,struct timeval* sen){
	if(rec->tv_usec < sen->tv_usec){//借位
		rec->tv_usec = rec->tv_usec - sen->tv_usec;
		rec->tv_sec = rec->tv_sec - 1;
		rec->tv_usec += 1000000;
	}
	else	rec->tv_usec = rec->tv_usec - sen->tv_usec;
	rec->tv_sec = rec->tv_sec - sen->tv_sec;
}

int get_nic_index(int fd, const char* nic_name){//获得接口对应的类型
	//printf("nicname = %s\n", nic_name);
    struct ifreq ifr;
    if(nic_name == NULL)
        return -1;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, nic_name, IFNAMSIZ);
    if(ioctl(fd, SIOCGIFINDEX, &ifr) == -1){
        printf("SIOCGIFINDEX ioctl error\n");
        return -1;
    }
    return ifr.ifr_ifindex;
}

void SendARP(int& sock_send_arp, char* dst_ip){
    //------------------------- 配置链路层发送结构 -------------------------------------------------
    struct sockaddr_ll saddrll;//链路层需要用此结构
    memset(&saddrll, 0, sizeof(saddrll));
    saddrll.sll_family = PF_PACKET;
    saddrll.sll_ifindex = get_nic_index(sock_send_arp, Device[0].interface);//获得本接口对应的类型
    saddrll.sll_halen = ETH_ALEN;
	for(m = 0; m < 6; ++m){//目的MAC地址
		saddrll.sll_addr[m] = 0xff;//广播ARP报文，目的MAC为全FF
		//printf("%x  ", saddrll.sll_addr[m]);
	}
    //--------------------------------------------------------------------------------------------

    unsigned char buffer[50] = "\0";
    //------------------------- FILL ETH_HEAD ----------------------------------------------------
    Eth_h* eth;
    eth = (Eth_h* )buffer;
    int t;
    for(t = 0; t < 6; ++t){//目的MAC地址，源MAC地址，使用转换
        eth->header.h_dest[t] = 0xff;
        eth->header.h_source[t] = strtol(Device[0].mac_addr + 3 * t, NULL, 16);
        //printf("mac1 = %x    mac2 = %x\n", eth->header.h_dest[t], eth->header.h_source[t]);
    }
    /*for(t = 0; t < 12; ++t){
        printf("buffer = %x   ", buffer_send[t]);
    }*/
    eth->header.h_proto = htons((short)0x0806);//上层协议为ARP协议
    //--------------------------------------------------------------------------------------------

    //------------------------ FILL ARP_HEAD -----------------------------------------------------
    Arp_h* arp_h = (Arp_h* )(buffer + 14)
    arp_h->arp_hrd = htons(1);//1表示以太网地址
    arp_h->arp_pro = htons(0x0800);//映射的地址类型为IPv4
    arp_h->arp_hln = 6;
    arp_h->arp_pln = 4;
    arp_h->arp_op = 1;//请求
    for(t = 0; t < 6; ++t){//目的MAC地址，源MAC地址，使用转换
        arp_h->arp_sha[t] = strtol(Device[0].mac_addr + 3 * t, NULL, 16);
        arp_h->arp_tha[t] = 0xff;
        //printf("mac1 = %x    mac2 = %x\n", eth->header.h_dest[t], eth->header.h_source[t]);
    }
    arp_h->arp_spa = inet_addr(myip);
    arp_h->arp_tpa = inet_addr(dst_ip);
    //-------------------------------------------------------------------------------------------

    //------------------------ SEND -------------------------------------------------------------
    if( sendto(sock_send_arp, buffer, 42, 0, (struct sockaddr*)&saddrll, sizeof(saddrll)) < 0){//发送
        printf("now in arp_send, sendto fail!  error = %x, decimal = %d\n", errno, errno);//发送失败，获得最后错误代码
        return -1;
    }
    //-------------------------------------------------------------------------------------------
}