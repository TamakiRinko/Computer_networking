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
const char myip[16] = "192.168.5.2";
const char gateway_ip[16] = "192.168.5.1";

unsigned short checksum(unsigned short* addr,int length);
unsigned short little_endian(unsigned short x);
void sub(struct timeval* rec,struct timeval* sen);
int get_nic_index(int fd, const char* nic_name);
void SendARP(int* sock);
int MATCH(unsigned char* buffer);
void ReplyARP(int* sock, unsigned char* buffer_rec);
int ICMP_MATCH(unsigned char* buffer);
void ICMP_Reply(unsigned char* buffer, int* sock);

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
    unsigned short arp_op;		//opcode
    unsigned char arp_sha[6];	//源MAC
    unsigned char arp_spa[4];	//源IP
    unsigned char arp_tha[6];	//目的MAC
    unsigned char arp_tpa[4];	//目的IP
}Arp_h;

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
    int n_read;
    unsigned char buffer[BUFFER_MAX];//接收字符串
    int flag = 1;
//---------------------------------------------------------------------------------------------------

//--------------------------- arp table && device set -----------------------------------------------
    strcpy(Device[0].interface, "eth0");
    memcpy(Device[0].mac_addr, "00:0c:29:3d:6c:41", 18);
    device_index++;
//---------------------------------------------------------------------------------------------------

//------------------------------- open --------------------------------------------------------------
    int sock;
    if((sock=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0){//打开发送
        printf("error create raw send socket\n");
        return -1;
    }
    
    //链路层不需要开启???
    //if(setsockopt(sock_send, IPPROTO_IP, IP_HDRINCL, (char *)&val, sizeof(val))/*==SOCKET_ERROR*/ < 0)//开启IP_HDRINGL
    //{
    //	printf("failed to set socket in raw mode.");
    //	return 0;
    //}
//---------------------------------------------------------------------------------------------------
        
//------------------------------- 主循环 -------------------------------------------------------------

    while(1){
        n_read = recvfrom(sock,buffer,2048,0,NULL,NULL);
        if(n_read < 42){
            printf("error when recv msg \n");
            return -1;
        }
		else if(n_read == 60){//收到ARP请求包，检测并回复，长度为60!
			if(MATCH(buffer) == 1){//ARP请求包匹配成功
				ReplyARP(&sock, buffer);//回复ARP包提供自己的MAC地址
			}
		}
		else if(n_read == 98){//ICMP，根据路由规则转发
            if(ICMP_MATCH(buffer) == 1){//回复ICMP
                ICMP_Reply(buffer, &sock);
            }
		}
    }
//---------------------------------------------------------------------------------------------------
    return -1;
}

//大端小端转换
unsigned short little_endian(unsigned short x){
    unsigned short low = x >> 8;
    unsigned short high = x & 0xff;
    unsigned short result = (high << 8) + low;//括号！
    return result;
}

//checksum
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

//计算时间差值
void sub(struct timeval* rec,struct timeval* sen){
    if(rec->tv_usec < sen->tv_usec){//借位
        rec->tv_usec = rec->tv_usec - sen->tv_usec;
        rec->tv_sec = rec->tv_sec - 1;
        rec->tv_usec += 1000000;
    }
    else	rec->tv_usec = rec->tv_usec - sen->tv_usec;
    rec->tv_sec = rec->tv_sec - sen->tv_sec;
}

//获得接口对应的类型
int get_nic_index(int fd, const char* nic_name){
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

void SendARP(int* sock){
    int m;
    unsigned char buffer[2048] = "\0";
//------------------------- 配置链路层发送结构 -------------------------------------------------
    struct sockaddr_ll saddrll;//链路层需要用此结构
    memset(&saddrll, 0, sizeof(saddrll));
    saddrll.sll_family = PF_PACKET;
    saddrll.sll_ifindex = get_nic_index(*sock, Device[0].interface);//获得本接口对应的类型
    saddrll.sll_halen = ETH_ALEN;
    for(m = 0; m < 6; ++m){//目的MAC地址
        saddrll.sll_addr[m] = 0xff;//广播ARP报文，目的MAC为全FF
    }
//--------------------------------------------------------------------------------------------

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
    Arp_h* arp_h = (Arp_h* )(buffer + 14);
    arp_h->arp_hrd = htons(1);//1表示以太网地址
    arp_h->arp_pro = htons(0x0800);//映射的地址类型为IPv4
    arp_h->arp_hln = 6;
    arp_h->arp_pln = 4;
    arp_h->arp_op = htons(1);//请求
    for(t = 0; t < 6; ++t){//目的MAC地址，源MAC地址，使用转换
        arp_h->arp_sha[t] = strtol(Device[0].mac_addr + 3 * t, NULL, 16);
        arp_h->arp_tha[t] = 0x0;
        //printf("mac1 = %x    mac2 = %x\n", eth->header.h_dest[t], eth->header.h_source[t]);
    }
    struct in_addr src_in_addr, dst_in_addr;
    inet_pton(AF_INET, myip, &src_in_addr);//ip地址转网络字节
    inet_pton(AF_INET, gateway_ip, &dst_in_addr);//只会请求默认网关的IP
    memcpy(arp_h->arp_spa, &src_in_addr, 4);
    memcpy(arp_h->arp_tpa, &dst_in_addr, 4);

/*
    arp_h->arp_spa = inet_addr(myip);
    arp_h->arp_tpa = inet_addr(dst_ip);
    //--------------- Modify ----------------
    memcpy(buffer + 28, buffer + 30, 4);
    memcpy(buffer + 32, buffer + 34, 6);
    memcpy(buffer + 38, buffer + 42, 4);
    //---------------------------------------
*/

//-------------------------------------------------------------------------------------------
//------------------------ SEND -------------------------------------------------------------
    if( sendto(*sock, buffer, 42, 0, (struct sockaddr*)&saddrll, sizeof(saddrll)) < 0){//发送
        printf("now in arp_send, sendto fail!  error = %x, decimal = %d\n", errno, errno);//发送失败，获得最后错误代码
        return;
    }
//-------------------------------------------------------------------------------------------
}

int MATCH(unsigned char* buffer){
	int flag = 1;
	int m;
	//if(strncmp(buffer, "ffffffffffff", 6) != 0)	flag = 0;//错误！字符串和字符串的值区分！
	for(m = 0; m < 6; ++m){
		if(buffer[m] != 0xff){
			flag = 0;
			break;
		}
	}
	Arp_h* arp_h = (Arp_h* )(buffer + 14);
	//ntohs,network to host，网络字节序转主机序
	if(ntohs(arp_h->arp_op) != 1)	flag = 0;//ARP请求
	//-------------------- 匹配本机IP ------------------------------------------------------
	struct in_addr src_in_addr;
	inet_pton(AF_INET, myip, &src_in_addr);//ip地址转网络字节
	unsigned char dst_ip[4];
	memcpy(dst_ip, &src_in_addr, 4);
	for(m = 0; m < 4; ++m){
		if(arp_h->arp_tpa[m] != dst_ip[m]){//目的IP不为本机IP
			flag = 0;
			break;
		}
	}
	//-------------------------------------------------------------------------------------
	return flag;
}

//回复ARP报文
void ReplyARP(int* sock, unsigned char* buffer_rec){
    int m;
    unsigned char buffer[2048] = "\0";
//------------------------- 配置链路层发送结构 -------------------------------------------------
    struct sockaddr_ll saddrll;//链路层需要用此结构
    memset(&saddrll, 0, sizeof(saddrll));
    saddrll.sll_family = PF_PACKET;
    saddrll.sll_ifindex = get_nic_index(*sock, Device[0].interface);//暂时只回复主机发来的ARP
    saddrll.sll_halen = ETH_ALEN;
    for(m = 0; m < 6; ++m){//目的MAC地址
        saddrll.sll_addr[m] = buffer_rec[m + 6];//回复报文，目的MAC为对方地址
    }
//--------------------------------------------------------------------------------------------

//------------------------- FILL ETH_HEAD ----------------------------------------------------
    Eth_h* eth;
    eth = (Eth_h* )buffer;
    int t;
    for(t = 0; t < 6; ++t){//目的MAC地址，源MAC地址，使用转换
        eth->header.h_dest[t] = buffer_rec[t + 6];
        eth->header.h_source[t] = strtol(Device[0].mac_addr + 3 * t, NULL, 16);
        //printf("mac1 = %x    mac2 = %x\n", eth->header.h_dest[t], eth->header.h_source[t]);
    }
    /*for(t = 0; t < 12; ++t){
        printf("buffer = %x   ", buffer_send[t]);
    }*/
    eth->header.h_proto = htons((short)0x0806);//上层协议为ARP协议
//--------------------------------------------------------------------------------------------

//------------------------ FILL ARP_HEAD -----------------------------------------------------
    Arp_h* arp_h = (Arp_h* )(buffer + 14);
    arp_h->arp_hrd = htons(1);//1表示以太网地址
    arp_h->arp_pro = htons(0x0800);//映射的地址类型为IPv4
    arp_h->arp_hln = 6;
    arp_h->arp_pln = 4;
    arp_h->arp_op = htons(2);//回复
    for(t = 0; t < 6; ++t){//目的MAC地址，源MAC地址，使用转换
        arp_h->arp_sha[t] = strtol(Device[0].mac_addr + 3 * t, NULL, 16);
        arp_h->arp_tha[t] = buffer_rec[t + 6];
        //printf("mac1 = %x    mac2 = %x\n", eth->header.h_dest[t], eth->header.h_source[t]);
    }
    memcpy(arp_h->arp_spa, buffer_rec + 38, 4);//直接反转对方的数据报中的IP
    memcpy(arp_h->arp_tpa, buffer_rec + 28, 4);
//--------------------------------------------------------------------------------------------

//------------------------ SEND -------------------------------------------------------------
    if( sendto(*sock, buffer, 42, 0, (struct sockaddr*)&saddrll, sizeof(saddrll)) < 0){//发送
        printf("now in arp_send, sendto fail!  error = %x, decimal = %d\n", errno, errno);//发送失败，获得最后错误代码
        return;
    }
//--------------------------------------------------------------------------------------------

//------------------------ store to arp table -----------------------------------------------
	unsigned int* temp = (unsigned int* )(buffer_rec + 28);
	unsigned char* arp_head = buffer_rec + 14;
	strcpy(Arp_table[arp_item_index].ip_addr, (char* )inet_ntoa(*((struct in_addr *)temp)));
	sprintf(Arp_table[arp_item_index].mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
        arp_head[8], arp_head[9], arp_head[10], arp_head[11], arp_head[12], arp_head[13]);
	//printf("ip = %s\nmac = %s\n", Arp_table[arp_item_index].ip_addr, Arp_table[arp_item_index].mac_addr);
	arp_item_index++;
//-------------------------------------------------------------------------------------------
}

//匹配ICP数据报
int ICMP_MATCH(unsigned char* buffer){
//------------------------ 匹配目的MAC地址 ---------------------------------------------------
    int m, t;
    int flag_mac;
    for(t = 0; t < device_index; ++t){
        flag_mac = 1;
        for(m = 0; m < 6; ++m){
            if(buffer[m] != strtol(Device[t].mac_addr + 3 * m, NULL, 16)){
                flag_mac = 0;
                break;
            }
        }
        if(flag_mac == 1){
            break;
        }
    }
    if(flag_mac != 1)   return 0;//拒绝该报
//-------------------------------------------------------------------------------------------

//------------------------- 匹配IP地址 -------------------------------------------------------
    struct ip* ip_h;
    ip_h = (struct ip* )(buffer + 14);
    if(strcmp(myip, (char* )inet_ntoa(ip_h->ip_dst)) != 0){//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        return 2;//目的IP地址不是自己，需转发
    }
    return 1;//目的IP地址是自己需回复
//-------------------------------------------------------------------------------------------
}

void ICMP_Reply(unsigned char* buffer, int* sock){
//-------------------------- 构造IP&&ETH头 ---------------------------------------------------
    unsigned char buffer_reply[BUFFER_MAX] = "\0";
    memcpy(buffer_reply, buffer, BUFFER_MAX);
    struct ip* ip_h = (struct ip* )(buffer_reply + 14);
    int m, t;
    for(m = 0; m < 6; ++m){//交换MAC
        buffer_reply[m] = buffer[m + 6];
        buffer_reply[m + 6] = buffer[m];
    }
    ip_h->ip_ttl = 64;//time to live
    ip_h->ip_sum = 0;//temporarily 0
    memcpy(buffer_reply + 26, buffer + 30, 4);//交换IP
    memcpy(buffer_reply + 30, buffer + 26, 4);
    ip_h->ip_sum = checksum((unsigned short* )ip_h, 20);//ip_header's checksum
//-------------------------------------------------------------------------------------------

//-------------------------- 构造ICMP头 ------------------------------------------------------
    Icmp_h* icmp;
    Icmp_h* icmp2;
    icmp = (Icmp_h* )(buffer_reply + 34);
    icmp2 = (Icmp_h* )(buffer + 34);
    icmp->type = 0;//回复报文，类型为0
    //icmp->type = 13;
    icmp->code = 0;//code = 0
    icmp->check_sum = 0;
    icmp->id = htons(0);
    icmp->seq = icmp2->seq;//seq不变
    memcpy(buffer_reply + 42, buffer + 42, 8);//时间值不能改变!
    char* mydata = buffer_reply + 50;
    strcpy(mydata, "Hello World! With my sincerity! ");//传输的data为Hello World! With my sincerity! 
    icmp->check_sum = checksum( (unsigned short *)icmp, 64);
//-------------------------------------------------------------------------------------------

//--------------------------- 构造链路层发送结构并发送 ----------------------------------------
    int flag_mac;
    struct sockaddr_ll saddrll;//链路层需要用此结构
    memset(&saddrll, 0, sizeof(saddrll));
    saddrll.sll_family = PF_PACKET;
    //----------------------- 匹配转发的接口 -------------------------------------------------
    for(t = 0; t < device_index; ++t){
        flag_mac = 1;
        for(m = 0; m < 6; ++m){
            if(buffer[m] != strtol(Device[t].mac_addr + 3 * m, NULL, 16)){
                flag_mac = 0;
                break;
            }
        }
        if(flag_mac == 1){
            break;
        }
    }
    //printf("t = %d\n", t);
    //--------------------------------------------------------------------------------------
    saddrll.sll_ifindex = get_nic_index(*sock, Device[t].interface);//获得本接口对应的类型
    saddrll.sll_halen = ETH_ALEN;
    for(m = 0; m < 6; ++m){//目的MAC地址
        saddrll.sll_addr[m] = buffer_reply[m];//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!not sure
        //printf("%x  ", saddrll.sll_addr[m]);
    }

    if( sendto(*sock, buffer_reply, 98, 0, (struct sockaddr*)&saddrll, sizeof(saddrll)) < 0){//发送
        printf("now in icmp_send, sendto fail!  error = %x, decimal = %d\n", errno, errno);//发送失败，获得最后错误代码
        return;
    }
//------------------------------------------------------------------------------------------
}
