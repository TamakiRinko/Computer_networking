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
#define MAX_ROUTE_INFO 10
#define MAX_DEVICE 5
#define MAX_ARP_SIZE 30

const char myip0[16] = "192.168.100.1";
const char myip1[16] = "192.168.200.2";

unsigned short little_endian(unsigned short x);
int MATCH(unsigned char* buffer, int* index);
void ReplyARP(int* sock_send_arp, unsigned char* buffer_rec, int index);
int get_nic_index(int fd, const char* nic_name);
void ROUTING(unsigned char* buffer, int* sock_receive);
unsigned short checksum(unsigned short* addr,int length);

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

//以太网头部
typedef struct ETH_HEAD{
    struct ethhdr header;
}Eth_h;

//转发表
struct Route_item{
	unsigned char destination[16];
	unsigned char gateway[16];
	unsigned char netmask[16];
	unsigned char interface[16];
}route_info[MAX_ROUTE_INFO];
int route_item_index = 0;

//本设备接口与MAC地址的对应关系
struct DEVICE_ITEM{
    unsigned char interface[14];//自身接口的名称
    unsigned char mac_addr[18];	//自身接口的MAC地址
}Device[MAX_DEVICE];
int device_index = 0;

//ARP表
struct ARP_TABLE_ITEM{
    unsigned char ip_addr[16];
    unsigned char mac_addr[18];
}Arp_table[MAX_ARP_SIZE];
int arp_item_index = 0;

int main(int argc,char* argv[]){
//--------------------------- 变量定义 --------------------------------------------------------------
    int proto[2];//协议
	int op[2];//ARP操作码
	int type;//以太网类型
	int len;//MAC地址长度 or IP地址长度
    int n_read;
    unsigned char buffer[BUFFER_MAX];
    char* eth_head;
    char* arp_head;
	char* ip_head;
    unsigned char *p;
    int index = -1;
//---------------------------------------------------------------------------------------------------

//--------------------------- arp table && device && ip table set -----------------------------------
    strcpy(Device[0].interface, "eth0");
    memcpy(Device[0].mac_addr, "00:0c:29:84:0b:6c", 18);
	strcpy(Device[1].interface, "eth1");
    memcpy(Device[1].mac_addr, "00:0c:29:84:0b:76", 18);
    device_index += 2;

	strcpy(route_info[0].destination, "192.168.100.0");//PC1
	strcpy(route_info[0].gateway, "*");
	strcpy(route_info[0].netmask, "255.255.255.0");
	strcpy(route_info[0].interface, "eth0");
	strcpy(route_info[1].destination, "192.168.200.0");//Router1
	strcpy(route_info[1].gateway, "*");
	strcpy(route_info[1].netmask, "255.255.255.0");
	strcpy(route_info[1].interface, "eth1");
	strcpy(route_info[2].destination, "192.168.5.0");//PC2
	strcpy(route_info[2].gateway, "192.168.200.1");//发往192.168.5.x的下一跳为192.168.200.1
	strcpy(route_info[2].netmask, "255.255.255.0");
	strcpy(route_info[2].interface, "eth1");
	route_item_index += 3;

	strcpy(Arp_table[0].ip_addr, "192.168.200.1");
	strcpy(Arp_table[0].mac_addr, "00:0c:29:19:eb:fd");
	arp_item_index++;
//---------------------------------------------------------------------------------------------------

//--------------------------- open ------------------------------------------------------------------
	int sock_receive;
	if((sock_receive=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){
		printf("error create raw socket\n");
		return -1;
	}
//---------------------------------------------------------------------------------------------------

//--------------------------- 接收数据报 -------------------------------------------------------------
    while(1){
        n_read = recvfrom(sock_receive,buffer,2048,0,NULL,NULL);
        if(n_read < 42){
            printf("error when recv msg \n");
            return -1;
        }
		else if(n_read == 60){//收到ARP请求包，检测并回复，长度为60!
			if(MATCH(buffer, &index) == 1){//ARP请求包匹配成功
				ReplyARP(&sock_receive, buffer, index);//回复ARP包提供自己的MAC地址
			}
		}
		else if(n_read == 98){//ICMP，根据路由规则转发
			ROUTING(buffer, &sock_receive);//根据路由规则进行转发
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

//匹配ARP报文
int MATCH(unsigned char* buffer, int* index){
//-------------------------------- 匹配MAC和opcode ---------------------------------------
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
	if(ntohs(arp_h->arp_op) != 1)	flag = 0;//ARP请求，ntohs,network to host，网络字节序转主机序
//--------------------------------------------------------------------------------------
	
//--------------------------------- 匹配本机IP ------------------------------------------
	struct in_addr src_in_addr;
    struct in_addr src_in_addr_1;
    unsigned char dst_ip[4];
	unsigned char dst_ip_1[4];
	inet_pton(AF_INET, myip0, &src_in_addr);//ip地址转网络字节
    inet_pton(AF_INET, myip1, &src_in_addr_1);//ip地址转网络字节
    memcpy(dst_ip, &src_in_addr, 4);
	memcpy(dst_ip_1, &src_in_addr_1, 4);

	for(m = 0; m < 4; ++m){//匹配myip0
		if(arp_h->arp_tpa[m] != dst_ip[m]){//目的IP不为本机IP
			flag = 0;
			break;
		}
	}
    if(flag == 0){//不成功，再匹配myip1
        flag = 1;
        for(m = 0; m < 4; ++m){
            if(arp_h->arp_tpa[m] != dst_ip_1[m]){//目的IP不为本机IP
                flag = 0;
                break;
            }
	    }
        if(flag == 1)   *index = 1;//eth1
    }
    else{//匹配myip0成功
        *index = 0;//eth0
    }
//--------------------------------------------------------------------------------------------
	return flag;
}

//回复ARP报文
void ReplyARP(int* sock_send_arp, unsigned char* buffer_rec, int index){
    int m;
    unsigned char buffer[2048] = "\0";
//------------------------- 配置链路层发送结构 -------------------------------------------------
    struct sockaddr_ll saddrll;//链路层需要用此结构
    memset(&saddrll, 0, sizeof(saddrll));
    saddrll.sll_family = PF_PACKET;
    saddrll.sll_ifindex = get_nic_index(*sock_send_arp, Device[index].interface);//暂时只回复主机发来的ARP
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
//-------------------------------------------------------------------------------------------
//------------------------ SEND -------------------------------------------------------------
    if( sendto(*sock_send_arp, buffer, 42, 0, (struct sockaddr*)&saddrll, sizeof(saddrll)) < 0){//发送
        printf("now in arp_send, sendto fail!  error = %x, decimal = %d\n", errno, errno);//发送失败，获得最后错误代码
        return;
    }
//-------------------------------------------------------------------------------------------

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


void ROUTING(unsigned char* buffer, int* sock_receive){
//----------------------------- 变量定义 ----------------------------------------------------
	struct ip* ip_h;
	ip_h = (struct ip* )(buffer + 14);
	unsigned char dst_ip[16] = "\0";//目的IP
	unsigned char change_ip[16] = "\0";//下一跳IP
	unsigned char change_dst_mac[18] = "\0";//新的目的MAC
	unsigned char change_src_mac[18] = "\0";//新的源MAC
	unsigned char change_interface[16] = "\0";//转发接口
	unsigned int netmask;//子网掩码对应的整数
//------------------------------------------------------------------------------------------
	strcpy(dst_ip, (char* )inet_ntoa(ip_h->ip_dst));
	int m;
//----------------------------- 检查路由表找到下一跳IP地址和转发接口 --------------------------
	for(m = 0; m < route_item_index; ++m){
		netmask = htonl(inet_addr(route_info[m].netmask));//子网掩码
		if((htonl(inet_addr(route_info[m].destination)) & netmask) == (htonl(inet_addr(dst_ip)) & netmask)){//IP地址匹配
		//if(strncmp(dst_ip, route_info[m].destination, netmask_num) == 0){
			strcpy(change_interface, route_info[m].interface);
			if(route_info[m].gateway[0] != '*'){
				strcpy(change_ip, route_info[m].gateway);
			}
			else{
				strcpy(change_ip, dst_ip);
			}
			break;
		}
	}
//------------------------------------------------------------------------------------------

//------------------------------ 检查ARP表找到下一跳MAC地址 ----------------------------------
	for(m = 0; m < arp_item_index; ++m){
		if(strcmp(change_ip, Arp_table[m].ip_addr) == 0){
			strcpy(change_dst_mac, Arp_table[m].mac_addr);
			break;
		}
	}
//------------------------------------------------------------------------------------------

//------------------------------ 检查设备表找到转发接口的MAC地址 -----------------------------
	for(m = 0; m < device_index; ++m){
		if(strcmp(change_interface, Device[m].interface) == 0){
			strcpy(change_src_mac, Device[m].mac_addr);
			break;
		}
	}
//------------------------------------------------------------------------------------------

//------------------------------ 重新构造ICMP数据报 -----------------------------------------
	unsigned char change_buffer[BUFFER_MAX] = "\0";
	memcpy(change_buffer, buffer, BUFFER_MAX);
	struct ip* ip_h_2 = (struct ip* )(change_buffer + 14);
	for(m = 0; m < 6; ++m){
		change_buffer[m] = strtol(change_dst_mac + 3 * m, NULL, 16);
		change_buffer[m + 6] = strtol(change_src_mac + 3 * m, NULL, 16);
	}
	ip_h_2->ip_ttl -= 1;//ttl - 1
	//if(ip_h_2->ip_ttl == 0)//扔
	ip_h_2->ip_sum = 0;//temporarily
	ip_h_2->ip_sum = checksum((unsigned short* )ip_h_2, 20);
//------------------------------------------------------------------------------------------

/*	for(m = 0; m < 98; ++m){
		printf("%x ", change_buffer[m]);
	}
	printf("\n");
*/

//------------------------------- 定义链路层发送结构并发送 -----------------------------------
	struct sockaddr_ll saddrll;//链路层需要用此结构
    memset(&saddrll, 0, sizeof(saddrll));
    saddrll.sll_family = PF_PACKET;
    //saddrll.sll_protocol = ETH_P_IP;//????
    saddrll.sll_ifindex = get_nic_index(*sock_receive, change_interface);//获得本接口对应的类型
    saddrll.sll_halen = ETH_ALEN;
    for(m = 0; m < 6; ++m){//目的MAC地址
        saddrll.sll_addr[m] = strtol(change_dst_mac + 3 * m, NULL, 16);//字符串转16进制数
        //printf("%x  ", saddrll.sll_addr[m]);
    }

	if( sendto(*sock_receive, change_buffer, 98, 0, (struct sockaddr*)&saddrll, sizeof(saddrll)) < 0){//发送
            printf("now in icmp_send, sendto fail!  error = %x, decimal = %d\n", errno, errno);//发送失败，获得最后错误代码
            return;
    }
//-------------------------------------------------------------------------------------------
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