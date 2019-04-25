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
#define MAX_ARP_SIZE 20

const char myip0[16] = "192.168.100.1";
const char myip1[16] = "192.168.200.2";

unsigned short little_endian(unsigned short x);
int MATCH(unsigned char* buffer);
void ReplyARP(int* sock_send_arp, unsigned char* buffer_rec);
int get_nic_index(int fd, const char* nic_name);
void ROUTING(unsigned char* buffer, int* sock_icmp_send);

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
	unsigned char hlen: 4;      //头长度
	unsigned char version: 4;   //版本
	unsigned char tos;          //服务类型
	unsigned short total_len;   //数据报总长度
	unsigned short id;          //数据报ID
    unsigned short flags: 3;     //分段标志
	unsigned short frag_off: 13;//分片偏移
	unsigned char ttl;          //生存期
	unsigned char protocol;     //协议
	unsigned short check_sum;     //检验和
	struct in_addr src_addr;     //源IP地址
	struct in_addr dst_addr;     //目的IP地址
}Ip_h;

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
//---------------------------------------------------------------------------------------------------

//--------------------------- open ------------------------------------------------------------------
    int sock_receive;
	int sock_reply_arp;
	int sock_icmp_send;
	if((sock_receive=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){
        printf("error create raw socket\n");
        return -1;
    }
	if((sock_reply_arp=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){
        printf("error create raw socket\n");
        return -1;
    }
	if((sock_icmp_send=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){
	printf("error create raw socket\n");
	return -1;
    }
//--------------------------------------------------------------------------------------------------

    while(1){
        n_read = recvfrom(sock_receive,buffer,2048,0,NULL,NULL);
        if(n_read < 42){
            printf("error when recv msg \n");
            return -1;
        }
		else if(n_read == 60){//收到ARP包，检测并回复，长度为60!
			if(MATCH(buffer) == 1){
				ReplyARP(&sock_reply_arp, buffer);
			}
		}
		else if(n_read == 98){//ICMP，根据路由规则转发
			ROUTING(buffer, &sock_icmp_send);
		}
        eth_head = buffer;
        arp_head = eth_head + 14;
		ip_head = eth_head + 14;
        p = eth_head + 12;//proto
		proto[0] = p[0];
		proto[1] = p[1];
		p = arp_head + 6;
		op[0] = p[0];
		op[1] = p[1];

		if(proto[0] == 8 && proto[1] == 0){//ip包
			proto[0] = (ip_head + 9)[0];
			printf("------------------------------------Protocol:");
			switch(proto[0]){
				case IPPROTO_ICMP: printf("icmp"); break;
				case IPPROTO_IGMP: printf("igmp"); break;
				case IPPROTO_IPIP: printf("ipip"); break;
				case IPPROTO_TCP: printf("tcp"); break;
				case IPPROTO_UDP: printf("udp"); break;
			}
			printf("----------------------------------------------\n");
			//---------------------------------------------- ip -----------------------------------------------
            printf("  Sender MAC address: Vmware_");
			p = eth_head + 6;
			printf("%.2x:%02x:%02x: (%.2x:%02x:%02x:%02x:%02x:%02x)\n", p[3],p[4],p[5],p[0],p[1],p[2],p[3],p[4],p[5]);
			printf("  Target MAC address: Vmware_");
			p = eth_head;
			printf("%.2x:%02x:%02x: (%.2x:%02x:%02x:%02x:%02x:%02x)\n", p[3],p[4],p[5],p[0],p[1],p[2],p[3],p[4],p[5]);
			Ip_h ip_h;//IP头，同上
			memcpy(&ip_h, buffer + 14, 20);//赋值ip头
			p = ip_head + 12;
			printf("Internet Protocol Version 4, Src: %d.%d.%d.%d (%d.%d.%d.%d), Dst: %d.%d.%d.%d (%d.%d.%d.%d)\n", p[0],p[1],p[2],p[3],p[0],p[1],p[2],p[3], p[4],p[5],p[6],p[7], p[4],p[5],p[6],p[7]);
			printf("Version: %d\n", ip_h.version);
			printf("Header length: %d bytes\n", ip_h.hlen * 4);
			printf("Total Length: %d\n", little_endian(ip_h.total_len));
			printf("Identification: 0x%x\n", little_endian(ip_h.id));
			/*printf("Flags: 0x%x\n", ip_h.flags);
			printf("Fragment offset: %d\n", ip_h.frag_off);*/
			printf("Time to live: %d\n", ip_h.ttl);
			printf("Header checksum: 0x%x [correct]\n", little_endian(ip_h.check_sum));
			printf("Source: %d.%d.%d.%d (%d.%d.%d.%d)\nDestination: %d.%d.%d.%d (%d.%d.%d.%d)\n", p[0],p[1],p[2],p[3], p[0],p[1],p[2],p[3], p[4],p[5],p[6],p[7], p[4],p[5],p[6],p[7]);
			printf("-----------------------------------------------------------------------------------------------\n\n");
			//-------------------------------------------------------------------------------------------------

			if(proto[0] == IPPROTO_ICMP){//icmp
				Icmp_h icmp_h;//ICMP头，用于存储获得的icmp头
				memcpy(&icmp_h, buffer + 34, 8);//赋值icmp头
				printf("------------------------------Internet Control Message Protocol--------------------------------\n");
				if(icmp_h.type == 0)
					printf("Type: 0 (Echo (ping) reply)\n");
				else
					printf("Type: 8 (Echo (ping) request)\n");
				printf("Code: %d\n", icmp_h.code);
				printf("Checksum: 0x%x\n", little_endian(icmp_h.check_sum));
				printf("Identifier (BE): %d (0x%x)\n", little_endian(icmp_h.id), little_endian(icmp_h.id));
				printf("Identifier (LE): %d (0x%x)\n", icmp_h.id, icmp_h.id);
				printf("Sequence number (BE): %d\n", little_endian(icmp_h.seq));
				printf("Sequence number (LE): %d\n", icmp_h.seq);
				printf("Data (56 bytes)\n");
				printf("-----------------------------------------------------------------------------------------------\n\n");
			}
		}
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
	//-------------------- 匹配本机IP ---------------------------------
	struct in_addr src_in_addr;
	inet_pton(AF_INET, myip0, &src_in_addr);//ip地址转网络字节
	unsigned char dst_ip[4];
	memcpy(dst_ip, &src_in_addr, 4);
	for(m = 0; m < 4; ++m){
		if(arp_h->arp_tpa[m] != dst_ip[m]){//目的IP不为本机IP
			flag = 0;
			break;
		}
	}
	//----------------------------------------------------------------
	return flag;
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

//回复ARP报文
void ReplyARP(int* sock_send_arp, unsigned char* buffer_rec){
    int m;
    unsigned char buffer[2048] = "\0";
//------------------------- 配置链路层发送结构 -------------------------------------------------
    struct sockaddr_ll saddrll;//链路层需要用此结构
    memset(&saddrll, 0, sizeof(saddrll));
    saddrll.sll_family = PF_PACKET;
    saddrll.sll_ifindex = get_nic_index(*sock_send_arp, Device[0].interface);//暂时只回复主机发来的ARP
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


void ROUTING(unsigned char* buffer, int* sock_icmp_send){
	struct ip* ip_h;
	ip_h = (struct ip* )(buffer + 14);
	unsigned char dst_ip[16] = "\0";
	unsigned char change_ip[16] = "\0";
	unsigned char change_dst_mac[18] = "\0";
	unsigned char change_src_mac[18] = "\0";
	unsigned char change_interface[16] = "\0";
	strcpy(dst_ip, (char* )inet_ntoa(ip_h->ip_dst));
	int m;
	for(m = 0; m < route_item_index; ++m){
		if(strcmp(dst_ip, route_info[m].destination) == 0){
			strcpy(change_interface, route_info[m].interface);
			if(route_info[m].gateway[0] != '*'){
				strcpy(change_ip, route_info[m].gateway);
			}
			else{
				strcpy(change_ip, route_info[m].destination);
			}
			break;
		}
	}
	for(m = 0; m < arp_item_index; ++m){
		if(strcmp(change_ip, Arp_table[m].ip_addr) == 0){
			strcpy(change_dst_mac, Arp_table[m].mac_addr);
			break;
		}
	}
	for(m = 0; m < device_index; ++m){
		if(strcmp(change_interface, Device[m].interface) == 0){
			strcpy(change_src_mac, Device[m].mac_addr);
			break;
		}
	}
	unsigned char change_buffer[BUFFER_MAX] = "\0";
	strcpy(change_buffer, buffer);
	for(m = 0; m < 6; ++m){
		change_buffer[m] = strtol(change_dst_mac + 3 * m, NULL, 16);
		change_buffer[m + 6] = strtol(change_src_mac + 3 * m, NULL, 16);
	}

	for(m = 0; m < 98; ++m){
		printf("%x ", change_buffer[m]);
	}
	printf("\n");


	struct sockaddr_ll saddrll;//链路层需要用此结构
    memset(&saddrll, 0, sizeof(saddrll));
    saddrll.sll_family = PF_PACKET;
    //saddrll.sll_protocol = ETH_P_IP;//????
    saddrll.sll_ifindex = get_nic_index(*sock_icmp_send, change_interface);//获得本接口对应的类型
    saddrll.sll_halen = ETH_ALEN;
    for(m = 0; m < 6; ++m){//目的MAC地址
        saddrll.sll_addr[m] = strtol(change_dst_mac + 3 * m, NULL, 16);//字符串转16进制数
        //printf("%x  ", saddrll.sll_addr[m]);
    }

	if( sendto(*sock_icmp_send, change_buffer, 98, 0, (struct sockaddr*)&saddrll, sizeof(saddrll)) < 0){//发送
            printf("now in icmp_send, sendto fail!  error = %x, decimal = %d\n", errno, errno);//发送失败，获得最后错误代码
            return ;
    }
}
