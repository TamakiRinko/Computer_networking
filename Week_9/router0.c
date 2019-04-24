#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#define BUFFER_MAX 2048
#define MAX_ROUTE_INFO 10
#define MAX_DEVICE 5
const char myip[16] = "192.168.100.1";

unsigned short little_endian(unsigned short x);
int MATCH(unsigned char* buffer);


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

//路由表
struct route_item{
	char destination[16];
	char gateway[16];
	char netmask[16];
	char interface[16];
}route_info[MAX_ROUTE_INFO];
int route_item_index = 0;

//本设备接口与MAC地址的对应关系
struct DEVICE_ITEM{
    unsigned char interface[14];//自身接口的名称
    unsigned char mac_addr[18];//自身接口的MAC地址
}Device[MAX_DEVICE];
int device_index = 0;


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

//--------------------------- arp table && device set -----------------------------------------------
    strcpy(Device[0].interface, "eth0");
    memcpy(Device[0].mac_addr, "00:0c:29:84:0b:6c", 18);
	strcpy(Device[1].interface, "eth1");
    memcpy(Device[1].mac_addr, "00:0c:29:84:0b:76", 18);
    device_index += 2;
//---------------------------------------------------------------------------------------------------

//--------------------------- open ------------------------------------------------------------------
    int sock_fd;
	if((sock_fd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){
        printf("error create raw socket\n");
        return -1;
    }
//--------------------------------------------------------------------------------------------------

    while(1){
        n_read = recvfrom(sock_fd,buffer,2048,0,NULL,NULL);
        if(n_read < 42){
            printf("error when recv msg \n");
            return -1;
        }
		else if(n_read == 42){//收到ARP包，检测并回复
			MATCH(buffer);
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



		/*if(proto[0] == 8 && proto[1] == 6){//ARP包
			if(op[1] == 2)
				printf("------------------------------Address Resolution Protocol (reply)------------------------------\n");
			else
				printf("------------------------------Address Resolution Protocol (request)----------------------------\n");
			p = arp_head;
			type = p[1];
			printf("  Hardware type: Ethernet (%d)\n", type);
			proto[0] = p[2];
			proto[1] = p[3];
			printf("  Protocol type: IP (0x0%d0%d)\n", proto[0], proto[1]);
			len = p[4];
			printf("  Hardware size: %d\n", len);
			len = p[5];
			printf("  Protocol size: %d\n", len);
			if(op[1] == 2)
				printf("  Opcode: reply (2)\n  [Is gratuitous: False]\n");
			else	
				printf("  Opcode: request (1)\n  [Is gratuitous: False]\n");
			printf("  Sender MAC address: Vmware_");
			p = arp_head + 8;
			printf("%.2x:%02x:%02x: (%.2x:%02x:%02x:%02x:%02x:%02x)\n", p[3],p[4],p[5],p[0],p[1],p[2],p[3],p[4],p[5]);
			printf("  Sender IP address: ");
			p = arp_head + 14;
			printf("%d.%d.%d.%d (%d.%d.%d.%d)\n", p[0],p[1],p[2],p[3], p[0],p[1],p[2],p[3]);
			if(op[1] == 2)
				printf("  Target MAC address: Vmware_");
			else
				printf("  Target MAC address: 00:00:00:");
			p = arp_head + 18;
			printf("%.2x:%02x:%02x: (%.2x:%02x:%02x:%02x:%02x:%02x)\n", p[3],p[4],p[5],p[0],p[1],p[2],p[3],p[4],p[5]);
			printf("  Target IP address: ");
			p = arp_head + 24;
			printf("%d.%d.%d.%d (%d.%d.%d.%d)\n", p[0],p[1],p[2],p[3], p[0],p[1],p[2],p[3]);
			printf("-----------------------------------------------------------------------------------------------\n\n");
		}
		else */if(proto[0] == 8 && proto[1] == 0){//ip包
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
	if(strncmp(buffer, "ffffffffffff", 6) != 0)	flag = 0;//ARP广播
	Arp_h* arp_h = (Arp_h* )(buffer + 14);
	if(arp_h->arp_op != 1)	flag = 0;//ARP请求
	//-------------------- 匹配本机IP ---------------------------------
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
	//----------------------------------------------------------------
	return flag;
}