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
#define MAX_VPN_ROUTE 10

unsigned short little_endian(unsigned short x);
int MATCH(unsigned char* buffer, int* index);
void ReplyARP(int* sock_send_arp, unsigned char* buffer_rec, int index);
int get_nic_index(int fd, const char* nic_name);
void ROUTING(unsigned char* buffer, int* sock);
unsigned short checksum(unsigned short* addr,int length);
void RECEIVE_ROUTER(int* sock);
int ICMP_MATCH(unsigned char* buffer);
void SendARP(int* sock, unsigned char* change_ip, int interface_index);
int ARP_MATCH_REPLY(int* sock, unsigned char* buffer_rece_arp, int interface_index, unsigned char* change_ip);

const char gateway_ip[16] = "172.0.0.1";

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
	unsigned char interface[14];
    unsigned char vpn_ip[16];
}route_info[MAX_ROUTE_INFO];
int route_item_index = 0;

//本设备接口与MAC地址的对应关系
struct DEVICE_ITEM{
    unsigned char interface[14];//自身接口的名称
    unsigned char mac_addr[18];	//自身接口的MAC地址
    unsigned char ip_addr[16];//自身接口的IP地址
    int is_entrance;            //是否为VPN接口????
}Device[MAX_DEVICE];
int device_index = 0;

//ARP表
struct ARP_TABLE_ITEM{
    unsigned char ip_addr[16];
    unsigned char mac_addr[18];
}Arp_table[MAX_ARP_SIZE];
int arp_item_index = 0;

//VPN表，未定
struct VPN_Route_item{
    unsigned char destination[16];
    unsigned char gateway[16];
    unsigned char netmask[16];
    unsigned char interface[14];
}VPN_route_info[MAX_VPN_ROUTE];
int vpn_route_index = 0;

int repack_packet(char* buffer, int* sock);
int unpack_packet(char* buffer, int* sock);

int main(int argc,char* argv[]){
//--------------------------- arp table && device && ip table set -----------------------------------
    strcpy(Device[0].interface, "eth0");
    memcpy(Device[0].mac_addr, "00:0c:29:95:5f:ed", 18);
    strcpy(Device[0].ip_addr, "172.0.0.2");
    Device[0].is_entrance = 1;
	strcpy(Device[1].interface, "eth1");
    memcpy(Device[1].mac_addr, "00:0c:29:95:5f:f7", 18);
    strcpy(Device[1].ip_addr, "10.0.1.1");
    Device[1].is_entrance = 0;
    device_index += 2;

	strcpy(route_info[0].destination, "172.0.0.0");//PC1
	strcpy(route_info[0].gateway, "*");
	strcpy(route_info[0].netmask, "255.255.255.0");
	strcpy(route_info[0].interface, "eth0");
    strcpy(route_info[0].vpn_ip, "*");
	strcpy(route_info[1].destination, "10.0.1.0");//Router1
	strcpy(route_info[1].gateway, "*");
	strcpy(route_info[1].netmask, "255.255.255.0");
	strcpy(route_info[1].interface, "eth1");
    strcpy(route_info[1].vpn_ip, "*");
	strcpy(route_info[2].destination, "10.0.0.0");//PC2
	strcpy(route_info[2].gateway, "172.0.0.1");//下一跳直接为网关地址
	strcpy(route_info[2].netmask, "255.255.255.0");
	strcpy(route_info[2].interface, "eth0");
    strcpy(route_info[2].vpn_ip, "192.168.0.2");
	route_item_index += 3;

	/*strcpy(Arp_table[0].ip_addr, "192.168.200.1");
	strcpy(Arp_table[0].mac_addr, "00:0c:29:19:eb:fd");
	arp_item_index++;*/
//---------------------------------------------------------------------------------------------------

//--------------------------- open ------------------------------------------------------------------
	int sock;
	if((sock=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){
		printf("error create raw socket\n");
		return -1;
	}
//---------------------------------------------------------------------------------------------------

//--------------------------- 接收数据报 -------------------------------------------------------------
    while(1){
        RECEIVE_ROUTER(&sock);
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
	int m;
    int flag = 1;
	//if(strncmp(buffer, "ffffffffffff", 6) != 0)	flag = 0;//错误！字符串和字符串的值区分！
	for(m = 0; m < 6; ++m){
		if(buffer[m] != 0xff){
            return 0;
		}
	}
	Arp_h* arp_h = (Arp_h* )(buffer + 14);
	if(ntohs(arp_h->arp_op) != 1)	return 0;//ARP请求，ntohs,network to host，网络字节序转主机序
//--------------------------------------------------------------------------------------
	
//--------------------------------- 匹配本机IP ------------------------------------------
	struct in_addr src_in_addr;
    struct in_addr src_in_addr_1;
    unsigned char dst_ip[4];
	unsigned char dst_ip_1[4];
	inet_pton(AF_INET, Device[0].ip_addr, &src_in_addr);//ip地址转网络字节
    inet_pton(AF_INET, Device[1].ip_addr, &src_in_addr_1);//ip地址转网络字节
    memcpy(dst_ip, &src_in_addr, 4);//100.1
	memcpy(dst_ip_1, &src_in_addr_1, 4);//200.2

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
    //printf("index = %d\n", *index);
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
        eth->header.h_source[t] = strtol(Device[index].mac_addr + 3 * t, NULL, 16);
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
        arp_h->arp_sha[t] = strtol(Device[index].mac_addr + 3 * t, NULL, 16);
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


void ROUTING(unsigned char* buffer, int* sock){
//----------------------------- 变量定义 ----------------------------------------------------
	struct ip* ip_h;
	ip_h = (struct ip* )(buffer + 14);
	unsigned char dst_ip[16] = "\0";//目的IP
	unsigned char change_ip[16] = "\0";//下一跳IP
	unsigned char change_dst_mac[18] = "\0";//新的目的MAC
	unsigned char change_src_mac[18] = "\0";//新的源MAC
	unsigned char change_interface[16] = "\0";//转发接口
	unsigned int netmask;//子网掩码对应的整数

    int flag = 0;
    int interface_index = -1;//接口下标
//------------------------------------------------------------------------------------------
	strcpy(dst_ip, (char* )inet_ntoa(ip_h->ip_dst));
	int m;
//----------------------------- 检查路由表找到下一跳IP地址和转发接口 --------------------------
	for(m = 0; m < route_item_index; ++m){
		netmask = htonl(inet_addr(route_info[m].netmask));//子网掩码
		if((htonl(inet_addr(route_info[m].destination)) & netmask) == (htonl(inet_addr(dst_ip)) & netmask)){//IP地址匹配
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

//------------------------------ 匹配接口下标并找到发送接口MAC地址 ----------------------------
    for(m = 0; m < device_index; ++m){
        if(strcmp(change_interface, Device[m].interface) == 0){
            interface_index = m;
            strcpy(change_src_mac, Device[m].mac_addr);
            break;
        }
    }
//------------------------------------------------------------------------------------------

//------------------------------ 检查ARP表找到下一跳MAC地址，若无，则发送ARP请求报文 -----------
	for(m = 0; m < arp_item_index; ++m){
		if(strcmp(change_ip, Arp_table[m].ip_addr) == 0){
			strcpy(change_dst_mac, Arp_table[m].mac_addr);
            flag = 1;
			break;
		}
	}
    if(flag == 0){//未有匹配，发送ARP请求报文并保存
        unsigned char buffer_rece_arp[BUFFER_MAX] = "\0";
        unsigned char* arp_head = buffer_rece_arp + 14;
        SendARP(sock, change_ip, interface_index);//发送ARP请求报文
        while(ARP_MATCH_REPLY(sock, buffer_rece_arp, interface_index, change_ip) != 1){;}//等待ARP回复
        //-------------------------- 匹配，添加表项 -------------------------------------------------------
        strcpy(Arp_table[arp_item_index].ip_addr, change_ip);
        sprintf(Arp_table[arp_item_index].mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",//sure
            arp_head[8], arp_head[9], arp_head[10], arp_head[11], arp_head[12], arp_head[13]);
        strcpy(change_dst_mac, Arp_table[arp_item_index].mac_addr);
        arp_item_index++;
        //-----------------------------------------------------------------------------------------------
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

//------------------------------- 定义链路层发送结构并发送 -----------------------------------
	struct sockaddr_ll saddrll;//链路层需要用此结构
    memset(&saddrll, 0, sizeof(saddrll));
    saddrll.sll_family = PF_PACKET;
    //saddrll.sll_protocol = ETH_P_IP;//????
    saddrll.sll_ifindex = get_nic_index(*sock, change_interface);//获得本接口对应的类型
    saddrll.sll_halen = ETH_ALEN;
    for(m = 0; m < 6; ++m){//目的MAC地址
        saddrll.sll_addr[m] = strtol(change_dst_mac + 3 * m, NULL, 16);//字符串转16进制数
        //printf("%x  ", saddrll.sll_addr[m]);
    }

	if( sendto(*sock, change_buffer, 98, 0, (struct sockaddr*)&saddrll, sizeof(saddrll)) < 0){//发送
            printf("now in icmp_send, sendto fail!  error = %x, decimal = %d\n", errno, errno);//发送失败，获得最后错误代码
            return;
    }
//------------------------------------------------------------------------------------------
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

//匹配ICMP数据报
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
    //if((strcmp(Device[0].ip_addr, (char* )inet_ntoa(ip_h->ip_dst)) != 0) && (strcmp(Device[1].ip_addr, (char* )inet_ntoa(ip_h->ip_dst)) != 0)){
    for(m = 0; m < device_index; ++m){
        if(strcmp(Device[m].ip_addr, (char* )inet_ntoa(ip_h->ip_dst)) == 0)
            return 1;//目的IP地址是自己，可能需要回复，也可能需要转发
    }
    return 2;////目的IP不是自己，为内部子网发出，需转发
//-------------------------------------------------------------------------------------------
}

//回复ICMP报文
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

//发送ARP报文获得网关MAC地址
void SendARP(int* sock, unsigned char* change_ip, int interface_index){
    int m;
    unsigned char buffer[2048] = "\0";
//------------------------- 配置链路层发送结构 -------------------------------------------------
    struct sockaddr_ll saddrll;//链路层需要用此结构
    memset(&saddrll, 0, sizeof(saddrll));
    saddrll.sll_family = PF_PACKET;
    saddrll.sll_ifindex = get_nic_index(*sock, Device[interface_index].interface);//获得本接口对应的类型
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
        eth->header.h_source[t] = strtol(Device[interface_index].mac_addr + 3 * t, NULL, 16);
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
        arp_h->arp_sha[t] = strtol(Device[interface_index].mac_addr + 3 * t, NULL, 16);
        arp_h->arp_tha[t] = 0x0;
        //printf("mac1 = %x    mac2 = %x\n", eth->header.h_dest[t], eth->header.h_source[t]);
    }
    struct in_addr src_in_addr, dst_in_addr;
    inet_pton(AF_INET, Device[interface_index].ip_addr, &src_in_addr);//ip地址转网络字节
    inet_pton(AF_INET, change_ip, &dst_in_addr);//根据路由表中的IP地址选择
    memcpy(arp_h->arp_spa, &src_in_addr, 4);
    memcpy(arp_h->arp_tpa, &dst_in_addr, 4);

/*
    arp_h->arp_spa = inet_addr(Device[interface_index].ip_addr);
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

//匹配ARP回复报文
int ARP_MATCH_REPLY(int* sock, unsigned char* buffer_rece_arp, int interface_index, unsigned char* change_ip){
//------------------------------ 变量定义 ------------------------------------------------------
    char* eth_head;
    unsigned char* arp_head;
    Arp_h* arp_head2;//判断返回的ARP包的源IP是否为输入参数
    int len_arp;//收到ARP包的长度
    int m;
//---------------------------------------------------------------------------------------------
    len_arp = recvfrom(*sock, buffer_rece_arp, 2048, 0, NULL, NULL);
    eth_head = buffer_rece_arp;
    arp_head = buffer_rece_arp + 14;
    if(len_arp != 60)   return -1;//返回len = 60!!!!!!!
    if(arp_head[7]!= 2)    return -1;//不是ARP响应
//------------------- 判断是否为对应的MAC地址 --------------------------------------------------
    int match = 1;
    for(m = 0; m < 6; ++m){
        if(arp_head[m + 18] != (strtol(Device[interface_index].mac_addr + 3 * m, NULL, 16))){//匹配我方MAC地址
            match = 0;
            break;
        }
    }
//--------------------------------------------------------------------------------------------

//--------------------- 匹配源IP地址 --------------------------------------------------------
    arp_head2 = (Arp_h* )(buffer_rece_arp + 14);
    struct in_addr src_in_addr;
    inet_pton(AF_INET, change_ip, &src_in_addr);//ip地址转网络字节
    unsigned char src_ip[4];
    memcpy(src_ip, &src_in_addr, 4);
    for(m = 0; m < 4; ++m){
        if(arp_head2->arp_spa[m] != src_ip[m]){
            match = 0;
            break;
        }
    }
    if(!match)  return -1;
//--------------------------------------------------------------------------------------------
    return 1;
}

//收包并转发或回复
void RECEIVE_ROUTER(int* sock){
    int n_read;
    unsigned char buffer[BUFFER_MAX] = "\0";
    int index = -1;
    n_read = recvfrom(*sock,buffer,2048,0,NULL,NULL);
    Eth_h* eth = (Eth_h* )buffer;
    unsigned short mytype = ntohs(eth->header.h_proto);//根据proto判断数据报类型
    if(n_read < 42){
        printf("error when recv msg \n");
        return;
    }
    else if(mytype == 0x0806){//收到ARP请求包，检测并回复，长度为60!
        //printf("here\n");
        if(MATCH(buffer, &index) == 1){//ARP请求包匹配成功
            //printf("here index = %d\n", index);
            ReplyARP(sock, buffer, index);//回复ARP包提供自己的MAC地址
        }
    }
    else if(mytype == 0x0800){//ICMP，根据路由规则转发
        int type = ICMP_MATCH(buffer);
        if(type == 0)   return;//拒绝该包
        else if(type == 2){//目的IP不是自己，为内部子网发出，封包，转发
            //ROUTING(buffer, sock);//根据路由规则进行转发
            repack_packet(buffer, sock);
        }
        else if(type == 1){//目的地址是自己的某接口，解包，回复 or 转发
            //ICMP_Reply(buffer, sock);
            unpack_packet(buffer, sock);
        }
    }
}

int repack_packet(char* buffer, int* sock){
    printf("hahaha here!\n");
    unsigned char buf[BUFFER_MAX] = "\0";
    memcpy(buf, buffer, BUFFER_MAX);

    struct ip* ip_h = (struct ip* )(buf + 14);//内部IP头
    char dest_ip[16] = "\0";
    strcpy(dest_ip, (char* )inet_ntoa(ip_h->ip_dst));//获得目的IP地址
    printf("dest_ip = %s\n", dest_ip);

    int i;
    int m;
    unsigned int netmask;//子网掩码对应的整数
    int flag = 0;
    int flag1 = 0;
    unsigned char change_ip[16] = "\0";//下一跳IP
    unsigned char change_interface[16] = "\0";//转发接口
    unsigned char change_dst_mac[18] = "\0";//新的目的MAC
    unsigned char change_src_mac[18] = "\0";//新的源MAC
    unsigned char dest_vpn_ip[16] = "\0";//目的
    int interface_index = -1;//接口下标

    for(i = 0; i < route_item_index; ++i){
        netmask = htonl(inet_addr(route_info[i].netmask));//子网掩码
        if((htonl(inet_addr(route_info[i].destination)) & netmask) == (htonl(inet_addr(dest_ip)) & netmask)){//IP地址匹配
            strcpy(change_interface, route_info[i].interface);
            strcpy(dest_vpn_ip, route_info[i].vpn_ip);//目的VPN IP地址
            if(route_info[i].gateway[0] != '*'){//不可能
				strcpy(change_ip, route_info[i].gateway);
			}
			else{
				strcpy(change_ip, dest_ip);
			}
            flag = 1;
			break;
        }
    }
    printf("change_ip = %s, dest_vpn_ip = %s, i = %d, interface = %s\n", change_ip, dest_vpn_ip, i, change_interface);

    if(flag == 0){
        strcpy(dest_vpn_ip, dest_ip);//目的VPN IP地址
        strcpy(change_interface, Device[0].interface);//出口为eth0
        strcpy(change_ip, gateway_ip);//下一跳IP为网关
    }

    //------------------------------ 匹配接口下标并找到发送接口MAC地址 ----------------------------
    for(m = 0; m < device_index; ++m){
        if(strcmp(change_interface, Device[m].interface) == 0){
            interface_index = m;
            strcpy(change_src_mac, Device[m].mac_addr);
            break;
        }
    }
    printf("change_src_mac = %s\n", change_src_mac);
    //------------------------------------------------------------------------------------------

    //------------------------------ 检查ARP表找到下一跳MAC地址，若无，则发送ARP请求报文 -----------
    for(m = 0; m < arp_item_index; ++m){
        if(strcmp(change_ip, Arp_table[m].ip_addr) == 0){
            strcpy(change_dst_mac, Arp_table[m].mac_addr);
            flag1 = 1;
            break;
        }
    }
    printf("change_dst_mac = %s\n", change_dst_mac);
    if(flag1 == 0){//未有匹配，发送ARP请求报文并保存
        unsigned char buffer_rece_arp[BUFFER_MAX] = "\0";
        unsigned char* arp_head = buffer_rece_arp + 14;
        SendARP(sock, change_ip, interface_index);//发送ARP请求报文
        while(ARP_MATCH_REPLY(sock, buffer_rece_arp, interface_index, change_ip) != 1){;}//等待ARP回复
        //-------------------------- 匹配，添加表项 -------------------------------------------------------
        strcpy(Arp_table[arp_item_index].ip_addr, change_ip);
        sprintf(Arp_table[arp_item_index].mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",//sure
            arp_head[8], arp_head[9], arp_head[10], arp_head[11], arp_head[12], arp_head[13]);
        strcpy(change_dst_mac, Arp_table[arp_item_index].mac_addr);
        printf("change_dst_mac = %s\n", change_dst_mac);
        arp_item_index++;
        //-----------------------------------------------------------------------------------------------
    }
    //------------------------------------------------------------------------------------------

    //------------------------------ 重新构造ICMP数据报 -----------------------------------------
    unsigned char change_buffer[BUFFER_MAX] = "\0";
    memcpy(change_buffer + 42, buf + 14, BUFFER_MAX - 42);
    struct ip* ip_h_2 = (struct ip* )(change_buffer + 14);
    Eth_h* eth;
    eth = (Eth_h* )change_buffer;
    for(m = 0; m < 6; ++m){
        change_buffer[m] = strtol(change_dst_mac + 3 * m, NULL, 16);
        change_buffer[m + 6] = strtol(change_src_mac + 3 * m, NULL, 16);
    }
    eth->header.h_proto = htons((short)0x0800);
    memcpy(change_buffer + 14, buf + 14, 20);
    for(i = 0; i < device_index; ++i){
        if(Device[i].is_entrance){
            ip_h_2->ip_src.s_addr = inet_addr(Device[i].ip_addr);//Device[0].ip_addr, fixed
            break;
        }
    }
    ip_h_2->ip_dst.s_addr = inet_addr(dest_vpn_ip);
    ip_h_2->ip_ttl = ip_h->ip_ttl - 1;
    ip_h_2->ip_sum = 0;//temporarily
    ip_h_2->ip_sum = checksum((unsigned short* )ip_h_2, 20);
    memcpy(change_buffer + 34, buf + 34, 8);//ICMP头部
    Icmp_h* icmp;
    icmp = (Icmp_h* )(change_buffer + 34);
    icmp->check_sum = 0;
    icmp->check_sum = checksum( (unsigned short *)icmp, 64);//check_sum，共计算92 = 8 + 20 + 8 + 56字节
    //------------------------------------------------------------------------------------------    

    //------------------------------- 定义链路层发送结构并发送 -----------------------------------
    struct sockaddr_ll saddrll;//链路层需要用此结构
    memset(&saddrll, 0, sizeof(saddrll));
    saddrll.sll_family = PF_PACKET;
    //saddrll.sll_protocol = ETH_P_IP;//????
    saddrll.sll_ifindex = get_nic_index(*sock, change_interface);//获得本接口对应的类型
    saddrll.sll_halen = ETH_ALEN;
    for(m = 0; m < 6; ++m){//目的MAC地址
        saddrll.sll_addr[m] = strtol(change_dst_mac + 3 * m, NULL, 16);//字符串转16进制数
        //printf("%x  ", saddrll.sll_addr[m]);
    }

    if( sendto(*sock, change_buffer,126, 0, (struct sockaddr*)&saddrll, sizeof(saddrll)) < 0){//发送
            printf("now in icmp_send, sendto fail!  error = %x, decimal = %d\n", errno, errno);//发送失败，获得最后错误代码
            return;
    }
    //------------------------------------------------------------------------------------------
}

int unpack_packet(char* buffer, int* sock){
    printf("now in unpack\n");
    unsigned char buf[BUFFER_MAX] = "\0";
    memcpy(buf, buffer, BUFFER_MAX);

    int flag = 0;
    int flag1 = 0;
    int i;
    int m;
    unsigned int netmask;//子网掩码对应的整数
    unsigned char change_interface[16] = "\0";//转发接口
    unsigned char change_dst_mac[18] = "\0";//新的目的MAC
    unsigned char change_src_mac[18] = "\0";//新的源MAC
    unsigned char change_ip[16] = "\0";//下一跳IP
    int interface_index = -1;//接口下标

    struct ip* ip_h = (struct ip* )(buf + 42);//内部IP头
    char dest_ip[16] = "\0";
    strcpy(dest_ip, (char* )inet_ntoa(ip_h->ip_dst));//获得目的IP地址
    for(i = 0; i < route_item_index; ++i){
        netmask = htonl(inet_addr(route_info[i].netmask));//子网掩码
        if((htonl(inet_addr(route_info[i].destination)) & netmask) == (htonl(inet_addr(dest_ip)) & netmask)){//IP地址匹配
            strcpy(change_interface, route_info[i].interface);
            if(route_info[i].gateway[0] != '*'){
				strcpy(change_ip, route_info[i].gateway);
			}
			else{
				strcpy(change_ip, dest_ip);
			}
            flag = 1;
			break;
        }
    }

    printf("change_ip = %s, flag = %d, interface = %s\n", change_ip, flag, change_interface);

    if(flag == 1){//本网段，VPN功能
        //------------------------------ 匹配接口下标并找到发送接口MAC地址 ----------------------------
        for(m = 0; m < device_index; ++m){
            if(strcmp(change_interface, Device[m].interface) == 0){
                interface_index = m;
                strcpy(change_src_mac, Device[m].mac_addr);
                break;
            }
        }
        printf("src_mac = %s\n", change_src_mac);
        //------------------------------------------------------------------------------------------

        //------------------------------ 检查ARP表找到下一跳MAC地址，若无，则发送ARP请求报文 -----------
        for(m = 0; m < arp_item_index; ++m){
            if(strcmp(change_ip, Arp_table[m].ip_addr) == 0){
                strcpy(change_dst_mac, Arp_table[m].mac_addr);
                flag1 = 1;
                break;
            }
        }
        if(flag1 == 0){//未有匹配，发送ARP请求报文并保存
            unsigned char buffer_rece_arp[BUFFER_MAX] = "\0";
            unsigned char* arp_head = buffer_rece_arp + 14;
            SendARP(sock, change_ip, interface_index);//发送ARP请求报文
            while(ARP_MATCH_REPLY(sock, buffer_rece_arp, interface_index, change_ip) != 1){;}//等待ARP回复
            //-------------------------- 匹配，添加表项 -------------------------------------------------------
            strcpy(Arp_table[arp_item_index].ip_addr, change_ip);
            sprintf(Arp_table[arp_item_index].mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",//sure
                arp_head[8], arp_head[9], arp_head[10], arp_head[11], arp_head[12], arp_head[13]);
            strcpy(change_dst_mac, Arp_table[arp_item_index].mac_addr);
            arp_item_index++;
            //-----------------------------------------------------------------------------------------------
        }
        printf("my mac = %s\n", change_dst_mac);
        //------------------------------------------------------------------------------------------

        //------------------------------ 重新构造ICMP数据报 -----------------------------------------
        unsigned char change_buffer[BUFFER_MAX] = "\0";
        memcpy(change_buffer + 14, buf + 42, BUFFER_MAX - 42);
        struct ip* ip_h_2 = (struct ip* )(change_buffer + 14);
        Eth_h* eth;
        eth = (Eth_h* )change_buffer;
        for(m = 0; m < 6; ++m){
            change_buffer[m] = strtol(change_dst_mac + 3 * m, NULL, 16);
            change_buffer[m + 6] = strtol(change_src_mac + 3 * m, NULL, 16);
        }
        eth->header.h_proto = htons((short)0x0800);
        ip_h_2->ip_ttl -= 1;//ttl - 1
        //if(ip_h_2->ip_ttl == 0)//扔
        ip_h_2->ip_sum = 0;//temporarily
        ip_h_2->ip_sum = checksum((unsigned short* )ip_h_2, 20);
        Icmp_h* icmp;
        icmp = (Icmp_h* )(change_buffer + 34);
        icmp->check_sum = 0;
        icmp->check_sum = checksum( (unsigned short *)icmp, 64);
        //------------------------------------------------------------------------------------------    

        //------------------------------- 定义链路层发送结构并发送 -----------------------------------
        struct sockaddr_ll saddrll;//链路层需要用此结构
        memset(&saddrll, 0, sizeof(saddrll));
        saddrll.sll_family = PF_PACKET;
        //saddrll.sll_protocol = ETH_P_IP;//????
        saddrll.sll_ifindex = get_nic_index(*sock, change_interface);//获得本接口对应的类型
        saddrll.sll_halen = ETH_ALEN;
        for(m = 0; m < 6; ++m){//目的MAC地址
            saddrll.sll_addr[m] = strtol(change_dst_mac + 3 * m, NULL, 16);//字符串转16进制数
            //printf("%x  ", saddrll.sll_addr[m]);
        }

        if( sendto(*sock, change_buffer, 98, 0, (struct sockaddr*)&saddrll, sizeof(saddrll)) < 0){//发送
                printf("now in icmp_send, sendto fail!  error = %x, decimal = %d\n", errno, errno);//发送失败，获得最后错误代码
                return;
        }
        //------------------------------------------------------------------------------------------
    }
    else{
        for(i = 0; i < device_index; ++i){
            if(strcmp(Device[i].ip_addr, dest_ip) == 0){//本机IP，为ping本机，须回复
                flag = 1;
                break;
            }
        }
    }
}
