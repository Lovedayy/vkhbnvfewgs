#pragma once
#include <WinSock2.h>
/* 网络层协议类型 */
#define IP       0x0800
#define ARP      0x0806

/* 传输层类型 */
#define ICMP       0x01
#define TCP        0x06
#define UDP        0x11
#define IPv6       0x29

#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    4321

//mac帧类型定义
#define MAC_IP  0x0800
#define MAC_ARP 0x0806
#define MAC_IP6 0x86dd

//ip地址
typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

//Mac帧头 14字节
typedef struct ethhdr
{
#if defined(LITTLE_ENDIAN)
    u_char dest[6];
    u_char src[6];
#elif defined(BIG_ENDIAN)
    u_char src[6];
    u_char dest[6];
#endif
    u_short type;
};

//ARP头
typedef struct arp_hdr
{
#ifdef LITTLE_ENDIAN
    u_short ar_hrd : 8;
    u_short ar_unused : 8;
#elif defined(BIG_ENDIAN)
    u_short ar_unused : 8;
    u_short ar_hrd : 8;
#endif
    //u_short ar_hrd;						//硬件类型
    u_short ar_pro;						//协议类型
    u_char ar_hln;						//硬件地址长度
    u_char ar_pln;						//协议地址长度
    u_short ar_op;						//操作码，1为请求 2为回复
    u_char ar_srcmac[6];			    //发送方MAC
    ip_address  ar_saddr;			    //发送方IP
    u_char ar_destmac[6];			    //接收方MAC
    ip_address  ar_daddr;   			//接收方IP
}arp_hdr;

//IPv4 首部 
typedef struct ip_header
{
#if defined(LITTLE_ENDIAN)
    u_char ip_ihl : 4;
    u_char ip_version : 4;
#elif defined(BIG_ENDIAN)
    u_char ip_version : 4;
    u_char  ip_ihl : 4;
#endif
    //u_char  ip_ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
    u_char  ip_tos;            // 服务类型(Type of service)
    u_short ip_tlen;           // 总长(Total length)
    u_short ip_identification; // 标识(Identification)
    u_short ip_flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    u_char  ip_ttl;            // 生存时间(Time to live)
    u_char  ip_type;           // 协议(Protocol)
    u_short ip_crc;            // 首部校验和(Header checksum)
    ip_address  ip_saddr;      // 源地址(Source address)
    ip_address  ip_daddr;      // 目的地址(Destination address)
    u_int   ip_op_pad;         // 选项与填充(Option + Padding)
}ip_header;

//TCP头部
typedef struct tcp_hdr
{
    u_short tcp_sport;			//源端口号
    u_short tcp_dport;			//目的端口号
    u_long tcp_seq;				//序列号
    u_long tcp_ack;				//确认号
#if defined(LITTLE_ENDIAN)
    u_short res1 : 4,
        doff : 4,
        fin : 1,
        syn : 1,
        rst : 1,
        psh : 1,
        ack : 1,
        urg : 1,
        ece : 1,
        cwr : 1;
#elif defined(BIG_ENDIAN)
    u_short doff : 4,
        res1 : 4,
        cwr : 1,
        ece : 1,
        urg : 1,
        ack : 1,
        psh : 1,
        rst : 1,
        syn : 1,
        fin : 1;
#endif
    u_short th_win;				//窗口大小
    u_short th_sum;				//校验和
    u_short th_urp;				//紧急数据指针
}tcp_hdr;

//UDP头部
typedef struct udp_hdr
{
    u_short udp_sport;			//源端口号
    u_short udp_dport;			//目的端口号
    u_short udp_ulen;			//UDP数据报长度
    u_short udp_sum;				//校验和
}udp_hdr;

//定义ICMP
typedef struct icmp_hdr
{
    u_char icmp_type;			//8位 类型
    u_char icmp_code;			//8位 代码
    u_char icmp_seq;				//序列号 8位
    u_char icmp_chksum;			//8位校验和
}icmp_hdr;

//HTTP首部
typedef struct http_hdr {
    char http_method[16];        // 请求方法，如 GET、POST 等
    char http_uri[128];          // 请求URI
    char http_version[16];       // HTTP协议版本
    char http_header[1024];      // 头部信息
} http_hdr;

//DNS首部
typedef struct dns_hdr {
    u_short dns_id;             // 标识号
    u_short dns_flags;          // 标志
    u_short dns_qcount;         // 问题数
    u_short dns_ancount;        // 回答数
    u_short dns_nscount;        // 授权回答数
    u_short dns_arcount;        // 额外回答数
} dns_hdr;
