#pragma once
#include <WinSock2.h>
/* �����Э������ */
#define IP       0x0800
#define ARP      0x0806

/* ��������� */
#define ICMP       0x01
#define TCP        0x06
#define UDP        0x11
#define IPv6       0x29

#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    4321

//mac֡���Ͷ���
#define MAC_IP  0x0800
#define MAC_ARP 0x0806
#define MAC_IP6 0x86dd

//ip��ַ
typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

//Mac֡ͷ 14�ֽ�
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

//ARPͷ
typedef struct arp_hdr
{
#ifdef LITTLE_ENDIAN
    u_short ar_hrd : 8;
    u_short ar_unused : 8;
#elif defined(BIG_ENDIAN)
    u_short ar_unused : 8;
    u_short ar_hrd : 8;
#endif
    //u_short ar_hrd;						//Ӳ������
    u_short ar_pro;						//Э������
    u_char ar_hln;						//Ӳ����ַ����
    u_char ar_pln;						//Э���ַ����
    u_short ar_op;						//�����룬1Ϊ���� 2Ϊ�ظ�
    u_char ar_srcmac[6];			    //���ͷ�MAC
    ip_address  ar_saddr;			    //���ͷ�IP
    u_char ar_destmac[6];			    //���շ�MAC
    ip_address  ar_daddr;   			//���շ�IP
}arp_hdr;

//IPv4 �ײ� 
typedef struct ip_header
{
#if defined(LITTLE_ENDIAN)
    u_char ip_ihl : 4;
    u_char ip_version : 4;
#elif defined(BIG_ENDIAN)
    u_char ip_version : 4;
    u_char  ip_ihl : 4;
#endif
    //u_char  ip_ver_ihl;        // �汾 (4 bits) + �ײ����� (4 bits)
    u_char  ip_tos;            // ��������(Type of service)
    u_short ip_tlen;           // �ܳ�(Total length)
    u_short ip_identification; // ��ʶ(Identification)
    u_short ip_flags_fo;       // ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)
    u_char  ip_ttl;            // ����ʱ��(Time to live)
    u_char  ip_type;           // Э��(Protocol)
    u_short ip_crc;            // �ײ�У���(Header checksum)
    ip_address  ip_saddr;      // Դ��ַ(Source address)
    ip_address  ip_daddr;      // Ŀ�ĵ�ַ(Destination address)
    u_int   ip_op_pad;         // ѡ�������(Option + Padding)
}ip_header;

//TCPͷ��
typedef struct tcp_hdr
{
    u_short tcp_sport;			//Դ�˿ں�
    u_short tcp_dport;			//Ŀ�Ķ˿ں�
    u_long tcp_seq;				//���к�
    u_long tcp_ack;				//ȷ�Ϻ�
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
    u_short th_win;				//���ڴ�С
    u_short th_sum;				//У���
    u_short th_urp;				//��������ָ��
}tcp_hdr;

//UDPͷ��
typedef struct udp_hdr
{
    u_short udp_sport;			//Դ�˿ں�
    u_short udp_dport;			//Ŀ�Ķ˿ں�
    u_short udp_ulen;			//UDP���ݱ�����
    u_short udp_sum;				//У���
}udp_hdr;

//����ICMP
typedef struct icmp_hdr
{
    u_char icmp_type;			//8λ ����
    u_char icmp_code;			//8λ ����
    u_char icmp_seq;				//���к� 8λ
    u_char icmp_chksum;			//8λУ���
}icmp_hdr;

//HTTP�ײ�
typedef struct http_hdr {
    char http_method[16];        // ���󷽷����� GET��POST ��
    char http_uri[128];          // ����URI
    char http_version[16];       // HTTPЭ��汾
    char http_header[1024];      // ͷ����Ϣ
} http_hdr;

//DNS�ײ�
typedef struct dns_hdr {
    u_short dns_id;             // ��ʶ��
    u_short dns_flags;          // ��־
    u_short dns_qcount;         // ������
    u_short dns_ancount;        // �ش���
    u_short dns_nscount;        // ��Ȩ�ش���
    u_short dns_arcount;        // ����ش���
} dns_hdr;
