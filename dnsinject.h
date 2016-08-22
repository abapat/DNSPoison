//Amit Bapat
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <fcntl.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <signal.h>
#include <syslog.h>
#include <ctype.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef __linux__
#include <netinet/ether.h>
#endif 

/* To get defns of NI_MAXSERV and NI_MAXHOST */
#define _GNU_SOURCE     
/* ethernet headers are 14 bytes */
#define SIZE_ETHERNET_HEADER 14
/* UDP headers are 8 bytes */
#define SIZE_UDP_HEADER 8
/* UDP headers are 8 bytes */
#define SIZE_ICMP_HEADER 8

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
        #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

#define getBit(x, n) ((x >> (n-1)) & 1) //right shifts x until desired bit is lsb and then masks with & 1

struct dns_header{
        char id[2];
        char flags[2];
        char qdcount[2];
        char ancount[2];
        char nscount[2];
        char arcount[2];
};

#define DNSA_LEN 16 //2 for ptr, 2 for type, 2 for class, 4 for TTL, 2 for rdata len, 4 for rdata (IP)
/*
struct dns_query {
        char* qname;
        char qtype[2];
        char qclass[2];
};

struct dns_answer {
        char* name;
        char type[2];
        char qclass[2];
        char ttl[4];
        char rdlength[2];
        char* rdata;
};*/