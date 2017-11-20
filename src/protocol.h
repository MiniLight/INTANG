
#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/types.h>

#define MAX_QNAME_LEN 64

#define MAX_REQLINE_LEN 1000

/*
 * UDP/TCP pseudo header
 * for cksum computing
 */
struct pseudohdr
{
	u_int32_t saddr;
	u_int32_t daddr;
	u_int8_t  zero;
	u_int8_t  protocol;
	u_int16_t length;
};

/*
 * DNS header
 */

struct mydnsquery
{
    char qname[100];
    u_int16_t qtype;
    u_int16_t qclass;
};

struct mydnshdr
{
    u_int16_t txn_id;
    u_int16_t flags;
    u_int16_t questions;
    u_int16_t answer_rrs;
    u_int16_t authority_rrs;
    u_int16_t addtional_rrs;
};

struct fourtuple
{
    u_int32_t saddr;
    u_int32_t daddr;
    u_int16_t sport;
    u_int16_t dport;
};

struct mypacket
{
    unsigned char *data;
    unsigned int len;
    union {
        struct {
            struct iphdr *iphdr;  // layer 3 IP header
            union {
                struct tcphdr *tcphdr;    // layer 4 TCP header
                struct udphdr *udphdr;    // layer 4 UDP header
            };
            unsigned char *payload; // layer 4 payload
            unsigned int payload_len;
        } ip4;

        struct {
            struct ip6hdr *ip6hdr;  // layer 3 IP header
            union {
                struct tcphdr *tcphdr;    // layer 4 TCP header
                struct udphdr *udphdr;    // layer 4 UDP header
            };
            unsigned char *payload; // layer 4 payload
            unsigned int payload_len;
        } ip6;
    };
};

struct tcpinfo
{
    u_int32_t saddr;
    u_int32_t daddr;
    u_int16_t sport;
    u_int16_t dport;
    u_int8_t flags;
    u_int32_t seq;
    u_int32_t ack;
    u_int8_t ttl;
    u_int16_t win;
    u_int16_t fragoff;
};


static inline struct iphdr* ip_hdr(unsigned char *pkt_data)
{
    return (struct iphdr*)pkt_data;
}

static inline struct tcphdr* tcp_hdr(unsigned char *pkt_data)
{
    return (struct tcphdr*)(pkt_data+ip_hdr(pkt_data)->ihl*4);
}

static inline unsigned char* tcp_payload(unsigned char *pkt_data)
{
    return pkt_data+ip_hdr(pkt_data)->ihl*4+tcp_hdr(pkt_data)->th_off*4;
}

static inline unsigned char* udp_payload(unsigned char *pkt_data)
{
    return pkt_data+ip_hdr(pkt_data)->ihl*4+8;
}

static inline struct udphdr* udp_hdr(unsigned char *pkt_data)
{
    return (struct udphdr*)(pkt_data+((struct iphdr*)pkt_data)->ihl*4);
}


#endif

