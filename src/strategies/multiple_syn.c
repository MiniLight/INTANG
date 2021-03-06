/*
 * Strategy implementation
 * .setup function:     Set up triggers, which listen to specific 
 *                      incoming or outgoing packets, and bind 
 *                      triggers to these events. 
 * .teardown function:  Unbind triggers.
 *
 */

#include "multiple_syn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "globals.h"
#include "socket.h"
#include "protocol.h"
#include "logging.h"
#include "helper.h"
#include "discrepancy.h"


/*
static void send_fake_SYN(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num, unsigned char ttl)
{
    char pkt[MAX_PACKET_SIZE];

    struct send_tcp_vars vars;
    memset(&vars, 0, sizeof vars);
    strncpy(vars.src_ip, src_ip, 16);
    strncpy(vars.dst_ip, dst_ip, 16);
    vars.src_port = src_port;
    vars.dst_port = dst_port;
    vars.flags = TCP_SYN;// | TCP_RST;// | TCP_FIN;
    vars.seq_num = seq_num;
    vars.ack_num = 0;
    //vars.wrong_tcp_checksum = 1;
    vars.ttl = ttl;

    // mss
    u_char bytes[4] = {0x02, 0x04, 0x05, 0xb4};
    memcpy(vars.tcp_opt, bytes, 4);
    vars.tcp_opt_len = 4;

    //dump_send_tcp_vars(&vars);

    send_tcp(&vars);
}

static void send_fake_FIN(
        const char *src_ip, unsigned short src_port,  
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num, unsigned int ack_num,
        unsigned char ttl)
{   
    struct send_tcp_vars vars;
    //log_debug("size of vars: %ld", sizeof vars);
    memset(&vars, 0, sizeof vars);
    strncpy(vars.src_ip, src_ip, 16);
    strncpy(vars.dst_ip, dst_ip, 16);
    vars.src_port = src_port;
    vars.dst_port = dst_port;
    vars.flags = TCP_FIN;
    vars.seq_num = seq_num;
    vars.ack_num = ack_num;
    vars.ttl = ttl;

    u_char bytes[20] = {0x13,0x12,0xf9,0x89,0x5c,0xdd,0xa6,0x15,0x12,0x83,0x3e,0x93,0x11,0x22,0x33,0x44,0x55,0x66,0x01,0x01};
    memcpy(vars.tcp_opt, bytes, 20);
    vars.tcp_opt_len = 20;
    
    //dump_send_tcp_vars(&vars);
    
    send_tcp(&vars);
}    

static void send_RST_super(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num, unsigned char ttl)
{
    char pkt[MAX_PACKET_SIZE];

    struct send_tcp_vars vars;
    //log_debug("size of vars: %ld", sizeof vars);
    memset(&vars, 0, sizeof vars);
    strncpy(vars.src_ip, src_ip, 16);
    strncpy(vars.dst_ip, dst_ip, 16);
    vars.src_port = src_port;
    vars.dst_port = dst_port;
    vars.flags = TCP_RST;// | TCP_ACK;
    vars.seq_num = seq_num;
    vars.ack_num = 0;
    //vars.wrong_tcp_checksum = 1;
    vars.ttl = ttl;

    u_char bytes[20] = {0x13,0x12,0xf9,0x89,0x5c,0xdd,0xa6,0x15,0x12,0x83,0x3e,0x93,0x11,0x22,0x33,0x44,0x55,0x66,0x01,0x01};
    memcpy(vars.tcp_opt, bytes, 20);
    vars.tcp_opt_len = 20;

    //dump_send_tcp_vars(&vars);

    send_tcp(&vars);
}
*/


int x11_setup()
{
    char cmd[256];
    sprintf(cmd, "iptables -A INPUT -p tcp -m multiport --sport 53,80 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
    system(cmd);

    return 0;
}

int x11_teardown()
{
    char cmd[256];
    sprintf(cmd, "iptables -D INPUT -p tcp -m multiport --sport 53,80 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
    system(cmd);

    return 0;
}

int x11_process_syn(struct mypacket *packet)
{
    unsigned int sflags = INS_DISC_SMALL_TTL;
    if (1) {
        sflags |= INS_DISC_BAD_TCP_CHECKSUM;
    }
    send_fake_SYN(packet, sflags);
    usleep(20000);
    send_fake_SYN(packet, sflags);
    usleep(20000);

    return 1;
}

int x11_process_synack(struct mypacket *packet)
{
    return 0;
}

int x11_process_request(struct mypacket *packet)
{
    unsigned int sflags, dflags;
    sflags = INS_DISC_SMALL_TTL;
    dflags = INS_DISC_BAD_ACK_NUM | INS_DISC_MD5 | INS_DISC_OLD_TIMESTAMP;
    if (1) {
        dflags |= INS_DISC_SMALL_TTL;
    }
    if (1) {
        sflags |= INS_DISC_BAD_TCP_CHECKSUM;
        dflags |= INS_DISC_BAD_TCP_CHECKSUM;
    }
    send_fake_SYN(packet, sflags);
    usleep(20000);

//    send_RST_super(sip, sport, dip, dport, packet->ip4.tcphdr->th_seq, ttl);
//    usleep(20000);
//    send_RST_super(sip, sport, dip, dport, packet->ip4.tcphdr->th_seq, ttl);
//    usleep(20000);
//    send_RST_super(sip, sport, dip, dport, packet->ip4.tcphdr->th_seq, ttl);
//    usleep(20000);
    //send_fake_FIN(sip, sport, dip, dport, packet->ip4.tcphdr->th_seq, 0, ttl); 
    //send_fake_FIN(sip, sport, dip, dport, packet->ip4.tcphdr->th_seq, 0, ttl); 
    //send_fake_FIN(sip, sport, dip, dport, packet->ip4.tcphdr->th_seq, 0, ttl); 

    send_desync_data(packet, dflags);
    usleep(20000);
    send_desync_data(packet, dflags);
    usleep(20000);
    send_desync_data(packet, dflags);

    //usleep(100000);

    return 1;
}


