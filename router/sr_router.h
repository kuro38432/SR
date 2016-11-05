/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

#define SIZE_ETHER

/* forward declare */
struct sr_if;
struct sr_rt;

enum {
  size_ether = sizeof(sr_ethernet_hdr_t),
  size_ip = sizeof(sr_ip_hdr_t),
  size_icmp = sizeof(sr_icmp_hdr_t),
  size_icmp_t3 = sizeof(sr_icmp_t3_hdr_t),
  size_arp = sizeof(sr_arp_hdr_t),
};

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
int valid_pkt(sr_ip_hdr_t * ip_hdr, unsigned int len);
struct sr_if* sr_get_interface_from_ip(struct sr_instance* sr, uint32_t ip_addr);
int handle_icmp_echo_request(sr_ip_hdr_t * ip_hdr, uint8_t * ip_packet, struct sr_if * iface, struct sr_instance * sr);
int handle_unreachable_packet(int code, sr_ip_hdr_t * ip_hdr, uint8_t * ip_packet, struct sr_if * iface, struct sr_instance * sr);
int forward_ip_packet(sr_ip_hdr_t * ip_hdr, uint8_t * ip_packet, struct sr_if * iface, struct sr_instance * sr);
int handle_dead_packet(sr_ip_hdr_t * ip_hdr, uint8_t * ip_packet, struct sr_if * iface, struct sr_instance * sr);
int handle_arp_request(sr_arp_hdr_t * arp_hdr, struct sr_if * iface, struct sr_instance * sr);
int handle_arp_reply(sr_arp_hdr_t * arp_hdr, struct sr_instance * sr);

int populate_icmp(sr_icmp_hdr_t * icmp_hdr, int type, int code, int len);
int populate_ip(sr_ip_hdr_t * ip_hdr, int ip_len, int ip_protocol, uint32_t ip_src, uint32_t ip_dst, int ttl);
int populate_icmp_t3(sr_icmp_t3_hdr_t * icmp_hdr, int code, uint8_t * ip_packet);
int populate_arp_reply(sr_arp_hdr_t * arp_hdr, unsigned char * sha, unsigned char * tha, uint32_t sip, uint32_t tip);
int populate_ethernet(sr_ethernet_hdr_t * ether_hdr, 
                      unsigned char * ether_dhost, unsigned char * ether_shost, int ether_type);
int populate_arp_request(sr_arp_hdr_t * arp_hdr, unsigned char * sha, uint32_t sip, uint32_t tip);
int populate_arp_request_ethernet(sr_ethernet_hdr_t * ether_hdr, unsigned char * ether_shost);
struct sr_rt * lookup_rt(uint32_t ip, struct sr_instance * sr);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
