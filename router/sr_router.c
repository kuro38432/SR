/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  print_hdrs(packet, len);

  /* fill in code here */
  int code = -1;
  struct sr_if *iface = sr_get_interface(sr, interface);

  /* get ethernet type */
  uint16_t ethtype = ethertype(packet);

  /* IP */
  if (ethtype == ethertype_ip) { 
    /* extract packet and headers */
    uint8_t *ip_packet = packet + size_ether;
    sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)ip_packet;
    /* check if packet is valid */
    if (valid_pkt(ip_hdr, len) == 0) {
      struct sr_if * target_iface = sr_get_interface_from_ip(sr, ip_hdr->ip_dst);
      /* IP FOR US */
      if(target_iface != NULL) {
        uint8_t ip_proto = ip_protocol(ip_packet);
        /* ICMP */
        if (ip_proto == ip_protocol_icmp) { 
          uint8_t * icmp_packet = ip_packet + size_ip;
          sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *)icmp_packet;
          /* ICMP ECHO REUEST */
          if (icmp_hdr->icmp_type == 8) { 
            code = handle_icmp_echo_request(ip_hdr, icmp_packet, iface, sr, len);
            if (code != 0) {
              printf("Error: Could not handle ICMP echo request\n");
            }
          }
          /* END - ICMP ECHO REQUEST */
        /* END - ICMP */
        /* UDP/TCP PAYLOAD */
        } else if (ip_proto == 6 || ip_proto == 17) {
          code = handle_unreachable_packet(3, ip_hdr, ip_packet, iface, sr);
          if (code != 0) {
            printf("Error: Could not handle TCP/UDP payload\n");
          }
        }
        /* END - UDP/TCP PAYLOAD */
      /* END - IP FOR US */
      /* IP NOT FOR US */  
      } else {
        /* FORWARD PACKET */
        if (ip_hdr->ip_ttl > 1) {
          code = forward_ip_packet(ip_hdr, ip_packet, iface, sr);
          if (code != 0) {
            printf("Error: Could not forward packet\n");
          }
        /* END - FORWARD PACKET */
        /* DEAD PACKET */
        } else {
          code = handle_dead_packet(ip_hdr, ip_packet, iface, sr);
          if (code != 0) {
            printf("Error: Could not handle dead packet\n");
          }
        }
        /* END - DEAD PACKET */
      }
      /* END - IP NOT FOR US */
    }
  /* END - IP */
  /* ARP */
  } else if (ethtype == ethertype_arp) {
    uint8_t * arp_packet = packet + size_ether;
    sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *)arp_packet;
    /* ARP REQUEST */
    if (ntohs(arp_hdr->ar_op) == arp_op_request) {
      code = handle_arp_request(arp_hdr, iface, sr);
      if (code != 0) {
        printf("Error: Could not handle ARP request\n");
      }
    /* END - ARP REQUEST */
    /* ARP REPLY */
    } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
      code = handle_arp_reply(arp_hdr, sr);
      if (code != 0) {
        printf("Error: Could not handle ARP reply\n");
      }
    }
    /* END - ARP REPLY */
  }
  /* END - ARP */
}/* end sr_ForwardPacket */


/* validates packet */
int valid_pkt(sr_ip_hdr_t * ip_hdr, unsigned int len) {
  uint16_t orig_sum = 0;
  uint16_t new_sum = 0;

  orig_sum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  new_sum = cksum((const void *)ip_hdr, size_ip);
  ip_hdr->ip_sum = orig_sum;

  if (orig_sum != new_sum) {
    printf("IP: bad checksum, dropping packet\n");
    return -1;
  }

  int packet_len = len - size_ether;
  if (packet_len < size_ip) {
    printf("IP: does not match minimum length, dropping packet\n");
    return -1;
  }

  return 0;
}

/* gets interface from ip */
struct sr_if* sr_get_interface_from_ip(struct sr_instance* sr, uint32_t ip_addr) {
  struct sr_if* if_walker = 0;

  if_walker = sr->if_list;

  while (if_walker) {
    if (ip_addr == if_walker->ip) { 
      return if_walker;
    }
    if_walker = if_walker->next;
  }
  return NULL;
}


/* HANDLERS -------------------------------------- */

int handle_icmp_echo_request(sr_ip_hdr_t * ip_hdr, uint8_t * icmp_packet, struct sr_if * iface, 
                             struct sr_instance * sr, unsigned int len) {

  /* malloc */
  uint8_t * packet = (uint8_t *)malloc(len - size_ether);

  /* copy icmp data */
  int icmp_len = len - size_ether - size_ip;
  memcpy(packet + size_ip, icmp_packet, icmp_len);

  /* get structs */
  sr_ip_hdr_t * packet_ip = (sr_ip_hdr_t *) packet;
  sr_icmp_hdr_t * packet_icmp = (sr_icmp_hdr_t *)(packet + size_ip);

  /* populate */
  int code = populate_icmp(packet_icmp, 0, 0, icmp_len);
  if (code != 0) {
    printf("Error: Could not populate icmp header for icmp echo reply\n");
    free(packet);
    return -1;
  }

  code = populate_ip(packet_ip, icmp_len + size_ip, ip_protocol_icmp, ip_hdr->ip_dst, ip_hdr->ip_src);
  if (code != 0) {
    printf("Error: Could not populate ip header for icmp echo reply\n");
    free(packet);
    return -1;
  }

  code = forward_ip_packet(packet_ip, packet, iface, sr);
  if (code != 0) {
    printf("Error: Could not forward ip packet for icmp echo reply\n");
    return -1;
  }

  return 0;
}


int handle_unreachable_packet(int code, sr_ip_hdr_t * ip_hdr, uint8_t * ip_packet, struct sr_if * iface, 
                              struct sr_instance * sr) {
  /* malloc */
  uint8_t * packet = (uint8_t *)malloc(size_ip + size_icmp_t3);

  /* get structs */
  sr_ip_hdr_t * packet_ip = (sr_ip_hdr_t *) packet;
  sr_icmp_t3_hdr_t * packet_icmp = (sr_icmp_t3_hdr_t *)(packet + size_ip);

  /* populate */
  int errcode = populate_icmp_t3(packet_icmp, code, ip_packet);
  if (errcode != 0) {
    printf("Error: Could not populate icmp header for icmp unreachable\n");
    free(packet);
    return -1;
  }

  errcode = populate_ip(packet_ip, size_icmp_t3 + size_ip, ip_protocol_icmp, ip_hdr->ip_dst, ip_hdr->ip_src);
  if (errcode != 0) {
    printf("Error: Could not populate ip header for icmp unreachable\n");
    free(packet);
    return -1;
  }

  errcode = forward_ip_packet(packet_ip, packet, iface, sr);
  if (errcode != 0) {
    printf("Error: Could not forward ip packet for icmp unreachable\n");
    return -1;
  }

  return 0;
}


int handle_dead_packet(sr_ip_hdr_t * ip_hdr, uint8_t * ip_packet, struct sr_if * iface, 
                       struct sr_instance * sr) {
  /* malloc */
  uint8_t * packet = (uint8_t *)malloc(size_ip + size_icmp + ICMP_DATA_SIZE);

  /* copy icmp data */
  memcpy(packet + size_ip + size_icmp, ip_packet, ICMP_DATA_SIZE);

  /* get structs */
  sr_ip_hdr_t * packet_ip = (sr_ip_hdr_t *) packet;
  sr_icmp_hdr_t * packet_icmp = (sr_icmp_hdr_t *)(packet + size_ip);

  /* populate */
  int code = populate_icmp(packet_icmp, 11, 0, size_icmp + ICMP_DATA_SIZE);
  if (code != 0) {
    printf("Error: Could not populate icmp header for icmp time exceeded\n");
    free(packet);
    return -1;
  }

  code = populate_ip(packet_ip, size_icmp + ICMP_DATA_SIZE + size_ip, 
                     ip_protocol_icmp, ip_hdr->ip_dst, ip_hdr->ip_src);
  if (code != 0) {
    printf("Error: Could not populate ip header for icmp time exceeded\n");
    free(packet);
    return -1;
  }

  code = forward_ip_packet(packet_ip, packet, iface, sr);
  if (code != 0) {
    printf("Error: Could not forward ip packet for icmp time exceeded\n");
    return -1;
  }

  return 0;
}


int handle_arp_request(sr_arp_hdr_t * arp_hdr, struct sr_if * iface, struct sr_instance * sr) {
  /* malloc */
  uint8_t * packet = (uint8_t *)malloc(size_ether + size_arp);

  /* get target iface */
  struct sr_if * target_iface = sr_get_interface_from_ip(sr, arp_hdr->ar_tip);
  if (target_iface == NULL) {
    printf("Error: Could not find interface with requested ip address\n");
    return -1;
  }

  /* get structs */
  sr_ethernet_hdr_t * packet_ether = (sr_ethernet_hdr_t *) packet;
  sr_arp_hdr_t * packet_arp = (sr_arp_hdr_t *)(packet + size_ether);

  int code = populate_arp_reply(packet_arp, target_iface->addr, arp_hdr->ar_sha, 
                                target_iface->ip, arp_hdr->ar_sip);
  if (code != 0) {
    printf("Error: Could not populate arp header for arp reply\n");
    free(packet);
    return -1;
  }

  code = populate_ethernet(packet_ether, arp_hdr->ar_sha, iface->addr, ethertype_arp);
  if (code != 0) {
    printf("Error: Could not populate ethernet header for arp reply\n");
    free(packet);
    return -1;
  }

  /* send packet */
  code = sr_send_packet(sr, packet, size_ether + size_arp, iface->name);
  free(packet);
  if (code != 0) {
    printf("Error: Could not send arp reply packet\n");
    return -1;
  }

  return 0;
}


int handle_arp_reply(sr_arp_hdr_t * arp_hdr, struct sr_instance * sr) {
  int code = -1;
  /* get arp request */
  struct sr_arpcache *cache = &(sr->cache);
  struct sr_arpreq * req = sr_arpcache_insert(cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

  /* send all packets on request queue out */
  if (req != NULL) {
    struct sr_packet * walker = req->packets;
    while (walker != NULL) {
      sr_ethernet_hdr_t * packet = (sr_ethernet_hdr_t *)(walker->buf);
      memcpy(packet->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      code = sr_send_packet(sr, walker->buf, walker->len, walker->iface);
      if (code != 0) {
        /* CAREFUL: possible memory not being freed */
        printf("Error: Could not send packet out from request queue\n");
        return -1;
      }
      walker = walker->next;
    }
    sr_arpreq_destroy(cache, req);
  }
  return 0;
}

int forward_ip_packet(sr_ip_hdr_t * ip_hdr, uint8_t * ip_packet, struct sr_if * iface, 
                      struct sr_instance * sr) {
  int code = -1;

  /* search routing table */
  struct sr_rt * rt = lookup_rt(ip_hdr->ip_dst, sr);
  if (rt == NULL) {
    code = handle_unreachable_packet(0, ip_hdr, ip_packet, iface, sr);
    if (code != 0) {
      printf("Error: Could not handle destination net unreachable packet\n");
      return -1;
    }
    return 0;
  }

  /* decrease TTL and recompute checksum */
  ip_hdr->ip_ttl -= 1;
  ip_hdr->ip_sum = 0;
  int sum = cksum((const void *)ip_hdr, size_ip);
  ip_hdr->ip_sum = sum;

  /* pack ethernet packet */
  int packet_len = size_ether + ip_hdr->ip_len;
  uint8_t * packet = (uint8_t *)malloc(packet_len);
  sr_ethernet_hdr_t * packet_ether = (sr_ethernet_hdr_t *) packet;
  /* copy over ip packet */
  memcpy(packet + size_ether, ip_packet, ip_hdr->ip_len);
  /* fill in packet, leave dhost blank */
  memcpy(packet_ether->ether_shost, iface->addr, ETHER_ADDR_LEN);
  packet_ether->ether_type = ethertype_ip;

  /* search arp cache */
  uint32_t ip = rt->gw.s_addr;
  struct sr_arpcache * cache = &(sr->cache);
  struct sr_arpentry * arp_entry = sr_arpcache_lookup(cache, ip);

  /* if found, just send */
  if (arp_entry != NULL) {
    /* fill in dhost */
    memcpy(packet_ether->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
    /* send */
    code = sr_send_packet(sr, packet, packet_len, iface->name);
    free(packet);
    free(arp_entry);
    if (code != 0) {
      printf("Error: Could not send packet out when forwarding\n");
      return -1;
    }
    return 0;
  }

  /* not found, so queue req */
  struct sr_arpreq * req = sr_arpcache_queuereq(cache, ip, packet, packet_len, iface->name);
  if (req == NULL) {
    printf("Error: Could not queue arp request\n");
    return -1;
  }
  free(req);
  return 0;
}

int populate_icmp(sr_icmp_hdr_t * icmp_hdr, int type, int code, int len) {
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->icmp_sum = 0;
  int sum = cksum(icmp_hdr, len);
  icmp_hdr->icmp_sum = sum;
  return 0;
}

int populate_ip(sr_ip_hdr_t * ip_hdr, int ip_len, int ip_protocol, 
                uint32_t ip_src, uint32_t ip_dst) {
  ip_hdr->ip_len = ip_len;
  /* TTL set to 30 for the moment */
  ip_hdr->ip_ttl = 30;
  ip_hdr->ip_p = ip_protocol;
  ip_hdr->ip_src = ip_src;
  ip_hdr->ip_dst = ip_dst;
  ip_hdr->ip_sum = 0;
  int sum = cksum(ip_hdr, size_ip);
  ip_hdr->ip_sum = sum;
  return 0;
}

int populate_icmp_t3(sr_icmp_t3_hdr_t * icmp_hdr, int code, uint8_t * ip_packet) {
  icmp_hdr->icmp_type = 3;
  icmp_hdr->icmp_code = code;
  icmp_hdr->icmp_sum = 0;
  memcpy(icmp_hdr->data, ip_packet, ICMP_DATA_SIZE);
  int sum = cksum(icmp_hdr, size_icmp_t3);
  icmp_hdr->icmp_sum = sum;
  return 0;
}

int populate_arp_reply(sr_arp_hdr_t * arp_hdr, unsigned char * sha, 
                       unsigned char * tha, uint32_t sip, uint32_t tip) {
  arp_hdr->ar_hrd = arp_hrd_ethernet;
  arp_hdr->ar_pro = ethertype_ip;
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pln = 4;
  arp_hdr->ar_sip = sip;
  arp_hdr->ar_tip = tip;
  memcpy(arp_hdr->ar_sha, sha, ETHER_ADDR_LEN);
  memcpy(arp_hdr->ar_tha, tha, ETHER_ADDR_LEN);
  return 0;
}

int populate_ethernet(sr_ethernet_hdr_t * ether_hdr, unsigned char * ether_dhost, 
                      unsigned char * ether_shost, int ether_type) {
  ether_hdr->ether_type = ether_type;
  memcpy(ether_hdr->ether_dhost, ether_dhost, ETHER_ADDR_LEN);
  memcpy(ether_hdr->ether_shost, ether_shost, ETHER_ADDR_LEN);
  return 0;
}

struct sr_rt * lookup_rt(uint32_t ip, struct sr_instance * sr) {
  struct sr_rt * rt_walker = sr->routing_table;
  struct sr_rt * rt = NULL;
  uint32_t max_mask = 0;

  uint32_t mask = 0;
  uint32_t dest = 0;
  uint32_t masked_ip = 0;
  uint32_t masked_dest = 0;
  while (rt_walker != NULL) {
    mask = rt_walker->mask.s_addr;
    dest = rt_walker->dest.s_addr;
    masked_ip = ip & mask;
    masked_dest = dest & mask;
    if (masked_ip == masked_dest && mask > max_mask) {
      rt = rt_walker;
      max_mask = mask;
    }
    rt_walker = rt_walker->next;
  }
  return rt;
}

int populate_arp_request(sr_arp_hdr_t * arp_hdr, unsigned char * sha,
                         uint32_t sip, uint32_t tip) {
  arp_hdr->ar_hrd = arp_hrd_ethernet;
  arp_hdr->ar_pro = ethertype_ip;
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pln = 4;
  arp_hdr->ar_sip = sip;
  arp_hdr->ar_tip = tip;
  memcpy(arp_hdr->ar_sha, sha, ETHER_ADDR_LEN);
  memset(arp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
  return 0;
}

int populate_arp_request_ethernet(sr_ethernet_hdr_t * ether_hdr, unsigned char * ether_shost) {
  ether_hdr->ether_type = ethertype_arp;
  memcpy(ether_hdr->ether_shost, ether_shost, ETHER_ADDR_LEN);
  memset(ether_hdr->ether_dhost, -1, ETHER_ADDR_LEN);
  return 0;
}