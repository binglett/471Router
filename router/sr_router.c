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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* TODO: Add constant definitions here... */
struct sr_arpentry arpCache[SR_ARPCACHE_SZ];
/* TODO: Add helper functions here... */

void ARP_sendReply(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface, struct sr_if* ifptr) {
  struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*)packet;
  struct sr_arp_hdr* arp_hdr = (struct sr_arp_hdr*)(packet + sizeof(sr_ethernet_hdr_t));
  struct in_addr replied;

  /* get MAC */

}

void ARP_makePacket(struct sr_arphdr* arp_hdr,
    unsigned short  ar_hrd,            /* format of hardware address   */
    unsigned short  ar_pro,             /* format of protocol address   */
    unsigned char   ar_hln,             /* length of hardware address   */
    unsigned char   ar_pln,             /* length of protocol address   */
    unsigned short  ar_op,             /* ARP opcode (command)         */
    unsigned char   ar_sha[ETHER_ADDR_LEN],  /* sender hardware address      */
    uint32_t        ar_sip,            /* sender IP address            */
    unsigned char   ar_tha[ETHER_ADDR_LEN],   /* target hardware address      */
    uint32_t        ar_tip ) {            /* target IP address   */
    int i = 0;
    arp_hdr->ar_hrd = arp_hrd;
    arp_hdr->ar_pro = arp_pro;
    arp_hdr->ar_hln = arp_hln;
    arp_hdr->ar_pln = arp_pln;
    arp_hdr->ar_op = arp_op;
    arp_hdr->ar_sip = sbuf; 
    arp_hdr->ar_tip = tbuf;
    for (i; i < ETHER_ADDR_LEN; i++) {
      arp_hdr->ar_sha[i] = ar_sha[i];
      arp_hdr->ar_tha[i] = ar_tha[i];
    }
}

void ICMP_sendUnreachable(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {

}

void ICMP_sendEcho(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {

}

void IP_forward(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {

}


/* Returns 1 if destination of packet matches router IP, 0 if not*/
int ARP_dstMatches(struct sr_instance* sr, uint8_t* packet, char* interface){
  /* get IP of interface that received packet*/
  struct sr_if* incoming_if = sr_get_interface(sr, interface);
  /* get destination IP */
  sr_arp_hdr_t* arp_hdr = (struct sr_arp_hdr*)(packet + sizeof(sr_ethernet_hdr_t));

  if (incoming_if->ip == arp_hdr->ar_tip) {
    return 1;
  } 
  return 0;
}
int IP_dstMatches(struct sr_instance* sr, uint8_t* packet, char* interface){
  /* get UP of interface that received packet */ 
  struct sr_if *incoming_if = sr_get_interface(sr, interface);
  /* get destination IP */
  sr_ip_hdr_t* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(sr_ethernet_hdr_t));

  if (incoming_if->ip == ip_hdr->ip_dst) {
    return 1;
  }
  return 0;
}


/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req){
  /* TODO: Fill this in */
   
}
/* Given an ARP packet, decides what to do based on 
   whether it is a request or reply */
void handle_ARP(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){
  /* Give structure to raw ARP packet */
  sr_arp_hdr_t* arp_hdr = (struct sr_arp_hdr*)(packet + sizeof(sr_ethernet_hdr_t));  
  struct in_addr requested, replied;
  struct sr_if* ifptr = sr->if_list;
  int i = 0; /* for looping thorugh waiting IP packets */

  fprintf(stdout, "My interfaces: \n");
  sr_print_if_list(sr);

  /* if ARP is request, check list of interfaces to see if have the 
     the MAC addr of request IP and send reply if we have it */
  if (ntohs(arp_hdr->ar_op) == arp_op_request) {
    requested.s_addr = arp_hdr->ar_tip;
    fprintf(stdout, "-> ARP Request: who has %s?\n", inet_ntoa(requested));
    /* Check if has it in its table */
    while (ifptr) {
      /* Has in its table, so send reply */
      if (ifptr->ip == requested.s_addr) {     
        fprintf(stdout, "HWaddr to send: %s\n", ifptr->name);
        ARP_sendReply(sr, packet, len, interface, ifptr);
        return;
      } else {
        ifptr = ifptr->next;
      }
    }

    if (!ifptr) {
      printf("-> ARP Request: we do not have %s\n", inet_ntoa(requested));
    }    
  } 

  if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
    replied.s_addr = arp_hdr->ar_sip;

    printf("-> ARP Reply: %s is at ", inet_ntoa(replied));

    /* Cache the reply */
    ARP_cacheEntry(arp_hdr);

    /* Forward waiting IP packets */
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
      if (arpCache[i].valid == 1) {
        checkWaitingPackets(sr, i);
      }
    }

  }
}

/* Given an IP packet, decides what to do based on 
   whether it is for our router or not */
void handle_IP(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){
  /* Give structure to raw IP packet*/
  struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)packet;

  if (IP_dstMatches(sr, packet, interface)) {
    if (ip_hdr->ip_p == IPPROTO_ICMP) {
      ICMP_sendEcho(sr, packet, len, interface);
    } else if (ip_hdr->ip_p == IPPROTO_TCP || ip_hdr->ip_p == IPPROTO_UDP) {
      ICMP_sendUnreachable(sr, packet, len, interface);
    }    
  } else {
    IP_forward(sr, packet, len, interface);
  }
}
/* End of helper functions... */

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
    
    /* TODO: (opt) Add initialization code here */

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
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).  
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d\n",len);

  /* TODO: Add forwarding logic here */
  /* Give structure to raw ethernet packet */
  sr_ethernet_hdr_t* eth_hdr = (struct sr_ethernet_hdr*)packet;
  print_hdrs(packet, len);
  print_hdr_eth(packet);

  if (ntohs(eth_hdr->ether_type) == ethertype_arp) {
    printf("=== sr_router::sr_handlePacket::Recieved ARP packet.\n");    
    handle_ARP(sr, packet, len, interface);
  } else if (ntohs(eth_hdr->ether_type) == ethertype_ip) {
    handle_IP(sr, packet, len, interface);
    printf("=== sr_router::sr_handlePacket::Recieved IP packet.\n");
  } else {
    /* ??? neither arp nor IP exception? */
    printf("=== sr_router::sr_handlePacket::Neither IP nor ARP!\n");
  }
  

}/* -- sr_handlepacket -- */

