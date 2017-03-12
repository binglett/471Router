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

/* TODO: Add helper functions here... */


void ICMP_sendUnreachable(struct sr_instance* sr,
          uint8_t* packet,
          unsigned int len,
          char* interface) {

}

void ICMP_sendEcho(struct sr_instance* sr,
          uint8_t* packet,
          unsigned int len,
          char* interface) {

}

void IP_forward(struct sr_instance* sr,
          uint8_t* packet,
          unsigned int len,
          char* interface) {

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
  sr_arp_hdr_t* arp_hdr = (struct sr_arp_hdr*)packet;
  struct in_addr requested, replied;

  /* if ARP is request, check list of interfaces to see if have the 
     the MAC addr of request IP and send reply if we have it */
  if (ntohs(arp_hdr->ar_op) == arp_op_request) {
    requested.s_addr = arp_hdr->ar_tip;
    fprintf(stdout, "-> ARP Request: who has %s?\n", inet_ntoa(requested));
  } 

  if(ntohs(arp_hdr->ar_op) == arp_op_reply) {
    replied.s_addr = arp_hdr->ar_sip;
    printf("-> ARP Reply: %s is at ", inet_ntoa(replied));
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

  if (ntohs(eth_hdr->ether_type) == ethertype_arp) {
    handle_ARP(sr, packet, len, interface);
  } else if (ntohs(eth_hdr->ether_type) == ethertype_ip) {
    handle_IP(sr, packet, len, interface);
  } else {
    /* ??? neither arp nor IP exception? */
  }
  

}/* -- sr_handlepacket -- */

