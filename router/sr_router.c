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

/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req){
  /* TODO: Fill this in */
  
}

/* Returns 1 if destination is this router, 0 if not*/
int dstMatches(struct sr_instance* sr, uint8_t* packet, char* interface){

}

/* Given an IP packet, decides what to do based on 
   whether it is for our router or not:
   - for this router
   - for another router */
void handle_ip(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){
  /* Give structure to raw IP packet*/
  struct sr_ip_hdr* ip_hdr = (sr_ip_hdr*)packet;

  if (dstMatches) {
    if (ip_hdr->ip_p == IPPROTO_ICMP) {
      /* handle ICMP*/
    } else if (ip_hdr->ip_p == IPPROTO_TCP || ip_hdr->ip_p == IPPROTO_UDP) {
      /* send ICMP unreachable*/
    }    
  } else {
    /* handle IP forwarding*/
  }



}

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
  sr_ethernet_hrd_t* eth_hdr = (sr_ethernet_hrd_t*)packet;

  if (ntohs(ethernetHdr->ether_type) == ethertype_arp) {
    handle_arpreq(sr, packet);
  } else if (ntohs(ethernetHdr->ether_type) == ethertype_ip) {
    handle_ip(sr, packet, len, interface);
  } else {
    /* ??? neither arp nor IP exception? */
  }
  

}/* -- sr_handlepacket -- */

