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
#define IP_HEADER_MIN_LEN 20

/* Return longest prefix match address */
struct sr_rt* findlongestPrefixMatching(struct sr_instance* sr, struct in_addr addr)
{
  struct sr_rt* longestMatch = 0;
  unsigned long addressLength = 0;
  struct sr_rt* currentMatch = sr->routing_table;

  /* go through all entries in routing table, and keep the longest matching address */
  while (currentMatch != 0) 
  {
    if ( (currentMatch->dest.s_addr & currentMatch->mask.s_addr) == (addr.s_addr & currentMatch->mask.s_addr))
    {
      /* only update longest prefix match is current address has a longer match */
      if(addressLength < currentMatch->mask.s_addr)
      {
        addressLength = currentMatch->mask.s_addr;
        longestMatch = currentMatch;
      }
    }
    currentMatch = currentMatch->next;
   }
   return longestMatch;
}



struct sr_arpentry arpCache[SR_ARPCACHE_SZ];
/* broadcast_eth_addr */
/* TODO: Add helper functions here... */

/* ARP request was for our router, send a reply with the requested
   MAC address corresponding to the given interface */
void ARP_sendReply(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface, struct sr_if* ifptr) {
  struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*)packet;
  /* create ARP header */
  struct sr_arp_hdr* arp_hdr = (struct sr_arp_hdr*)(packet + sizeof(sr_ethernet_hdr_t));  

  /* create ARP packet by modifying the recieved packet */
  ARP_makePacket(arp_hdr, arp_hdr->ar_hrd, arp_hdr->ar_pro, arp_hdr->ar_hln, arp_hdr->ar_pln, htons(arp_op_request), 
    sr_get_interface(sr, interface)->addr, sr_get_interface(sr, interface)->ip, arp_hdr->ar_sha, 
    arp_hdr->ar_sip);
  /* create ethernet packet to send back to sender */
  ETH_makePacket(eth_hdr, ethertype_arp, ifptr->addr, eth_hdr->ether_shost);
  
  /* send created ethernet wrapped arp reply packet */
  sr_send_packet(sr, packet, len, interface);

}

/* caches an ARP reply*/
void ARP_cacheEntry(struct sr_arp_hdr* arp_hdr) {

}

/* creates an ethernet packet  */
void ETH_makePacket(struct sr_ethernet_hdr* eth_hdr, uint16_t type, uint8_t* src, uint8_t* dst) {
  int i;  

  eth_hdr->ether_type = htons(type);
  for (i = 0; i < ETHER_ADDR_LEN; i++) {
      eth_hdr->ether_shost[i] = src[i];
      eth_hdr->ether_dhost[i] = dst[i];
  }
}

/* Given a new ARP header, fill it with its contents */
void ARP_makePacket(struct sr_arp_hdr* arp_hdr,
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
    arp_hdr->ar_hrd = ar_hrd;
    arp_hdr->ar_pro = ar_pro;
    arp_hdr->ar_hln = ar_hln;
    arp_hdr->ar_pln = ar_pln;
    arp_hdr->ar_op = ar_op;
    arp_hdr->ar_sip = ar_sip; 
    arp_hdr->ar_tip = ar_tip;
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
      arp_hdr->ar_sha[i] = ar_sha[i];
      arp_hdr->ar_tha[i] = ar_tha[i];
    }
}

/* loop though IP packetse waiting on an ARP reply */
void checkandSendWaitingPackets(struct sr_instance* sr, int i) {


}

/* Return 1 if ICMP isvalid, 0 otherwise */
int ICMP_checkValidity(sr_ip_hdr_t* ipHeader)
{
  /*Get the ICMP header*/
  uint8_t* icmpHeaderLocation = (uint8_t*)(ipHeader);	
  icmpHeaderLocation = icmpHeaderLocation + (ipHeader->ip_hl << 2);
  sr_icmp_hdr_t* icmpHeader = (sr_icmp_hdr_t*)(icmpHeaderLocation);
  
  unsigned int icmpPacketSize = (ntohs(ipHeader->ip_len) - (ipHeader->ip_hl << 2 ));
  uint16_t claimedChecksum = icmpHeader->icmp_sum; 
  uint16_t actualChecksum = cksum(icmpHeader,icmpPacketSize);
  
  if (actualChecksum != claimedChecksum)
  {
    fprintf(stderr, "ICMP incorrect checksum, dropping\n");
    return 0;
  }
  return 1;
}

/* Packet has no match for next hop*/
void ICMP_sendNetUnreachable(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {

      fprintf(stderr, "ICMP sending net unreachable, type 3 code 0\n");
struct sr_icmp_t3_hdr outPacketHdr;

}


/* Packet was for us but contained TCP/UDP, send unreachable to sender */
void ICMP_sendPortUnreachable(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {

      fprintf(stderr, "ICMP send port unreachable, type 3 code 3\n");
/* can use default type here?
 type 3 code 3 */
struct sr_icmp_t3_hdr outPacketHdr;

}

void ICMP_sendTimeExceeded(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {

      fprintf(stderr, "ICMP send time exceeded, type 11 code 0\n");
/* can use default type here?
 type 3 code 3 */
struct sr_icmp_t3_hdr outPacketHdr;

}
/* Packet was for this router so send an ICMP echo to sender */
void ICMP_sendEcho(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {

  fprintf(stderr, "ICMP send echo, type 0\n");
/* type 0 code ?? */
 /*  struct sr_icmp_hdr outPacket; */
  
  sr_icmp_hdr_t* icmpHeader;
  /*sr_ip_hdr_t* error_ip_header_ptr; */
  sr_ip_hdr_t* echoIPHeader;
  
  /*struct sr_rt* rt; */
  interface = (struct sr_if*)interface;
  uint16_t icmpSize; 
  uint16_t totalSize;
  uint8_t* new_ip_packet;
  uint8_t* new_ip_packet_ptr;
  uint32_t ip_dst;
  
  /* Repurpose packet and send back to sender */
  echoIPHeader = (sr_ip_hdr_t*)(packet);
  ip_dst = echoIPHeader->ip_src;
  echoIPHeader->ip_src = echoIPHeader->ip_dst;
  echoIPHeader->ip_dst = ip_dst;
  
  /* modify data in icmp packet */
  uint8_t* icmpHeaderLocation = (uint8_t*)(echoIPHeader);	
  icmpHeaderLocation = icmpHeaderLocation + (echoIPHeader->ip_hl << 2);
  icmpHeader = (sr_icmp_hdr_t*)(icmpHeaderLocation);

  /*icmpHeader = get_icmp_header(echoIPHeader); */
  icmpHeader->icmp_type = 0;
  icmpHeader->icmp_code = 0;
  icmpHeader->icmp_sum = 0;
  
  /* make a copy */
  totalSize = ntohs(echoIPHeader->ip_len);
  icmpSize = totalSize - IP_HEADER_MIN_LEN;
  new_ip_packet = malloc(totalSize);
  memcpy(new_ip_packet,echoIPHeader,totalSize);

   /* checksum icmp */
  /* [ip_header[icmp_header|echoIPHeader|8byte]] */
  /* checksum for [icmp_header|echoIPHeader|8byte] */
  icmpHeaderLocation = (uint8_t*)(echoIPHeader);	
  icmpHeaderLocation = icmpHeaderLocation + (echoIPHeader->ip_hl << 2);
  icmpHeader = (sr_icmp_hdr_t*)(icmpHeaderLocation);

  /*icmpHeader = get_icmp_header((sr_ip_hdr_t*)new_ip_packet); */
  icmpHeader->icmp_sum = cksum(icmpHeader,icmpSize);
  /* ETH make packet
  send packet */
} 	
  	
  	
/*	 Handles the forwarding of an IP packet destined elsewhere */
void IP_forward(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
/*         sanity check packet
//	 if ( meets minimum length && has correct checksum )
//	if ( (len <= 20) && ( cksum(packet) ) ) */
  	
  	/* Get relevant packet statistics */
  	/*unsigned int minlengthETH = sizeof(sr_ethernet_hdr_t); */
  	unsigned int minlengthIP = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t); 
  	
  	sr_ip_hdr_t* ipHeader = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  	unsigned int ipHeaderSize = ipHeader->ip_hl << 2;
  	unsigned int ipPacketSize = len - sizeof(sr_ethernet_hdr_t);
  	uint16_t ipPacketSizeParam = ntohs(ipHeader->ip_len);
  	
  	uint16_t checksum = 0;

  /* sanity check ethernet frame size */
  /* if (len < minlengthETH )
  {
      fprintf(stderr, "ETHERNET frame insufficient length\n");
  } */
  /* sanity check ip packet size */
  /*else*/ if (len < minlengthIP)
  {
      fprintf(stderr, "IP packet insufficient length\n");
      return;
  }
  /* sanity check ip header size */
  else if (ipPacketSize < ipHeaderSize)
  {
      fprintf(stderr, "IP packet size less than what header claims\n");
      return;
  }
  /* check what IP header claims is correct */
  else if (ipPacketSize != ipPacketSizeParam)
  {
      fprintf(stderr, "IP packet size less than what header claims\n");
      return;
  }

  /* make sure checksum is correct*/
  uint16_t claimedChecksum = 0;
  uint16_t actualChecksum = 0;

  claimedChecksum = ipHeader->ip_sum;
  actualChecksum = cksum(ipHeader,ipHeaderSize);

  if ( actualChecksum != claimedChecksum )
  {
      fprintf(stderr, "IP packet wrong checksum\n");
      return;
  }

  /* make sure we didn't do anything stupid.*/
  ipHeader->ip_sum = 0;
  ipHeader->ip_sum = actualChecksum;
  


  
  /* packet passed all checks...continue with forwarding packet */
  fprintf(stderr, "Sanity checks passed, forwarding IP packet\n");

  /* is this necassary?  nah*/
  uint8_t* forwarded_packet;
  unsigned int forwarded_ipPacketSizeParam = ntohs(ipHeader->ip_len);

  /* Decrement TTL, and if it is 0, send ICMP, otherwise recompute checksum
    with destination IP, and check ARP for next hop
  MAC address corresponding to next hopt IP */
  ipHeader->ip_ttl--;
  ipHeader->ip_sum = 0;
  unsigned int forwarded_ipHeaderSize = ipHeader->ip_hl << 2;
  ipHeader->ip_sum = cksum(ipHeader,forwarded_ipHeaderSize);

  if ( ipHeader->ip_ttl == 0 )
  {
    /* send ICMP TTL exceeded, type 11, code 0 
     using any incoming interface as source address*/
    fprintf(stderr, "TTL = 0, sending ICMP time exceeded (type 11, code 0)\n");

    return;
  }
  
  forwarded_packet = malloc(forwarded_ipPacketSizeParam);
  memcpy(forwarded_packet, ipHeader, ipPacketSizeParam);
  
  /* send packet. 
  First find if there is a longest prefix match for destination, 
  if not send ICMP net unreachable type 3 code 0. */
 
  struct sr_rt* routingTableEntry = findLongestMatchingPrefix(sr, ipHeader->ip_dst);
  if (routingTableEntry == 0)
  {
    /* send ICMP net unreachable type 3 code 0 */
    fprintf(stderr, "No match for next hop, sending ICMP net unreachable (type 3, code 0)\n");

    return;
  }
  
    fprintf(stderr, "Found routing entry!\n");
  /* if we have MAC address for next hop destination, send packet*/ 
  struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*)packet;
  /* ETH_makePacket(eth_hdr, ethertype_ip, uint8_t* src, eth_hdr->ether_shost); */
  /* sendpacket */

  free(forwarded_packet);
  
  
  

/* //  TTL--
//  if ( TTL == 0)
//    send ICMP time exceeded
//  else 
//  recompute modified packet checksum over modified header 
//  find entry with longest prefix match with destinitation IP
//  check ARP cache for next hop mac address
//  corresponding to next hop ip
//  if ( match found for next hop usin longest prefix)
//    if ( have mac address for next hop)
//      send packet
//    else 
//      has arp request been sent?.....
//  else 
//    send ICMP net unreachable
//    
// else ( drop packet ) */

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
  /* get IP of interface that received packet */ 
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
        checkandSendWaitingPackets(sr, i);
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

  /* Is for our router */
  if (IP_dstMatches(sr, packet, interface)) {
    if (ip_hdr->ip_p == IPPROTO_ICMP) {
    /* need to check for valid ICMP checksum first */
      if ( ICMP_checkValidity(ip_hdr) ){
        ICMP_sendEcho(sr, packet, len, interface);
      }
    } else if (ip_hdr->ip_p == IPPROTO_TCP || ip_hdr->ip_p == IPPROTO_UDP) {
      ICMP_sendUnreachable(sr, packet, len, interface);
    } else {
      /* ignore anything else */
      return;
    }   
  } 
  /* Not for our router */
  else {
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

