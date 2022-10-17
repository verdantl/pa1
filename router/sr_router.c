#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

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

  /* fill in code here */

  uint16_t ethtype = ethertype(packet);

  print_hdrs(packet, len);
  if (ethtype == ethertype_ip) { /* IP */
      printf("This is an IP packettttttttttttttttttttttttttttttttttttt\n");
      sr_handle_ip_packet(sr, packet, len, interface);
    }
  else if (ethtype == ethertype_arp){
      printf("This is an ARP packet\n");
      sr_handle_arp_packet(sr, packet, len, interface);
  }

}/* end sr_ForwardPacket */

void sr_handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  struct sr_if* received_interface = sr_get_interface(sr, interface);
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  printf("-------------------------------\n");
  print_addr_eth(ehdr->ether_dhost);
  print_addr_eth(received_interface->addr);
  printf("-------------------------------\n");
  sr_print_if_list(sr);
  printf("Below is the destination ip address\n");
  print_addr_ip_int(ntohl(iphdr->ip_dst));

  /* check if IP packet meets minimum length */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
      printf("IP packet doesn't meet minimum length\n");
      return;
  }
    
  /* verify checksum of IP packet */
  uint16_t original_ip_checksum = iphdr->ip_sum;
  iphdr->ip_sum = 0;
  if (original_ip_checksum != cksum(iphdr, sizeof(sr_ip_hdr_t))){
      printf("Checksum of IP packet is inccorect\n");
      iphdr->ip_sum = original_ip_checksum;
      return;
  }
  iphdr->ip_sum = original_ip_checksum;

  /* find out if packet is for me */
  struct sr_if *curr_if_node = sr->if_list;
  while (curr_if_node) {
    if (curr_if_node->ip == iphdr->ip_dst) {
      printf("This is for me!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* verify checksum of ICMP packet */
        uint16_t original_icmp_checksum = icmp_hdr->icmp_sum;
        icmp_hdr->icmp_sum = 0;
        if (original_icmp_checksum != cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t))) {
          icmp_hdr->icmp_sum = original_icmp_checksum;
          printf("Checksum of ICMP packet is incorrect\n");
          return;
        }
        icmp_hdr->icmp_sum = original_icmp_checksum;

      /* icmp request */
      if (iphdr->ip_p == ip_protocol_icmp) {

        /* echo request */
        if (icmp_hdr->icmp_type == 8) {

            /* change ETHERNET header*/
            memcpy(ehdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
            memcpy(ehdr->ether_shost, received_interface->addr, ETHER_ADDR_LEN);

            /* change IP header */
            iphdr->ip_dst = iphdr->ip_src;
            iphdr->ip_src = received_interface->ip;

            /* change ICMP header */
            icmp_hdr->icmp_type = 0x00;
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
            printf("YEAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
            printf("%d\n", icmp_hdr->icmp_sum);

            /* send icmp reply back */
            sr_send_packet(sr, packet, len, interface);
        }
      }

    }

    /*　The packet is not for me　*/
    else {
      iphdr->ip_ttl -= 1;
      iphdr->ip_sum = 0;
      iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));

      /* perform LPM */
      struct sr_rt *curr_routing_node = sr->routing_table;
      struct sr_rt *matched = NULL;
      while (curr_routing_node) {
        uint32_t masked_dest = iphdr->ip_dst & curr_routing_node->mask.s_addr;
        if (masked_dest == curr_routing_node->dest.s_addr) {
          matched = curr_routing_node;
          break;

        }
        curr_routing_node = curr_routing_node->next;
      }

      if (matched) {
        printf("matcheddddddddddddd\n");
        /* struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, iphdr->ip_dst); */
        struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, matched->gw.s_addr);

        if (arp_entry) { /* arp hit */
          printf("ARP hit");
          /* send fram*/

        }

        else {
          /*send arp request */
          struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, matched->gw.s_addr, packet, len, matched->interface);
          /* handle_arpreq(req, sr); */
        }

      }

      else {
        printf("ICMP not unreachable");
      }
    }

    curr_if_node = curr_if_node->next;
  }
 

}

void sr_handle_arp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */) {
  struct sr_if* received_interface = sr_get_interface(sr, interface);
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  printf("-------------------------------\n");
  print_addr_eth(ehdr->ether_dhost);
  print_addr_eth(received_interface->addr);
  printf("-------------------------------\n");
  sr_print_if_list(sr);
  print_addr_ip_int(ntohl(arphdr->ar_sip));

  struct sr_if *curr_if_node = sr->if_list;

  while (curr_if_node){
    if (curr_if_node->ip == arphdr->ar_tip){
      printf("ARP Request IP matches one of the router's IP addresses\n");
      if (ntohs(arphdr->ar_op) == arp_op_request){
        /*Then the IP matches one of the IP's of the router*/
        printf("This is an ARP Request\n");
        /* We need to construct a reply and send it back if the request matches the router's ethernet addresses */
        uint8_t *response_arp = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)); 
        sr_ethernet_hdr_t *response_ethernet_hdr = (sr_ethernet_hdr_t *) response_arp;
        /*1. Fill in ethernet header values*/
        memcpy(response_ethernet_hdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN); /*makes the destination the original source*/
        memcpy(response_ethernet_hdr->ether_shost, curr_if_node->addr, ETHER_ADDR_LEN);
        /*still need to fill in source address - router ethernet address*/
        response_ethernet_hdr->ether_type = htons(ethertype_arp);
        
        /*2. Fill in arp response header*/
        sr_arp_hdr_t* response_arp_hdr = (sr_arp_hdr_t*) (response_arp + sizeof(sr_ethernet_hdr_t));
        response_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
        response_arp_hdr->ar_pro = arphdr->ar_pro;
        response_arp_hdr->ar_hln = arphdr->ar_hln;
        response_arp_hdr->ar_pln = arphdr->ar_pln;
        response_arp_hdr->ar_op = htons(arp_op_reply);

        /*still need to fill in source ip and hardware*/
        memcpy(response_arp_hdr->ar_sha, curr_if_node->addr, ETHER_ADDR_LEN);
        response_arp_hdr->ar_sip = arphdr->ar_tip;
        memcpy(response_arp_hdr->ar_tha, arphdr->ar_sha, ETHER_ADDR_LEN);
        response_arp_hdr->ar_tip = arphdr->ar_sip;

        print_hdrs(response_arp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

        sr_send_packet(sr, response_arp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);
      } 
      else if (ntohs(arphdr->ar_op) == arp_op_reply){
        printf("This is an ARP Reply\n");
      }          
      else{
        printf("Why is this not working %d %d %d \n", arp_op_request, arp_op_reply, ntohs(arphdr->ar_op));
      }
    }
    curr_if_node = curr_if_node->next;  
  }
}
