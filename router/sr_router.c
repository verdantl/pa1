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
  int header_len = sizeof(sr_icmp_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  printf("The length is %d\n", header_len);

  /* fill in code here */

  uint16_t ethtype = ethertype(packet);

  print_hdrs(packet, len);
  if (ethtype == ethertype_ip) { /* IP packet */
      sr_handle_ip_packet(sr, packet, len, interface);
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
  /*printf("-------------------------------\n");
  print_addr_eth(ehdr->ether_dhost);
  print_addr_eth(received_interface->addr);
  printf("-------------------------------\n");
  sr_print_if_list(sr);
  printf("Below is the destination ip address\n");
  print_addr_ip_int(ntohl(iphdr->ip_dst));*/

  /* check if IP packet meets minimum length */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
      fprintf(stderr, "IP packet doesn't meet minimum length\n");
      return;
  }
    
  /* verify IP header checksum */
  uint16_t original_ip_checksum = iphdr->ip_sum;
  iphdr->ip_sum = 0;
  if (original_ip_checksum != cksum(iphdr, sizeof(sr_ip_hdr_t))){
      iphdr->ip_sum = original_ip_checksum;
      fprintf(stderr, "IP header checksum is inccorect\n");
      return;
  }
  iphdr->ip_sum = original_ip_checksum;

  /* find out if packet is for me */
  struct sr_if *curr_if_node = sr->if_list;
  while (curr_if_node) {
    if (curr_if_node->ip == iphdr->ip_dst) {
      printf("This is for me!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
      if (iphdr->ip_p == ip_protocol_icmp){
        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* verify ICMP header checksum */
        uint16_t original_icmp_checksum = icmp_hdr->icmp_sum;
        icmp_hdr->icmp_sum = 0;
        if (original_icmp_checksum != cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t))) {
          icmp_hdr->icmp_sum = original_icmp_checksum;
          fprintf(stderr, "ICMP header checksum is incorrect\n");
          return;
        }
        icmp_hdr->icmp_sum = original_icmp_checksum;

        /* echo request ####################### TO DO ######################*/
        if (icmp_hdr->icmp_type == 8) {
          handle_icmp_request(sr, packet, len, 0, 0, received_interface);
        }
      }
      else { /* ################## TO DO ##################*/
        printf("Port unreachable\n");
        handle_icmp_request(sr, packet, len, 3, 3, received_interface);
      }
    }
    curr_if_node = curr_if_node->next;
  }

  /*　The packet is not for me　*/
  iphdr->ip_ttl -= 1;
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));

  if (iphdr->ip_ttl == 0) {
    /* Time exceeded ################ TO DO ################*/
    handle_icmp_request(sr, packet, len, 11, 0, received_interface);
  }

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
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), matched->gw.s_addr);

    if (arp_entry) { /* ARP cache hit */
      printf("ARP hit");
      /* send frame */
      struct sr_if *new_interface = sr_get_interface(sr, matched->interface);
      memcpy(ehdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
      memcpy(ehdr->ether_shost, new_interface->addr, ETHER_ADDR_LEN);
      free(arp_entry);
      sr_send_packet(sr, packet, len, new_interface->name);
      return;
    }
    else { /* ARP cache miss */
      /*send arp request */
      /*struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), matched->gw.s_addr, packet, len, matched->interface);
      handle_arpreq(sr, req); */
      return;
    }

  }

  else {
    /* No match found ############# TO DO ##################*/
    printf("ICMP net unreachable");
    handle_icmp_request(sr, packet, len, 3, 0, received_interface);
  }
}

void handle_icmp_request(struct sr_instance *sr, uint8_t *packet, unsigned int len, 
                          uint8_t icmp_type, uint8_t icmp_code, struct sr_if *interface) {
  /* change ETHERNET header */
  int new_packet_size = 0;
  if (icmp_type == 0) {
    new_packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
  }
  else {
    new_packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
  }

  /* set ETHERNET header */
  uint8_t *new_packet = (uint8_t *)malloc(new_packet_size);
  sr_ethernet_hdr_t *response_ehdr = (sr_ethernet_hdr_t *)new_packet;
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
  memcpy(response_ehdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(response_ehdr->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
  response_ehdr->ether_type = htons(ethertype_ip); /*might need to use ntoh or hton*/

  /* set IP header */
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *new_iphdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
  new_iphdr->ip_tos = iphdr->ip_tos;
  new_iphdr->ip_len = iphdr->ip_len;
  new_iphdr->ip_id = iphdr->ip_id;
  new_iphdr->ip_off = iphdr->ip_off;
  new_iphdr->ip_ttl = 255;
  new_iphdr->ip_p = iphdr->ip_p;
  new_iphdr->ip_src = iphdr->ip_dst;
  new_iphdr->ip_dst = iphdr->ip_src;
  new_iphdr->ip_sum = 0;
  new_iphdr->ip_sum = cksum(new_iphdr, sizeof(sr_ip_hdr_t));

  /*set ICMP header */
  if (icmp_type == 0) {
    sr_icmp_hdr_t *new_icmp_hdr = (sr_icmp_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    new_icmp_hdr->icmp_type = icmp_type;
    new_icmp_hdr->icmp_code = icmp_code;
    new_icmp_hdr->icmp_sum = 0;
    new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  }
  else {
    sr_icmp_t3_hdr_t *new_icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    new_icmp_t3_hdr->icmp_type = icmp_type;
    new_icmp_t3_hdr->icmp_code = icmp_code;
    new_icmp_t3_hdr->unused = 0;
    new_icmp_t3_hdr->next_mtu = 1500;
    new_icmp_t3_hdr->icmp_sum = 0;
    new_icmp_t3_hdr->icmp_sum = cksum(new_icmp_t3_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    /*memcpy(new_icmp_t3_hdr->data, iphdr->)*/
  }


  /*send icmp reply back */
  sr_send_packet(sr, new_packet, len, interface->name);
  printf("HI");
}