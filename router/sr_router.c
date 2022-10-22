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

  print_hdrs(packet, len);

  uint16_t ethtype = ethertype(packet);
  if (ethtype == ethertype_ip) { /* IP packet */
      printf("This is an IP packet\n");
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
  struct sr_if *received_interface = sr_get_interface(sr, interface);
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

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
      printf("This packet is for me\n");
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

        /* echo request */
        if (icmp_hdr->icmp_type == 8) {
          printf("This is ICMP echo request\n");
          handle_icmp_request(sr, packet, len, 0, 0, received_interface);
        }
      }

      else { /* it's TCP/UDP, send ICMP port unreachable */
        printf("Port unreachable\n");
        handle_icmp_request(sr, packet, len, 3, 3, received_interface);
      }
    }
    curr_if_node = curr_if_node->next;
  }

  /* start IP forwarding */
  handle_ip_forwarding(sr, packet, len, received_interface);
}

void handle_icmp_request(struct sr_instance *sr, uint8_t *packet, unsigned int len, 
                          uint8_t icmp_type, uint8_t icmp_code, struct sr_if *interface) {
  /* change ETHERNET header */
  int new_packet_size = 0;
  if (icmp_type == 0) {
    /* sending back the original content */
    new_packet_size = len;
  }
  else {
    new_packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  }

  /* set ETHERNET header */
  uint8_t *new_packet = (uint8_t *)malloc(new_packet_size);
  memcpy(new_packet, packet, new_packet_size);

  sr_ethernet_hdr_t *response_ehdr = (sr_ethernet_hdr_t *)new_packet;
  memcpy(response_ehdr->ether_dhost, response_ehdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(response_ehdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
  response_ehdr->ether_type = htons(ethertype_ip);

  /* set IP header */
  sr_ip_hdr_t *original_iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *response_iphdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));

  if ((icmp_type == 0 && icmp_code == 0) || (icmp_type == 3 && icmp_code == 3)){ 
        response_iphdr->ip_src = original_iphdr->ip_dst;
    }
  else {
        response_iphdr->ip_src = interface->ip;
  }
  response_iphdr->ip_ttl = INIT_TTL;
  response_iphdr->ip_p = ip_protocol_icmp;
  response_iphdr->ip_dst = original_iphdr->ip_src;
  response_iphdr->ip_sum = 0;
  response_iphdr->ip_sum = cksum(response_iphdr, sizeof(sr_ip_hdr_t));

  /*set ICMP header */
  if (icmp_type == 0) {
    /* Echo reply */
    sr_icmp_hdr_t *new_icmp_hdr = (sr_icmp_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    new_icmp_hdr->icmp_type = icmp_type;
    new_icmp_hdr->icmp_code = icmp_code;
    new_icmp_hdr->icmp_sum = 0;
    new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  }
  else {
    /* Message other than echo reply(ICMP type 3 message) */
    sr_icmp_t3_hdr_t *new_icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    new_icmp_t3_hdr->icmp_type = icmp_type;
    new_icmp_t3_hdr->icmp_code = icmp_code;
    new_icmp_t3_hdr->unused = 0;
    new_icmp_t3_hdr->next_mtu = 0;
    memcpy(new_icmp_t3_hdr->data, original_iphdr, ICMP_DATA_SIZE);
    new_icmp_t3_hdr->icmp_sum = 0;
    new_icmp_t3_hdr->icmp_sum = cksum(new_icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
  }
  
  /* start IP forwarding */
  handle_ip_forwarding(sr, new_packet, new_packet_size, interface);
  free(new_packet);
}

void handle_ip_forwarding(struct sr_instance *sr, uint8_t *packet, 
                          unsigned int len, struct sr_if *received_interface) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));   

  /*　The packet is not for me　*/
  printf("This packet is NOT for me\n");
  iphdr->ip_ttl -= 1;
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));

  if (iphdr->ip_ttl == 0) {
    /* TTL field is 0, send ICMP time exceeded */
    printf("Time exceeded\n");
    handle_icmp_request(sr, packet, len, 11, 0, received_interface);
    return;
  }

  /* perform LPM */
  struct sr_rt *curr_routing_node = sr->routing_table;
  struct sr_rt *matched = NULL;
  while (curr_routing_node) {
    uint32_t masked_dest = iphdr->ip_dst & curr_routing_node->mask.s_addr;
    if (masked_dest == (curr_routing_node->dest.s_addr & curr_routing_node->mask.s_addr)) {
      if(!matched || matched->mask.s_addr < curr_routing_node->mask.s_addr) {
        matched = curr_routing_node;
      }
    }
    curr_routing_node = curr_routing_node->next;
  }

  if (matched) {
    printf("Matched\n");
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), matched->gw.s_addr);

    if (arp_entry) { /* ARP cache hit */
      printf("ARP cache hit\n");
      /* send frame */
      struct sr_if *new_interface = sr_get_interface(sr, matched->interface);
      memcpy(ehdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
      memcpy(ehdr->ether_shost, new_interface->addr, ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, len, matched->interface);
      free(arp_entry);
    }
    else { /* ARP cache miss */
      /*send arp request */
      printf("ARP cache miss\n");
      print_addr_ip_int(ntohl(matched->gw.s_addr));
      struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), matched->gw.s_addr, packet, len, matched->interface);
      handle_arpreq(sr, req);
    }
  }

  else {
    /* No match found, send ICMP net unreachable */
    printf("ICMP net unreachable\n");
    handle_icmp_request(sr, packet, len, 3, 0, received_interface);
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
        response_arp_hdr->ar_sip = curr_if_node->ip;
        memcpy(response_arp_hdr->ar_tha, arphdr->ar_sha, ETHER_ADDR_LEN);
        response_arp_hdr->ar_tip = arphdr->ar_sip;

        print_hdrs(response_arp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

        sr_send_packet(sr, response_arp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);
      } 
      else if (ntohs(arphdr->ar_op) == arp_op_reply){
        printf("Handling an ARP Reply\n");
        struct sr_arpreq *arp_request = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha, arphdr->ar_sip);
        if (arp_request) {
            struct sr_packet *packet = arp_request->packets;
            /* We send the packets for this request, and we need to find the interface for this ip*/
            while (packet){

                struct sr_if *iface = sr_get_interface(sr, packet->iface);
                if (iface) {
                    sr_ethernet_hdr_t *new_ehdr = (sr_ethernet_hdr_t *)packet->buf;
                    memcpy(new_ehdr->ether_dhost, arphdr->ar_sha, ETHER_ADDR_LEN);
                    memcpy(new_ehdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
                    sr_send_packet(sr, packet->buf, packet->len, packet->iface);
                }


                packet = packet->next;
            }
            sr_arpreq_destroy(&(sr->cache), arp_request);  
        }
     
      }          
      else{
        printf("Why is this not working %d %d %d \n", arp_op_request, arp_op_reply, ntohs(arphdr->ar_op));
      }
    }
    curr_if_node = curr_if_node->next;  
  }
}
