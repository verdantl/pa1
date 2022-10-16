#include <stdio.h>
#include <assert.h>
#include <string.h>

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

}/* end sr_ForwardPacket */

void sr_handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  struct sr_if* received_interface = sr_get_interface(sr, interface);
  /*sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet); */
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if *find_iterator = sr->if_list;
  printf("-------------------------------\n");
  print_addr_eth(ehdr->ether_dhost);
  print_addr_eth(received_interface->addr);
  printf("-------------------------------\n");
  sr_print_if_list(sr);
  printf("Below is the destination ip address\n");
  print_addr_ip_int(ntohl(iphdr->ip_dst));

  while (find_iterator) {
    if (find_iterator->ip == iphdr->ip_dst) {
      printf("This is for me!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        /* checking ICMP checkksum */
        uint16_t icmp_sum_temp = icmp_hdr->icmp_sum;
        icmp_hdr->icmp_sum = 0;
        uint16_t recalculation = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
        if (icmp_sum_temp != cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t))) {
          icmp_hdr->icmp_sum = icmp_sum_temp;
          printf("%d\n", icmp_sum_temp);
          printf("%d\n", recalculation);
          printf("ICMP header checksum is incorrect\n");
          return;
        }
        icmp_hdr->icmp_sum = icmp_sum_temp;

      /* icmp request */
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
          // icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));

          /* send icmp reply back */
          sr_send_packet(sr, packet, len, interface);
      }

    }
    find_iterator = find_iterator -> next;
  }


  

}