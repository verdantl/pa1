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
  // struct sr_if* received_interface= sr_get_interface(sr, interface);
  /*sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet); */
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  // sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
  struct sr_if *find_iterator = sr->if_list;
  print_addr_ip_int(ntohl(sr->if_list->ip));
  print_addr_ip_int(ntohl(iphdr->ip_dst));

  while (find_iterator) {
    print_addr_ip_int(ntohl(find_iterator->ip));
    if (find_iterator->ip == iphdr->ip_dst) {
    printf("This is for me!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    }
    find_iterator = find_iterator -> next;
  }


  

}