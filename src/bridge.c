/* Copyright 2022 Bernhard R. Fischer.
 *
 * This file is part of Endoor.
 *
 * Endoor is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * Endoor is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Endoor. If not, see <http://www.gnu.org/licenses/>.
 */

/*! \file bridge.c
 * This file contains everything of the switching code, so switching frames
 * between the 3 interfaces.
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2022/09/13
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#ifdef HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif

#include "bridge.h"
#include "endoor.h"
#include "pcap.h"
#include "log.h"
#include "tun.h"
#include "state.h"

#define SNAPLEN 4096


/*! This is an accept filter. It always return FI_ACCEPT without any other
 * action.
 * @param ii Pointer to interface info struct.
 * @param buf Pointer to data buffer.
 * @param len Length of data in buffer.
 * @return The function returns FI_ACCEPT.
 */
int filter_accept(if_info_t *UNUSED(ii), char *UNUSED(buf), int UNUSED(len))
{
   return FI_ACCEPT;
}


/*! This is the filter for all frames arriving on the inside interface. If an
 * ARP request or reply is received, the IP address is extraced and set on the
 * tunnel interface.
 * @param ii Pointer to interface info struct.
 * @param buf Pointer to data buffer.
 * @param len Length of data in buffer.
 * @return The function returns FI_ACCEPT.
 */
int filter_in_inside(if_info_t *ii, char *buf, int len)
{
   struct in_addr netmask;
   struct ether_header *eh = (struct ether_header*) buf;
   struct ether_arp *ah;

   if (ntohs(eh->ether_type) == ETHERTYPE_ARP)
   {
      if (len < (int) sizeof(*eh) + (int) sizeof(*ah))
         return FI_ACCEPT;

      ah = (struct ether_arp*) (eh + 1);
      if (ah->arp_hrd == htons(ARPHRD_ETHER) && ah->arp_pro == htons(ETHERTYPE_IP) && (ah->arp_op == htons(ARPOP_REQUEST) || ah->arp_op == htons(ARPOP_REPLY)) && HWADDR_CMP(ii->hwclient, eh->ether_src))
      {
#if 1
         update_table(&ii->mtbl, (char*) eh->ether_src, AF_INET, (char*) ah->arp_spa, PA_CLIENT);
#else
         log_msg(LOG_INFO, "setting up tun");
         pthread_mutex_lock(&ii->mutex);
         HWADDR_COPY(ii->hwclient, eh->ether_src);
         ii->hwclient_valid = 1;
         pthread_mutex_unlock(&ii->mutex);
         memset(&netmask, -1, sizeof(netmask));
         tun_ipv4_config(ii->out->gate->ifname, (struct in_addr*) ah->arp_spa, &netmask);
#endif
      }
   }

   return FI_ACCEPT;
}


/*! This s the filter for all frames incoming on the outside interface. All
 * packets are matched against the state table.
 * @param ii Pointer to interface info struct.
 * @param buf Pointer to data buffer.
 * @param len Length of data in buffer.
 * @return The function returns FI_ACCEPT if no state was found meaning that it
 * should be forwarded to the inside interface. FI_DROP is returned if a state
 * matched. The state is updated.
 */
int filter_in_outside(if_info_t *ii, char *buf, int len)
{
   if (update_state_if_exists(ii->st, (struct ether_header*) buf, len, INCOMING) < 0)
      return FI_ACCEPT;
   memset(buf, 0, ii->gate->off);
   return FI_DROP;
}


/*! This is the filter for all frames which go out on the tunnel interface. It
 * maintains the state table.
 * protocols are dropped.
 * @param ii Pointer to interface info struct.
 * @param buf Pointer to data buffer.
 * @param len Length of data in buffer.
 * @return The function returns FI_ACCEPT if a state could be maintained. If
 * the protocol is unsupported, FI_DROP is returned.
 */
int filter_out_tunnel(if_info_t *ii, char *buf, int len)
{
   struct ether_header *eh = (struct ether_header*) buf;

   if (ntohs(eh->ether_type) != ETHERTYPE_IP)
   {
      log_msg(LOG_INFO, "ethertype 0x%04x on %s not implemented yet", ntohs(eh->ether_type), ii->ifname);
      return FI_DROP;
   }

   pthread_mutex_lock(&ii->out->out->mutex);
   if (!ii->out->out->hwclient_valid)
   {
      pthread_mutex_unlock(&ii->out->out->mutex);
      log_msg(LOG_NOTICE, "no valid client address yet found on %s", ii->out->out->ifname);
      return FI_DROP;
   }
   HWADDR_COPY(buf + ETHER_ADDR_LEN, ii->out->out->hwclient);
   pthread_mutex_unlock(&ii->out->out->mutex);

   pthread_mutex_lock(&ii->out->mutex);
   if (!ii->out->router_valid)
   {
      pthread_mutex_unlock(&ii->out->mutex);
      log_msg(LOG_NOTICE, "no valid router address yet found on %s", ii->out->ifname);
      return FI_DROP;
   }
   HWADDR_COPY(buf, ii->out->hwrouter);
   pthread_mutex_unlock(&ii->out->mutex);

   if (update_state(ii->st, (struct ether_header*) buf, len, OUTGOING) < 0)
      return FI_DROP;

   return FI_ACCEPT;
}


/*! This is the basic frame processor.
 * It observes all incoming frames and updates the mac address table
 * accordingly.
 * @param ii Pointer to interface info struct.
 * @param buf Pointer to data buffer which should point to the beginning of an
 * Ethernet frame.
 * @param len Length of data in buffer.
 * @return The function returns FI_ACCEPT if the packet shall be forwarded and
 * FI_DROP of it shall be dropped. The latter case occurs for all outgoing
 * frames with the local address since promisious mode captures both directions
 * and not just incoming.
 */
int proc_src_addr(if_info_t *ii, const char *buf, int len)
{
   struct ether_header *eh = (struct ether_header*) buf;
   struct ether_arp *ah;
   //struct iphdr *ih;
   struct ip6_hdr *i6h;
   struct icmp6_hdr *icmp6;
   int family = AF_PACKET;
   void *addr;
   char addrstr[32];
   int flags = 0;

   if (len < (int) sizeof(*eh))
   {
      log_msg(LOG_WARNING, "frame of %d bytes too short on %s", len, ii->ifname);
      return FI_ACCEPT;
   }

   addr = eh->ether_src;
   if (!HWADDR_CMP(ii->hwaddr, addr))
   {
      //log_msg(LOG_DEBUG, "ignoring own frame on %s", ii->ifname);
      return FI_DROP;
   }
   ether_ntoa_r(addr, addrstr);

   switch (ntohs(eh->ether_type))
   {
      case ETHERTYPE_ARP:
         if (len < (int) sizeof(*eh) + (int) sizeof(*ah))
            return FI_ACCEPT;

         //log_msg(LOG_DEBUG, "%s: src = %s, ethertype = 0x%04x", ii->ifname, addrstr, ntohs(eh->ether_type));
         ah = (struct ether_arp*) (eh + 1);
         if (ah->arp_hrd == htons(ARPHRD_ETHER) && ah->arp_pro == htons(ETHERTYPE_IP) && (ah->arp_op == htons(ARPOP_REQUEST) || ah->arp_op == htons(ARPOP_REPLY)))
         {
            family = AF_INET;
            addr = ah->arp_spa;
         }
         break;

      case ETHERTYPE_IPV6:
         if (len < (int) sizeof(*eh) + (int) sizeof(*i6h))
            return FI_ACCEPT;

         i6h = (struct ip6_hdr*) (eh + 1);
         if (i6h->ip6_nxt == IPPROTO_ICMPV6)
         {
            if (len < (int) sizeof(*eh) + (int) sizeof(*i6h) + (int) sizeof(*icmp6))
               return FI_ACCEPT;

            icmp6 = (struct icmp6_hdr*) (i6h + 1);
            switch (icmp6->icmp6_type)
            {
               case ND_ROUTER_ADVERT:
                  flags = PA_ROUTER;
                  /* fall through */
               case ND_NEIGHBOR_SOLICIT:
               case ND_NEIGHBOR_ADVERT:
               case ND_ROUTER_SOLICIT:
                  //log_msg(LOG_DEBUG, "%s: src = %s, icmp6_type = %d", ii->ifname, addrstr, icmp6->icmp6_type);
                  family = AF_INET6;
                  addr = &i6h->ip6_src;
            }
         }
         break;
   }

   // collect only addresses of ARP/NDP (not any frame)
   //if (family != AF_PACKET)
      (void) update_table(&ii->mtbl, (char*) eh->ether_src, family, addr, flags);

   return FI_ACCEPT;
}


/*! This function is a wrapper for write(2) outputting some log information in
 * case of error.
 * @param ii Pointer to interface info struct.
 * @param buf Pointer to data buffer.
 * @param len Length of data in buffer.
 * @return The function returns the number of bytes written or -1 in case of
 * error (see write(2)).
 */
int write_out(if_info_t *ii, const char *buf, int len)
{
   int wlen;

   if ((wlen = write(ii->fd, buf + ii->off, len - ii->off)) == -1)
   {
      log_msg(LOG_ERR, "write() to %s failed: %s (%d bytes)", ii->ifname, strerror(errno), len - ii->off);
      return -1;
   }

   if (wlen < len - ii->off)
      log_msg(LOG_NOTICE, "short write() to %s: %d < %d", ii->ifname, wlen, len);
   /*else
      log_msg(LOG_DEBUG, "%d bytes written to fd %d", wlen, ii->out->fd);*/

   return wlen;
}
 

/*! This is the frame forwarder.
 * It receives frames processes it through proc_src_addr() and the calls the
 * filter. If proc_src_addr() returns FI_DROP, the frame is dropped and the
 * next incoming frame is processed.
 * If proc_src_addr() returns FI_ACCEPT, the filter is called. If the filter
 * returns FI_ACCEPT the frame is forwarded to the interface defined as out. If
 * the filter returns FI_DROP, the frame is forwarded to the interface defined
 * as gate (if not NULL).
 * The bridge receiver is started in a thread by pthread_create(3). There is
 * one bridge receiver thread per interface (so 3 in total, 1 for inside, 1 for
 * outside, 1 for the tunnel).
 * @param p Pointer to an interface info struct.
 * @return The function returns NULL.
 */
void *bridge_receiver(void *p)
{
   if_info_t *ii = p;
   int len;
   char buf[SNAPLEN];

   // safety check
   if (ii == NULL)
      log_msg(LOG_EMERG, "ii == NULL"), exit(1);

   if (ii->filter == NULL)
      ii->filter = filter_accept;

   if (ii->off > (int) sizeof(buf))
      ii->off = sizeof(buf);

   for (;;)
   {
      memset(buf, 0, ii->off);
      if ((len = read(ii->fd, buf + ii->off, sizeof(buf) - ii->off)) == -1)
      {
         log_msg(LOG_ERR, "read() on %s failed: %s. retrying soon...", ii->ifname, strerror(errno));
         sleep(10);
         continue;
      }

      if (!len)
      {
         log_msg(LOG_NOTICE, "received EOF on %s (fd = %d)", ii->ifname, ii->fd);
         // FIXME: terminate properly...or whatelse?
         return NULL;
      }

      len += ii->off;

      //log_msg(LOG_DEBUG, "%d bytes received on %s", len, ii->ifname);
      //log_hex(buf, len);

      save_packet(ii->wfd, buf, len);

      if (proc_src_addr(ii, buf, len) == FI_DROP)
         continue;

      if (ii->filter(ii, buf, len) == FI_DROP)
      {
         if (ii->gate != NULL)
         {
            log_msg(LOG_DEBUG, "diverting to %s", ii->gate->ifname);
            write_out(ii->gate, buf, len);
         }
         continue;
      }

      write_out(ii->out, buf, len);
   }

   return NULL;
}

