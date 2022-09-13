
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


int filter_accept(if_info_t *ii, char *buf, int len)
{
   return FI_ACCEPT;
}


int filter_inside_set_ip(if_info_t *ii, char *buf, int len)
{
   struct in_addr netmask;
   struct ether_header *eh = (struct ether_header*) buf;
   struct ether_arp *ah;

   if (ntohs(eh->ether_type) == ETHERTYPE_ARP)
   {
      if (len < sizeof(*eh) + sizeof(*ah))
         return FI_ACCEPT;

      ah = (struct ether_arp*) (eh + 1);
      if (ah->arp_hrd == htons(ARPHRD_ETHER) && ah->arp_pro == htons(ETHERTYPE_IP) && (ah->arp_op == htons(ARPOP_REQUEST) || ah->arp_op == htons(ARPOP_REPLY)) && HWADDR_CMP(ii->hwclient, eh->ether_src))
      {
         log_msg(LOG_INFO, "setting up tun");
         pthread_mutex_lock(&ii->mutex);
         HWADDR_COPY(ii->hwclient, eh->ether_src);
         ii->hwclient_valid = 1;
         pthread_mutex_unlock(&ii->mutex);
         memset(&netmask, -1, sizeof(netmask));
         tun_ipv4_config(ii->out->gate->ifname, (struct in_addr*) ah->arp_spa, &netmask);
      }
   }

   return FI_ACCEPT;
}


int filter_incoming(if_info_t *ii, char *buf, int len)
{
   if (update_state_if_exists(ii->st, (struct ether_header*) buf, len, INCOMING) < 0)
      return FI_ACCEPT;
   memset(buf, 0, ii->gate->off);
   return FI_DROP;
}


int filter_tun_out(if_info_t *ii, char *buf, int len)
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

   if (len < sizeof(*eh))
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
         if (len < sizeof(*eh) + sizeof(*ah))
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
         if (len < sizeof(*eh) + sizeof(*i6h))
            return FI_ACCEPT;

         i6h = (struct ip6_hdr*) (eh + 1);
         if (i6h->ip6_nxt == IPPROTO_ICMPV6)
         {
            if (len < sizeof(*eh) + sizeof(*i6h) + sizeof(*icmp6))
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

   if (ii->off > sizeof(buf))
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

