
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>

#include "log.h"
#include "state.h"
#include "rwpack.h"
#include "protoaddr.h"


int new_state_table(state_table_t *st, int n)
{
   memset(st, 0, sizeof(*st));
   if ((st->state = calloc(n, sizeof(*st->state))) == NULL)
   {
      log_msg(LOG_ERR, "malloc failed: %s", strerror(errno));
      return -1;
   }
   st->size = n;
   pthread_mutex_init(&st->mutex, NULL);
   return 0;
}


int get_unused_state0(const state_table_t *st)
{
   int i;

   for (i = 0; i < st->size && st->state[i].family; i++);
   return i;
}


static uint16_t get_u16(void *buf)
{
   return *((uint16_t*) buf);
}


/*! The function checks if a state exists in the state table by comparing
 * protocol, ip addresses, and port numbers.
 * Some minimum requirements are checked at first (e.g. if data is long
 * enough).
 * @param st Pointer to state table.
 * @param ih Pointer to IPv4 header.
 * @param len Total length of bytes available, starting at ih.
 * @return If the packet does not match minimum criteria, -1 is returned. If a
 * state was found, the index of the valid entry in the state table is
 * returned, which is 0 <= index < st->size. If no valid entry is found
 * st->size is returned.
 */
int has_ip_state0(state_table_t *st, struct iphdr *ih, int len, int dir)
{
   int i, j, hlen;

   // safety check
   if (len < sizeof(*ih))
   {
      log_msg(LOG_DEBUG, "packet too short for IP");
      return -1;
   }

   if (ih->version != 4)
   {
      log_msg(LOG_DEBUG, "doesn't seem to by IPv4");
      return -1;
   }

   hlen = ih->ihl * 4;
   if (hlen < 20)
   {
      log_msg(LOG_DEBUG, "too short for IPv4 header");
      return -1;
   }

   if (len < hlen + 4)
   {
      log_msg(LOG_DEBUG, "too few bytes for payload");
      return -1;
   }

   for (i = 0, j = st->num; i < st->size && j; i++, j--)
   {
      // ignore empty entries
      if (!st->state[i].family)
         continue;

      // ignore other address families
      if (st->state[i].family != AF_INET)
         continue;

      // ignore other l4 protocols
      if (ih->protocol != st->state[i].proto)
         continue;

      // ignore if ip addresses do not match
      if (dir == OUTGOING)
      {
         if (ih->saddr != st->state[i].src.sin_addr.s_addr || ih->daddr != st->state[i].dst.sin_addr.s_addr)
            continue;
      }
      else
      {
         if (ih->daddr != st->state[i].src.sin_addr.s_addr || ih->saddr != st->state[i].dst.sin_addr.s_addr)
            continue;
      }

      switch (ih->protocol)
      {
         case IPPROTO_UDP:
         case IPPROTO_TCP:
            if (dir == OUTGOING)
            {
               if (get_u16((char*) ih + hlen) == st->state[i].src.sin_port && get_u16((char*) ih + hlen + 2) == st->state[i].dst.sin_port)
                  return i;
            }
            else
            {
               if (get_u16((char*) ih + hlen + 2) == st->state[i].src.sin_port && get_u16((char*) ih + hlen) == st->state[i].dst.sin_port)
                  return i;
            }
            break;

         case IPPROTO_ICMP:
            if (dir == OUTGOING)
            {
               if (get_u16((char*) ih + hlen + 4) == st->state[i].dst.sin_port)
                  return i;
            }
            else
            {
               if (get_u16((char*) ih + hlen + 4) == st->state[i].dst.sin_port)
                  return i;
            }
            break;

         default:
            log_msg(LOG_DEBUG, "protocol %d not implemented for state table", ih->protocol);
            return -1;
      }
   }

   return st->size;
}


int has_ipv6_state0(state_table_t *st, struct ip6_hdr *ih, int len, int dir)
{
   int i, j;

   // check minimum length
   if (len < sizeof(*ih) + 4)
   {
      log_msg(LOG_DEBUG, "packet too short for IPv6");
      return -1;
   }

   if ((ih->ip6_vfc & 0xf0) != 0x60)
   {
      log_msg(LOG_DEBUG, "doesn't seem to by IPv6");
      return -1;
   }

   for (i = 0, j = st->num; i < st->size && j; i++, j--)
   {
      // ignore empty entries
      if (!st->state[i].family)
         continue;

      // ignore other address families
      if (st->state[i].family != AF_INET6)
         continue;

      // ignore other l4 protocols
      if (ih->ip6_nxt != st->state[i].proto)
         continue;

      // ignore if ip addresses do not match
      if (dir == OUTGOING)
      {
         if (!IN6_ARE_ADDR_EQUAL(&ih->ip6_src, &st->state[i].src6.sin6_addr) || !IN6_ARE_ADDR_EQUAL(&ih->ip6_dst, &st->state[i].dst6.sin6_addr))
            continue;
      }
      else
      {
         if (!IN6_ARE_ADDR_EQUAL(&ih->ip6_dst, &st->state[i].src6.sin6_addr) || !IN6_ARE_ADDR_EQUAL(&ih->ip6_src, &st->state[i].dst6.sin6_addr))
            continue;
      }

      switch (ih->ip6_nxt)
      {
         // ignore if ports do not match
         case IPPROTO_UDP:
         case IPPROTO_TCP:
            if (dir == OUTGOING)
            {
               if (get_u16(ih + 1) == st->state[i].src6.sin6_port && get_u16((char*) (ih + 1) + 2) == st->state[i].dst6.sin6_port)
                  return i;
            }
            else
            {
               if (get_u16(ih + 1) == st->state[i].dst6.sin6_port && get_u16((char*) (ih + 1) + 2) == st->state[i].src6.sin6_port)
                  return i;
            }
            continue;

         default:
            log_msg(LOG_DEBUG, "protocol %d not implemented for state table", ih->ip6_nxt);
            return -1;
      }
   }

   return st->size;
}


int has_state0(state_table_t *st, struct ether_header *eh, int len, int dir)
{
   switch (ntohs(eh->ether_type))
   {
      case ETHERTYPE_IP:
         return has_ip_state0(st, (struct iphdr*) (eh + 1), len - sizeof(*eh), dir);

      case ETHERTYPE_IPV6:
         return has_ipv6_state0(st, (struct ip6_hdr*) (eh + 1), len - sizeof(*eh), dir);
   }

   return -1;
}


int has_state(state_table_t *st, struct ether_header *eh, int len, int dir)
{
   int res;

   pthread_mutex_lock(&st->mutex);
   res = has_state0(st, eh, len, dir);
   pthread_mutex_unlock(&st->mutex);
   return res;
}


int add_ip_state0(state_t *st, struct iphdr *ih, int len)
{
   int hlen = ih->ihl * 4;

   switch (ih->protocol)
   {
      case IPPROTO_UDP:
      case IPPROTO_TCP:
         st->src.sin_port = get_u16((char*) ih + hlen);
         st->dst.sin_port = get_u16((char*) ih + hlen + 2);
         break;

      case IPPROTO_ICMP:
         st->dst.sin_port = get_u16((char*) ih + hlen + 4);
         st->src.sin_port = 0;
         break;

      default:
         return -ih->protocol;
   }

   st->family = AF_INET;
   st->proto = ih->protocol;
   st->src.sin_addr.s_addr = ih->saddr;
   st->dst.sin_addr.s_addr = ih->daddr;

   return st->proto;
}


int add_ipv6_state0(state_t *st, struct ip6_hdr *ih, int len)
{
   if (/*ih->ip6_nxt != IPPROTO_ICMP ||*/ ih->ip6_nxt != IPPROTO_UDP || ih->ip6_nxt != IPPROTO_TCP)
      return -ih->ip6_nxt;

   st->family = AF_INET6;
   st->proto = ih->ip6_nxt;
   IN6_ADDR_COPY(&st->src6.sin6_addr, &ih->ip6_src);
   IN6_ADDR_COPY(&st->dst6.sin6_addr, &ih->ip6_dst);
   st->src6.sin6_port = get_u16(ih + 1);
   st->dst6.sin6_port = get_u16((char*) (ih + 1) + 2);

   return st->proto;
}


int update_state0(state_table_t *st, struct ether_header *eh, int len, int dir, int add)
{
   int i, res;

   // check if state exists
   if ((i = has_state0(st, eh, len, dir)) < 0)
      // return in case if ill-formed packed
      return i;

   // if no state does yet exist, get empty entry
   if (i >= st->size)
   {
      if (!add)
         return -1;

      if ((i = get_unused_state0(st)) >= st->size)
      {
         log_msg(LOG_ERR, "state table full");
         return -1;
      }
      if (eh->ether_type == htons(ETHERTYPE_IP))
         res = add_ip_state0(&st->state[i], (struct iphdr*) (eh + 1), len - sizeof(*eh));
      else if (eh->ether_type == htons(ETHERTYPE_IPV6))
         res = add_ipv6_state0(&st->state[i], (struct ip6_hdr*) (eh + 1), len - sizeof(*eh));
      // this should never happen...
      else
         return -1;

      if (res <= 0)
      {
         log_msg(LOG_WARNING, "l4 protocol %d not supported", -res);
         return -1;
      }

      log_msg(LOG_INFO, "adding state: i = %d, type = 0x%04x, protocol = %d", i, ntohs(eh->ether_type), res);
      st->num++;
   }

   // update timestamp
   st->state[i].age = time(NULL);
   return i;
}


int update_state_if_exists(state_table_t *st, struct ether_header *eh, int len, int dir)
{
   int res;

   pthread_mutex_lock(&st->mutex);
   res = update_state0(st, eh, len, dir, 0);
   pthread_mutex_unlock(&st->mutex);
   return res;
}


int update_state(state_table_t *st, struct ether_header *eh, int len, int dir)
{
   int res;

   pthread_mutex_lock(&st->mutex);
   res = update_state0(st, eh, len, dir, 1);
   pthread_mutex_unlock(&st->mutex);
   return res;
}


void cleanup_states(state_table_t *st)
{
   time_t t = time(NULL);
   int i, j;

   pthread_mutex_lock(&st->mutex);

   for (i = 0, j = 0; i < st->size && j < st->num; i++)
   {
      if (!st->state[i].family)
         continue;

      j++;
      if (st->state[i].age + MAX_STATE_AGE < t)
      {
         log_msg(LOG_INFO, "deleting state");
         st->state[i].family = 0;
         st->num--;
      }
   }

   pthread_mutex_unlock(&st->mutex);
}


int snprint_states(state_table_t *st, char *buf, int len)
{
   int i, j, wlen, tlen = 0;
   int sport, dport;
   char *saddr, *daddr, saddrs[64], daddrs[64];

   if (len > 0)
      *buf = '\0';

   pthread_mutex_lock(&st->mutex);

   for (i = 0, j = 0; i < st->size && j < st->num && len > 0; i++)
   {
      if (!st->state[i].family)
         continue;

      j++;

      if (st->state[i].family == AF_INET)
      {
         sport = ntohs(st->state[i].src.sin_port);
         dport = ntohs(st->state[i].dst.sin_port);
         saddr = (char*) &st->state[i].src.sin_addr;
         daddr = (char*) &st->state[i].dst.sin_addr;
      }
      else if (st->state[i].family == AF_INET6)
      {
         sport = ntohs(st->state[i].src6.sin6_port);
         dport = ntohs(st->state[i].dst6.sin6_port);
         saddr = (char*) &st->state[i].src6.sin6_addr;
         daddr = (char*) &st->state[i].dst6.sin6_addr;
      }
      else
      {
         log_msg(LOG_ERR, "unknown address family in state table");
         continue;
      }

      addr_ntop(st->state[i].family, saddr, saddrs, sizeof(saddrs));
      addr_ntop(st->state[i].family, daddr, daddrs, sizeof(daddrs));

      wlen = snprintf(buf, len, "%d: %d %s %d %s %d %ld\n", i, st->state[i].proto, saddrs, sport, daddrs, dport, time(NULL) - st->state[i].age);
      len -= wlen;
      buf += wlen;
      tlen += wlen;
   }

   pthread_mutex_unlock(&st->mutex);

   return tlen;
}


