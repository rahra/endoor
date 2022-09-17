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

/*! \file state.c
 * This file contains to code for managing the state table.
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2022/09/13
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
#ifdef HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#include "log.h"
#include "state.h"
#include "endoor.h"
#include "protoaddr.h"


/*! Initialize and allocate memory for state table. The state table memory
 * itself (st->state) shall be freed after use again with a call to free().
 * @param st Pointer to uninitialized state table struct.
 * @param n Maximum number of state entries.
 * @return On success 0 is returned. In case of error -1 is returned.
 */
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


/*! Get index if an unused state entry.
 * @param st Pointer to state table struct.
 * @return The function returnes a integer of an empty state entry. If the
 * state table is full, st->size is returned.
 */
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
 * @param dir Direction of the frame which is either INCOMING or OUTGOING.
 * @return If the packet does not match minimum criteria, -1 is returned. If a
 * state was found, the index of the valid entry in the state table is
 * returned, which is 0 <= index < st->size. If no valid entry is found
 * st->size is returned.
 */
int has_ip_state0(state_table_t *st, struct iphdr *ih, int len, int dir)
{
   int i, j, hlen;

   // safety check
   if (len < (int) sizeof(*ih))
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
               if (*((char*) ih + hlen) != 8 || *((char*) ih + hlen + 1) != 0)
               {
                  log_msg(LOG_DEBUG, "ICMP type %d/%d not implemented", *((char*) ih + hlen), *((char*) ih + hlen + 1));
                  return -1;
               }

               if (get_u16((char*) ih + hlen + 4) == st->state[i].dst.sin_port)
                  return i;
            }
            else
            {
               if (*((char*) ih + hlen) != 0 || *((char*) ih + hlen + 1) != 0)
               {
                  log_msg(LOG_DEBUG, "ICMP type %d/%d not implemented", *((char*) ih + hlen), *((char*) ih + hlen + 1));
                  return -1;
               }

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


/*! This function works exactly in the same way has has_ip_state0() except for
 * IPV6. See there for more information.
 */
int has_ipv6_state0(state_table_t *st, struct ip6_hdr *ih, int len, int dir)
{
   int i, j;

   // check minimum length
   if (len < (int) sizeof(*ih) + 4)
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


/*! This function checks if there is a state in the state table for the frame
 * in buf.
 * @param st Pointer to state table struct.
 * @param eh Pointer to the beginning of the frame.
 * @param len Length of the frame.
 * @param dir Direction that should be considered. This is either INCOMING or
 * OUTGOING.
 * @return If a state was found, the function returns an index to the state
 * which is 0 <= index < st->state. If no valid state was found, st->size is
 * returned. In case of error, -1 is returned. Errors are unsupported ether
 * types, frames are somehow illformed (too short or somehow invalid), or the
 * layer 4 protocol is not supported.
 */
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


/*! This function is exactly the same as has_state0() but is thread safe.
 * Generally only this function should be called.
 */
int has_state(state_table_t *st, struct ether_header *eh, int len, int dir)
{
   int res;

   pthread_mutex_lock(&st->mutex);
   res = has_state0(st, eh, len, dir);
   pthread_mutex_unlock(&st->mutex);
   return res;
}


/*! Set the state st according to the packet ih of length len.
 * It must have been checked that len is long enough, i.e. at least ihl + 6
 * bytes.
 * @param st Pointer to state struct.
 * @param ih Pointer to IPV4 header.
 * @param len Length of pointed to by ih.
 * @return On success the layer 5 protocol number is returned. If the protocol
 * is not supported the protocol is returned as negativ value. If the packet
 * length is to short, 0 is returned.
 * Note: 0 will also be returned, if the protocol number is 0. This protocol is
 * not supported for IPV4.
 */
int add_ip_state0(state_t *st, struct iphdr *ih, int len)
{
   int hlen;

   // safety check
   if (len < (int) sizeof(*ih) && len < ih->ihl * 4 + 8)
   {
      log_msg(LOG_WARNING, "packet toot short for IPV4 state: %d < %d", len, ih->ihl * 4 + 8);
      return 0;
   }
   hlen = ih->ihl * 4;

   switch (ih->protocol)
   {
      case IPPROTO_UDP:
      case IPPROTO_TCP:
         st->src.sin_port = get_u16((char*) ih + hlen);
         st->dst.sin_port = get_u16((char*) ih + hlen + 2);
         break;

      case IPPROTO_ICMP:
         // check for echo request (type 8, code 0)
         if (*((char*) ih + hlen) != 8 || *((char*) ih + hlen + 1) != 0)
            return -IPPROTO_ICMP;

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


/*! This function is the IPV6 version of add_ip_state0().
 */
int add_ipv6_state0(state_t *st, struct ip6_hdr *ih, int len)
{
   // safety check
   if (len < (int) sizeof(*ih) + 8)
   {
      log_msg(LOG_WARNING, "packet toot short for IPV6 state: %d < %ld", len, sizeof(*ih) + 8);
      return 0;
   }

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


/*! This function updates an existing state. If no such state exists, a new
 * state is added if the parameter add is != 0.
 * @param st Pointer to state table struct.
 * @param eh Pointer to the frame.
 * @param len Total length of the frame.
 * @param dir Direction which should be considered. This is either INCOMING or
 * OUTGOING.
 * @param add If this is not 0, a new state is added if no suitable state
 * exists yet.
 * @return On success, the function returns the index of the state which is 0
 * <= index < st->state. If the state does not exists or could not be added, -1
 * is returned.
 */
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

      switch (ntohs(eh->ether_type))
      {
         case ETHERTYPE_IP:
            res = add_ip_state0(&st->state[i], (struct iphdr*) (eh + 1), len - sizeof(*eh));
            break;

         case ETHERTYPE_IPV6:
            res = add_ipv6_state0(&st->state[i], (struct ip6_hdr*) (eh + 1), len - sizeof(*eh));
            break;

         default:
            log_msg(LOG_EMERG, "unknown ethertype %d", ntohs(eh->ether_type));
            return -1;
      }

      if (res <= 0)
      {
         log_msg(LOG_NOTICE, "l4 protocol %d not supported", -res);
         return -1;
      }

      log_msg(LOG_DEBUG, "adding state: i = %d, type = 0x%04x, protocol = %d", i, ntohs(eh->ether_type), res);
      st->num++;
   }

   // update timestamp
   st->state[i].age = time(NULL);
   return i;
}


/*! This function updates an existing state.
 * @param st Pointer to state table struct.
 * @param eh Pointer to the frame.
 * @param len Total length of the frame.
 * @param dir Direction which should be considered. This is either INCOMING or
 * OUTGOING.
 * @return On success, the function returns the index of the state which is 0
 * <= index < st->state. If the state does not exist, -1 is returned.
 */
int update_state_if_exists(state_table_t *st, struct ether_header *eh, int len, int dir)
{
   int res;

   pthread_mutex_lock(&st->mutex);
   res = update_state0(st, eh, len, dir, 0);
   pthread_mutex_unlock(&st->mutex);
   return res;
}


/*! This function updates an existing state or adds a new state if no state
 * does yet exist.
 * @param st Pointer to state table struct.
 * @param eh Pointer to the frame.
 * @param len Total length of the frame.
 * @param dir Direction which should be considered. This is either INCOMING or
 * OUTGOING.
 * @return On success, the function returns the index of the state which is 0
 * <= index < st->state. If the state could not be added, -1 is returned.
 */
int update_state(state_table_t *st, struct ether_header *eh, int len, int dir)
{
   int res;

   pthread_mutex_lock(&st->mutex);
   res = update_state0(st, eh, len, dir, 1);
   pthread_mutex_unlock(&st->mutex);
   return res;
}


/*! This function removes all states of the state table which are older than
 * MAX_STATE_AGE (defined in state.h).
 * @param st Pointer to state table struct.
 */
void *cleanup_states(state_table_t *st)
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
         log_msg(LOG_DEBUG, "deleting state %d", i);
         st->state[i].family = 0;
         st->num--;
      }
   }

   pthread_mutex_unlock(&st->mutex);

   return NULL;
}


/*! This function prints the whole state table to the buffer buf. The function
 * always writes a \0-terminated string to buf.
 * @param st Pointer to state table struct.
 * @param buf Pointer to destination buffer.
 * @param len Length of destination buffer.
 * @return The function returns the number of bytes written to buf excluding
 * the terminating \0. Thus it a value < len is returned. If the buffer was too
 * small, len is returned. In any case buf will be \0-terminated.
 */
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
         log_msg(LOG_EMERG, "unknown address family %d in state table", st->state[i].family);
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

