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

/*! \file protoaddr.c
 * This file contains the code for managing the protocol address lists (mac
 * address table).
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2022/09/13
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_ETHER_H
#include <netinet/ether.h>
#endif

#include "protoaddr.h"
#include "log.h"


/*! Init an allocate memory for a protocol address list of n available protocol
 * addresses.
 * @param pa Pointer to empty protocol address struct.
 * @param n Number of elements that should be allocated.
 * @return On success, 0 is returned. In case of error, -1 is returned.
 */
int init_pa_list(proto_addr_t *pa, int n)
{
   memset(pa, 0, sizeof(*pa));
   if ((pa->list = calloc(n, sizeof(*pa))) == NULL)
   {
      log_msg(LOG_ERR, "calloc() failed: %s", strerror(errno));
      return -1;
   }

   pa->size = n;
   return 0;
}


/*! This function initializes and allocates memory for a mac address table of n
 * entries, each allowing m protocol addresses to be stored.
 * @param pa Pointer to empty protocol address struct.
 * @param n Number of elements that should be allocated for ethernet addresses.
 * @param m Number of protocol address entries (IP/IPV6) that each ethernet
 * address can be associated with.
 * @return On success, 0 is returned. In case of error, -1 is returned.
 */
int init_mac_table(proto_addr_t *pa, int n, int m)
{
   if (init_pa_list(pa, n) == -1)
      return -1;
   for (int i = 0; i < n; i++)
      if (init_pa_list(&pa->list[i], m) == -1)
         return -1;
   return 0;
}


/*! Return the memory size of a network address depending on the address
 * family.
 * @param family Adress family (AF_INET, AF_INET6, AF_PACKET).
 * @return Returns the number of bytes which an address of the address family
 * takes in memory. If the address family is unknown, 0 is returned.
 */
int addr_size(int family)
{
   switch (family)
   {
      case AF_INET:
         return 4;

      case AF_INET6:
         return 16;

      case AF_PACKET:
         return 6;

      default:
         return 0;
   }
}


/*! Get an empty index in a protocol address list.
 * @param pa Pointer to protocol address list.
 * @return The function returns a valid index which is 0 <= index < pa->size.
 * If no empty index is available, pa->size is returned.
 */
int get_empty_index(const proto_addr_t *pa)
{
   int i;
   for (i = 0; i < pa->size && pa->list[i].family; i++);
   return i;
}


/*! Get the index of an address in the protocol address list pa.
 * @param pa Pointer to protocol address list.
 * @param family Address family of address.
 * @param addr Pointer to address.
 * @return The function returns a valid index which is 0 <= index < pa->size.
 * If the address was not found, pa->size is returned.
 */
int get_addr_index(const proto_addr_t *pa, int family, const char *addr)
{
   int i, j;

   for (i = 0, j = 0; j < pa->cnt && i < pa->size; i++)
   {
      if (!pa->list[i].family)
         continue;
      j++;
      if (pa->list[i].family == family && !memcmp(pa->list[i].addr, addr, addr_size(family)))
         return i;
   }
   return pa->size;
}


/*! This function updates an entry in the protocol address list. If no entry is
 * available yet, a new entry is created.
 * @param pa Pointer to protocol address list.
 * @param family Address family of address.
 * @param addr Pointer to address.
 * @param flags Flags which are associated with this address (e.g. PA_ROUTER).
 * @return The function returns a valid index which is 0 <= index < pa->size.
 * If the address table is full and the address could not be added, -1 is
 * returned.
 */
int update_entry(proto_addr_t *pa, int family, const char *addr, int flags)
{
   int i;

   if ((i = get_addr_index(pa, family, addr)) >= pa->size)
   {
      if ((i = get_empty_index(pa)) >= pa->size)
      {
         log_msg(LOG_ERR, "protocol address list full");
         return -1;
      }
      pa->list[i].family = family;
      memcpy(pa->list[i].addr, addr, addr_size(family));
      pa->cnt++;

      char as[64];
      addr_ntop(family, addr, as, sizeof(as));
      log_msg(LOG_DEBUG, "adding address entry %s", as);
   }
   pa->list[i].age = time(NULL);
   pa->list[i].hits++;
   pa->list[i].flags |= flags;

   return i;
}


/*! This function updates the mac address table with the address pair hwaddr/addr.
 * @param pa Pointer to protocol address list.
 * @param hwaddr Ethernet address.
 * @param family Address family of protocol address.
 * @param addr Pointer to protocol address.
 * @param flags Flags which are associated with this address (e.g. PA_ROUTER).
 * @return The function returns a valid index which is 0 <= index < pa->size.
 * If the address table is full and the address could not be added, -1 is
 * returned.
 */
int update_table(proto_addr_t *pa, const char *hwaddr, int family, const char *addr, int flags)
{
   int i;

   pthread_mutex_lock(&pa->mutex);
   if ((i = update_entry(pa, AF_PACKET, hwaddr, flags)) == -1)
      goto ut_exit;

   if (family != AF_PACKET)
      if ((i = update_entry(&pa->list[i], family, addr, flags)) == -1)
         goto ut_exit;

   ut_exit:
   pthread_mutex_unlock(&pa->mutex);
   return i;
}


#define MIN_HITS 100
int search_router(proto_addr_t *pa, char *addr)
{
   int i, j, im, ir;
   unsigned int max = 0, rmax = 0;

   pthread_mutex_lock(&pa->mutex);
   for (i = 0, j = 0; i < pa->size && j < pa->cnt; i++)
   {
      // ignore empty entries
      if (!pa->list[i].family)
         continue;
      j++;

      if (pa->list[i].flags & PA_ROUTER)
      {
         if (pa->list[i].hits > rmax)
         {
            rmax = pa->list[i].hits;
            ir = i;
         }
      }
      else
      {
         if (pa->list[i].hits > max)
         {
            max = pa->list[i].hits;
            im = i;
         }
      }
   }

   i = 0;
   if (rmax)
   {
      if (rmax > MIN_HITS)
      {
         HWADDR_COPY(addr, pa->list[ir].addr);
         i = 1;
      }
   }
   else if (max)
   {
      if (max > MIN_HITS)
      {
         HWADDR_COPY(addr, pa->list[im].addr);
         i = 1;
      }
   }

   pthread_mutex_unlock(&pa->mutex);

   return i;
}


int search_client0(proto_addr_t *pa, char *addr)
{
   int i, j;

   for (i = 0, j = 0; i < pa->size && j < pa->cnt; i++)
   {
      // ignore empty entries
      if (!pa->list[i].family)
         continue;
      j++;

      if (pa->list[i].flags & PA_CLIENT)
      {
         memcpy(addr, pa->list[i].addr, addr_size(pa->list[i].family));
         return i;
      }
   }
   return pa->size;
}


int search_client(proto_addr_t *pa, char *hwaddr, char *addr)
{
   int i, j;

   pthread_mutex_lock(&pa->mutex);
   if ((i = search_client0(pa, hwaddr)) >= pa->size)
      goto sc_exit;

   j = i;
   if ((i = search_client0(&pa->list[i], addr)) >= pa->size)
      goto sc_exit;

   if (pa->list[j].list[i].family != AF_INET)
      i = pa->size;

sc_exit:
   pthread_mutex_unlock(&pa->mutex);
   return i;
}


/*! This function recursively removes all entries from the protocol address
 * list if the entries are older than MAX_AGE seconds.
 * @param pa Pointer to protocol address list.
 */
void pa_cleanup0(proto_addr_t *pa)
{
   char addr[64];
   time_t t = time(NULL);
   int i, j;

   for (i = 0, j = 0; i < pa->size && j < pa->cnt; i++)
   {
      // ignore empty entries
      if (!pa->list[i].family)
         continue;
      j++;

      // recursively clean sub-entries
      if (pa->list[i].cnt)
         pa_cleanup0(&pa->list[i]);

      // do not remove this entry if there are still sub-entries
      if (pa->list[i].cnt)
         continue;
 
      // ignore young entries
      if (pa->list[i].age + MAX_AGE > t)
         continue;

      addr_ntop(pa->list[i].family, pa->list[i].addr, addr, sizeof(addr));
      log_msg(LOG_DEBUG, "deleting address %s", addr);
      pa->list[i].family = 0;
      pa->cnt--;
   }
}


/*! Clean mac address table of old entries. This function is thread-safe.
 * @param pa Pointer to protocol address list.
 */
void pa_cleanup(proto_addr_t *pa)
{
   pthread_mutex_lock(&pa->mutex);
   pa_cleanup0(pa);
   pthread_mutex_unlock(&pa->mutex);
}


/*! Convert a network address of type family to a character string. This
 * function is similar to inet_ntop(3) but can also convert ethernet addresses
 * (AF_PACKET).
 * @param family Adress family (AF_INET, AF_INET6, AD_PACKET).
 * @param src Pointer to network address.
 * @param dst Pointer to destination buffer.
 * @param len Length of destination buffer.
 * @return The function returns the length of the converted string. In case of
 * error, -1 is returned.
 */
int addr_ntop(int family, const char *src, char *dst, int len)
{
   if (src == NULL || dst == NULL || len <= 0)
      return -1;

   switch (family)
   {
      case AF_INET:
      case AF_INET6:
         if (inet_ntop(family, src, dst, len) == NULL)
         {
            log_msg(LOG_ERR, "inet_ntop(): %s", strerror(errno));
            *dst = '\0';
         }
         break;

      case AF_PACKET:
         if (len >= 19)
         {
            ether_ntoa_r((struct ether_addr*) src, dst);
         }
         else
         {
            log_msg(LOG_ERR, "buffer too small for ether_ntoa_r()");
            *dst = '\0';
         }
         break;

      default:
         *dst = '\0';
   }

   return strlen(dst);
}


int snprint_proto_addr(char *buf, int len, const proto_addr_t *pa)
{
   char addr[64];

   addr_ntop(pa->family, pa->addr, addr, sizeof(addr));
   return snprintf(buf, len, "family = %d, addr = \"%s\", age = %ld, hits = %d, flags = %d, count = %d\n", pa->family, addr, time(NULL) - pa->age, pa->hits, pa->flags, pa->cnt);
}


static int bs(char *buf, int len, int n)
{
   int i;

   len--;
   for (i = 0; i < n && len > 0; i++, buf++, len--)
      *buf = ' ';
   *buf = '\0';

   return n;
}


int snprint_palist(char *buf, int len, const proto_addr_t *pa, int indent)
{
   int i, j, wlen, tlen = 0;

   if (len > 0)
      *buf = '\0';

   for (i = 0, j = 0; i < pa->size && j < pa->cnt; i++)
   {
      if (!pa->list[i].family)
         continue;

      wlen = bs(buf, len, indent);
      buf += wlen;
      len -= wlen;
      tlen += wlen;

      wlen = snprint_proto_addr(buf, len, &pa->list[i]);
      buf += wlen;
      len -= wlen;
      tlen += wlen;

      if (pa->list[i].cnt)
      {
         wlen = snprint_palist(buf, len, &pa->list[i], indent + 3);
         buf += wlen;
         len -= wlen;
         tlen += wlen;
      }
   }

   return tlen;
}


int snprint_mac_table(char *buf, int len, proto_addr_t *pa)
{
   int i;

   pthread_mutex_lock(&pa->mutex);
   i = snprint_palist(buf, len, pa, 0);
   pthread_mutex_unlock(&pa->mutex);
   return i;
}


