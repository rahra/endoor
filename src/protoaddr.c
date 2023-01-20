/* Copyright 2022-2023 Bernhard R. Fischer.
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
 *  \date 2023/01/20
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
#include "estring.h"

static int max_age_ = MAX_AGE;
static pthread_mutex_t mutex_ = PTHREAD_MUTEX_INITIALIZER;


/*! Set the maximum age of the entries in the address table.
 * @param age Maximum age in seconds. 0 means infinite age. Negative values are
 * ignored.
 * @return The function returns the age which was previously set. If age was
 * set to a negative value it will return the current value without changing
 * it.
 */
int set_max_age(int age)
{
   pthread_mutex_lock(&mutex_);
   int m = max_age_;
   if (age >= 0)
      max_age_ = age;
   pthread_mutex_unlock(&mutex_);
   return m;
}


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


int test_proto_addr(const proto_addr_t *src, void *dst0)
{
   proto_addr_t *dst = dst0;

   if ((src->flags & dst->flags) == dst->flags && src->family == dst->family && src->hits > dst->hits)
   {
      memcpy(dst->addr, src->addr, addr_size(src->family));
      dst->hits = src->hits;
      return 0;
   }
   return -1;
}


int test_ipv4_client(const proto_addr_t *src, void *dst0)
{
   proto_addr_t *dst = dst0;
   proto_addr_t dst1 = *dst;

   if (test_proto_addr(src, &dst1) == -1)
      return -1;

   // ignore source 0.0.0.0
   if (!*((uint32_t*) dst1.addr))
   {
      log_msg(LOG_INFO, "ignoring source 0.0.0.0");
      return -1;
   }

   // ignore 169.254.0.0/16
   if ((ntohl(*((uint32_t*) dst1.addr)) & 0xffff0000) == 0xa9fe0000)
   {
      log_msg(LOG_INFO, "ignoring source 169.254.x.x");
      return -1;
   }

   memcpy(dst->addr, dst1.addr, addr_size(dst1.family));
   dst->hits = dst1.hits;
   return 0;
}


/*! This function iterates over all entries in a protocol address list pa and
 * calls query() for each element.
 * @return The function returns the index to an element if an entry was found
 * by query. This index is 0 <= index < pa->size. If no entry was found
 * pa->size is returned.
 */
int pa_iterate(proto_addr_t *pa, int (*query)(const proto_addr_t *, void*), void *p)
{
   int i, j, res, i0 = pa->size;

   for (i = 0, j = 0; i < pa->size && j < pa->cnt; i++)
   {
      // ignore empty entries
      if (!pa->list[i].family)
         continue;

      j++;
      if ((res = query(&pa->list[i], p)) >= 0)
         i0 = i, i = pa->size;
   }
   return i0;
}


#define MIN_HITS 100
int search_router(proto_addr_t *pa, char *addr)
{
   proto_addr_t dst;
   int res;

   memset(&dst, 0, sizeof(dst));
   dst.family = AF_PACKET;
   dst.flags = PA_ROUTER;

   pthread_mutex_lock(&pa->mutex);
   if ((res = pa_iterate(pa, test_proto_addr, &dst)) >= pa->size)
   {
      dst.flags = 0;
      res = pa_iterate(pa, test_proto_addr, &dst);
   }
   pthread_mutex_unlock(&pa->mutex);

   if (res >= pa->size || dst.hits < MIN_HITS)
      return pa->size;

   HWADDR_COPY(addr, dst.addr);
   return res;
}


int search_client(proto_addr_t *pa, char *hwaddr, char *addr)
{
   proto_addr_t dst;
   int res;

   memset(&dst, 0, sizeof(dst));
   dst.family = AF_PACKET;
   //dst.flags = PA_CLIENT;

   pthread_mutex_lock(&pa->mutex);
   if ((res = pa_iterate(pa, test_proto_addr, &dst)) < pa->size)
   {
      HWADDR_COPY(hwaddr, dst.addr);
      dst.family = AF_INET;
      dst.hits = 0;
      if ((res = pa_iterate(&pa->list[res], test_ipv4_client, &dst)) < pa->size)
         memcpy(addr, dst.addr, addr_size(dst.family));
   }
   pthread_mutex_unlock(&pa->mutex);

   return res;
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
      if (!max_age_ || pa->list[i].age + max_age_ > t)
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

