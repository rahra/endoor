
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include "protoaddr.h"
#include "log.h"


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


int init_mac_table(proto_addr_t *pa, int n, int m)
{
   if (init_pa_list(pa, n) == -1)
      return -1;
   for (int i = 0; i < n; i++)
      if (init_pa_list(&pa->list[i], m) == -1)
         return -1;
   return 0;
}


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


int get_empty_index(const proto_addr_t *pa)
{
   int i;
   for (i = 0; i < pa->size && pa->list[i].family; i++);
   return i;
}


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
   return -1;
}


int update_entry(proto_addr_t *pa, int family, const char *addr, int flags)
{
   int i;

   if ((i = get_addr_index(pa, family, addr)) == -1)
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
   int i, j, max = 0, im, rmax = 0, ir;

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

      if (pa->list[i].cnt)
         pa_cleanup0(&pa->list[i]);
 
      // ignore young entries
      if (pa->list[i].age + MAX_AGE > t)
         continue;

      addr_ntop(pa->list[i].family, pa->list[i].addr, addr, sizeof(addr));
      log_msg(LOG_DEBUG, "deleting address %s", addr);
      pa->list[i].family = 0;
      pa->cnt--;
   }
}


void pa_cleanup(proto_addr_t *pa)
{
   pthread_mutex_lock(&pa->mutex);
   pa_cleanup0(pa);
   pthread_mutex_unlock(&pa->mutex);
}


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


