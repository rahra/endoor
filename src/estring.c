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

/*! \file estring.c
 * This file contains various string functions for the output of information to
 * the CLI.
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2022/09/19
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
#include "state.h"
#include "json.h"


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

   for (i = 0, j = 0; i < pa->size && j < pa->cnt && len > 0; i++)
   {
      if (!pa->list[i].family)
         continue;

      wlen = bs(buf, len, indent);
      buf += wlen;
      len -= wlen;
      tlen += wlen;

      if ((wlen = snprint_proto_addr(buf, len, &pa->list[i])) >= len)
         wlen = len;
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


static int fprintj_palist0(FILE *f, const proto_addr_t *pa, int indent)
{
   int i, j, tlen = 0;
   char addr[128];

   if (pa->cnt <= 0)
      return 0;

   flabel(f, "addresses", indent);
   //findent(f, indent);
   fochar(f, '[');
   for (i = 0, j = 0; i < pa->size && j < pa->cnt; i++)
   {
      if (!pa->list[i].family)
         continue;

      addr_ntop(pa->list[i].family, pa->list[i].addr, addr, sizeof(addr));
      findent(f, indent);
      fochar(f, '{');
      fint(f, "type", pa->list[i].family, indent + 1);
      fstring(f, "addr", addr, indent + 1);
      fint(f, "time", pa->list[i].age, indent + 1);

      if (pa->list[i].cnt)
      {
         //fochar(f, '[');
         fprintj_palist0(f, &pa->list[i], indent + 1);
         //funsep(f);
         //fcchar(f, ']');
      }
      funsep(f);
      findent(f, indent);
      fcchar(f, '}');
   }
   funsep(f);
   findent(f, indent);
   fcchar(f, ']');

   return tlen;
}


int fprintj_palist(FILE *f, proto_addr_t *pa, int indent)
{
   pthread_mutex_lock(&pa->mutex);
   int tlen = fprintj_palist0(f, pa, indent);
   pthread_mutex_unlock(&pa->mutex);
   return tlen;
}


static int jpalist0(json_t *J, const proto_addr_t *pa, int indent)
{
   int i, j, tlen = 0;
   char addr[128];

   if (pa->cnt <= 0)
      return 0;

   jlabel(J, "addresses", indent);
   //findent(f, indent);
   jochar(J, '[');
   for (i = 0, j = 0; i < pa->size && j < pa->cnt; i++)
   {
      if (!pa->list[i].family)
         continue;

      addr_ntop(pa->list[i].family, pa->list[i].addr, addr, sizeof(addr));
      jindent(J, indent);
      jochar(J, '{');
      jint(J, "type", pa->list[i].family, indent + 1);
      jstring(J, "addr", addr, indent + 1);
      jint(J, "time", pa->list[i].age, indent + 1);

      if (pa->list[i].cnt)
      {
         //fochar(f, '[');
         jpalist0(J, &pa->list[i], indent + 1);
         //funsep(f);
         //fcchar(f, ']');
      }
      junsep(J);
      jindent(J, indent);
      jcchar(J, '}');
   }
   junsep(J);
   jindent(J, indent);
   jcchar(J, ']');

   return tlen;
}


int jpalist(json_t *J, proto_addr_t *pa, int indent)
{
   pthread_mutex_lock(&pa->mutex);
   int tlen = jpalist0(J, pa, indent);
   pthread_mutex_unlock(&pa->mutex);
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

      if ((wlen = snprintf(buf, len, "%d: %d %s %d %s %d %ld\n", i, st->state[i].proto, saddrs, sport, daddrs, dport, time(NULL) - st->state[i].age)) >= len)
         wlen = len;
      len -= wlen;
      buf += wlen;
      tlen += wlen;
   }

   pthread_mutex_unlock(&st->mutex);

   return tlen;
}

