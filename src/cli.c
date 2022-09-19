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

/*! \file cli.c
 * This file contains the code for the cli.
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2022/09/19
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_LINUX_IF_PACKET_H
#include <linux/if_packet.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include "endoor.h"
#include "pcap.h"
#include "log.h"
#include "bridge.h"
#include "tun.h"
#include "estring.h"

#define SNAPLEN 4096
#define MACTABLESIZE 1024
#define STATETABLESIZE 16384


int data_to_hex(char *dst, const char *buf, int buflen)
{
   const char *hex = "0123456789abcdef";
   int len;

   // safety check
   if (buflen <= 0 || buf == NULL || dst == NULL)
      return 0;

   for (len = 0; buflen > 0; buflen--, buf++, len += 3)
   {
      *dst++ = hex[(*buf) >> 4 & 0xf];
      *dst++ = hex[(*buf) & 0xf];
      *dst++ = ' ';
   }

   *--dst = '\0';
   return len;
}


void log_hex(const char *buf, int len)
{
   char s[16 * 3];

   data_to_hex(s, buf, len > 16 ? 16 : len);
   log_msg(LOG_DEBUG, "data: %s", s);
}


void print_mac_table(if_info_t *ii)
{
   char buf[4096];

   snprint_mac_table(buf, sizeof(buf), &ii->mtbl);
   printf("===== %s =====\n%s\n", ii->ifname, buf);
}


void print_if_info(if_info_t *ii)
{
   char hwaddr[32], hwclient[32], hwrouter[32];
   int valid;

   ether_ntoa_r((struct ether_addr*) ii->hwaddr, hwaddr);
   pthread_mutex_lock(&ii->mutex);
   ether_ntoa_r((struct ether_addr*) ii->hwclient, hwclient);
   ether_ntoa_r((struct ether_addr*) ii->hwrouter, hwrouter);
   valid = ii->hwclient_valid;
   pthread_mutex_unlock(&ii->mutex);

   printf(
         "===== %s =====\n"
         "fd = %d\n"
         "wfd = %d\n"
         "filter = 0x%p\n"
         "out = %s\n"
         "gate = %s\n"
         "off = %d\n"
         "hwaddr = %s\n"
         "hwclient = %s\n"
         "hwclient_valid = %d\n"
         "hwrouter = %s\n\n"
         ,
         ii->ifname, ii->fd, ii->wfd, ii->filter, ii->out->ifname, ii->gate != NULL ? ii->gate->ifname : "NULL", ii->off, hwaddr, hwclient, valid, hwrouter);
}


void cli_help(void)
{
   printf(
         "addr ......... List address tables.\n"
         "debug ........ Set debug level to DEBUG (7).\n"
         "exit ......... Exit program.\n"
         "info ......... Show interface info.\n"
         "nodebug ...... Set debug level to INFO (6).\n"
         "state ........ Show state table.\n"
         );
}


void cli(if_info_t *ii, int n)
{
   int running, i;
   char *s, *eptr;
   char buf[65536];

   printf("Welcome to %s!\n", PACKAGE_STRING);
   for (running = 1; running;)
   {
      printf("endoor# ");
      if (fgets(buf, sizeof(buf), stdin) == NULL)
         break;

      if ((s = strtok_r(buf, " \r\n", &eptr)) == NULL)
         continue;

      if (!strcmp(s, "exit"))
         running = 0;
      else if (!strcmp(s, "debug"))
         debug_level_ = 7;
      else if (!strcmp(s, "nodebug"))
         debug_level_ = 6;
      else if (!strcmp(s, "help"))
         cli_help();
      else if (!strcmp(s, "addr"))
      {
         for (i = 0; i < n; i++)
            print_mac_table(&ii[i]);
      }
      else if (!strcmp(s, "info"))
      {
         for (i = 0; i < n; i++)
            print_if_info(&ii[i]);
      }
      else if (!strcmp(s, "state"))
      {
         snprint_states(ii[2].st, buf, sizeof(buf));
         printf("%s\n", buf);
      }
   }
   printf("Good bye!\n");
}

