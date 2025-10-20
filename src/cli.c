/* Copyright 2022-2025 Bernhard R. Fischer.
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
 *  \date 2025/07/06
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
#include "json.h"
#include "cli.h"

#define SNAPLEN 4096


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


int set_hwrouter(if_info_t *ii, const char *s)
{
   int ret = -1;

   pthread_mutex_lock(&ii->mutex);
   if (ether_aton_r(s, (struct ether_addr*) ii->hwrouter) != NULL)
      ii->router_valid = 2, ret = 0;
   pthread_mutex_unlock(&ii->mutex);

   return ret;
}


static void j_if_info(FILE *f, if_info_t *ii, int indent)
{
   char hwaddr[32], hwclient[32], hwrouter[32];

   ether_ntoa_rz((struct ether_addr*) ii->hwaddr, hwaddr);
   pthread_mutex_lock(&ii->mutex);
   ether_ntoa_rz((struct ether_addr*) ii->hwclient, hwclient);
   ether_ntoa_rz((struct ether_addr*) ii->hwrouter, hwrouter);
   pthread_mutex_unlock(&ii->mutex);

   findent(f, indent);
   fochar(f, '{');
   fstring(f, "ifname", ii->ifname, indent + 1);
   fstring(f, "gate", ii->gate != NULL ? ii->gate->ifname : "NULL", indent + 1);
   fstring(f, "hwaddr", hwaddr, indent + 1);
   fstring(f, "hwclient", hwclient, indent + 1);
   fstring(f, "hwrouter", hwrouter, indent + 1);
   fprintj_palist(f, &ii->mtbl, indent + 1);
   funsep(f);
   findent(f, indent);
   fcchar(f, '}');
   //funsep(f);
}


static void j_dump(FILE *f, if_info_t *ii, int n)
{
   int i;

   fochar(f, '{');
   flabel(f, "interfaces", 1);
   fochar(f, '[');
   for (i = 0; i < n; i++)
      j_if_info(f, &ii[i], 1);
   funsep(f);
   findent(f, 1);
   fcchar(f, ']');
   funsep(f);
   fcchar(f, '}');
   funsep(f);
}


static void print_if_info(FILE *f, if_info_t *ii)
{
   char hwaddr[32], hwclient[32], hwrouter[32];

   ether_ntoa_rz((struct ether_addr*) ii->hwaddr, hwaddr);
   pthread_mutex_lock(&ii->mutex);
   ether_ntoa_rz((struct ether_addr*) ii->hwclient, hwclient);
   ether_ntoa_rz((struct ether_addr*) ii->hwrouter, hwrouter);
   pthread_mutex_unlock(&ii->mutex);

   fprintf(f, 
         "===== %s =====\n"
         "fd = %d\n"
         "wfd = %d\n"
         "filter = 0x%p\n"
         "out = %s\n"
         "gate = %s\n"
         "off = %d\n"
         "hwaddr = %s\n"
         "hwclient = %s\n"
         "hwrouter = %s\n\n"
         ,
         ii->ifname, ii->fd, ii->wfd, ii->filter, ii->out->ifname, ii->gate != NULL ? ii->gate->ifname : "NULL", ii->off, hwaddr, hwclient, hwrouter);
}


static void cli_help(FILE *f)
{
   fprintf(f,
         "addr ......... List address tables.\n"
         "debug ........ Set debug level to DEBUG (7).\n"
         "dump ......... Dump address database to 'dump.json'.\n"
         "exit ......... Exit program.\n"
         "expire <sec> . Expire all addresses older than <sec> seconds.\n"
         "info ......... Show interface info.\n"
         "nodebug ...... Set debug level to INFO (6).\n"
         "router <hw> .. Set router hardware address.\n"
         "state ........ Show state table.\n"
         );
}


/*! This function parses the arguments in string s delemited by one of " \r\n"
 * into the array argv. The last entry in argv is set to NULL.
 * @param s Source string to parse.
 * @param argv Array to receive pointers to each element.
 * @param size Number of elements available in argv.
 * @return Returns the number of arguments (argc) parsed into argv not counting
 * the last NULL element, which is 0 <= argc < size.
 */
int parse_cmd0(char *s, char **argv, int size, const char *sep)
{
   char *r;
   int c = 0;

   s = strtok_r(s, sep, &r);
   for (; s != NULL && c < size - 1; c++, argv++)
   {
      *argv = s;
      s = strtok_r(NULL, sep, &r);
   }

   if (c < size)
      *argv = NULL;

   return c;
}


int parse_cmd(char *s, char **argv, int size)
{
   return parse_cmd0(s, argv, size, " \r\n");
}


void cli(FILE *f0, FILE *f, if_info_t *ii, int n)
{
   int running, i;
   char buf[256 * 1024];
   char *argv[MAX_ARGS];
   int argc;

   fprintf(f, "Welcome to %s!\n", PACKAGE_STRING);
   for (running = 1; running;)
   {
      fprintf(f, "endoor# ");
      if (fgets(buf, sizeof(buf), f0) == NULL)
         break;

      if (!(argc = parse_cmd(buf, argv, MAX_ARGS)))
         continue;

      if (!strcmp(argv[0], "exit"))
         running = 0;
      else if (!strcmp(argv[0], "debug"))
         debug_level_ = 7;
      else if (!strcmp(argv[0], "nodebug"))
         debug_level_ = 6;
      else if (!strcmp(argv[0], "help"))
         cli_help(f);
      else if (!strcmp(argv[0], "addr"))
      {
         for (i = 0; i < n; i++)
         {
            snprint_mac_table(buf, sizeof(buf), &ii[i].mtbl);
            fprintf(f, "===== %s =====\n%s\n", ii[i].ifname, buf);
         }
      }
      else if (!strcmp(argv[0], "info"))
      {
         for (i = 0; i < n; i++)
            print_if_info(f, &ii[i]);
      }
      else if (!strcmp(argv[0], "router"))
      {
         if (argc > 1)
         {
            if (set_hwrouter(&ii[1], argv[1]) == -1)
               fprintf(f, "ill hwaddr: \"%s\"\n", argv[1]);
         }
         else
            fprintf(f, "need hw address\n");
      }
      else if (!strcmp(argv[0], "state"))
      {
         snprint_states(ii[2].st, buf, sizeof(buf));
         fprintf(f, "%s\n", buf);
      }
      else if (!strcmp(argv[0], "dump"))
      {
         FILE *fout;

         if ((fout = fopen("dump.json", "w")) != NULL)
         {
            j_dump(fout, ii, 3);
            fclose(fout);
         }
         else
            fprintf(f, "failed to open file\n");
      }
      else if (!strcmp(argv[0], "expire"))
      {
         if (argc > 1)
         {
            int max_age = atoi(argv[1]);
            for (int i = 0; i < 3; i++)
               pa_cleanup(&ii[i].mtbl, max_age);
         }
         else
            fprintf(f, "need expiry seconds\n");
      }
      else
      {
         fprintf(f, "*** unknown command <%s>\n", argv[0]);
      }
   }
   fprintf(f, "Good bye!\n");
}

