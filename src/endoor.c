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

/*! \file endoor.c
 * This is the main file of endoor. it mostly contains initialization code and
 * the cli.
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2022/09/13
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
#include "thread.h"
#include "cli.h"

#define SNAPLEN 4096
#define MACTABLESIZE 1024
#define STATETABLESIZE 16384

int set_hwrouter(if_info_t *, const char *);


int init_socket(if_info_t *ii)
{
   struct sockaddr_ll sa;
   struct ifreq ifr;

   log_msg(LOG_INFO, "setting up %s", ii->ifname);
   if ((ii->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
      log_msg(LOG_ERR, "socket(): %s", strerror(errno)), exit(1);

   memset(&ifr, 0, sizeof(ifr));
   strlcpy(ifr.ifr_name, ii->ifname, sizeof(ifr.ifr_name));
   if (ioctl(ii->fd, SIOCGIFINDEX, &ifr) == -1)
      log_msg(LOG_ERR, "ioctl(SIOCGIFINDEX): %s", strerror(errno)), exit(1);

   memset(&sa, 0, sizeof(sa));
   sa.sll_family = AF_PACKET;
   sa.sll_ifindex = ifr.ifr_ifindex;
   if ((bind(ii->fd, (struct sockaddr*) &sa, sizeof(sa))) == -1)
      log_msg(LOG_ERR, "bind(): %s", strerror(errno)), exit(1);

   memset(&ifr, 0, sizeof(ifr));
   strlcpy(ifr.ifr_name, ii->ifname, sizeof(ifr.ifr_name));
   if (ioctl(ii->fd, SIOCGIFHWADDR, &ifr) == -1)
      log_msg(LOG_ERR, "ioctl(SIOCGIFHWADDR): %s", strerror(errno)), exit(1);

   HWADDR_COPY(ii->hwaddr, &((struct sockaddr*) &ifr.ifr_hwaddr)->sa_data);

   memset(&ifr, 0, sizeof(ifr));
   strlcpy(ifr.ifr_name, ii->ifname, sizeof(ifr.ifr_name));
   if (ioctl(ii->fd, SIOCGIFFLAGS, &ifr) == -1)
      log_msg(LOG_ERR, "ioctl(SIOCGIFFLAGS): %s", strerror(errno)), exit(1);
   ifr.ifr_flags |= IFF_PROMISC;
   if (ioctl(ii->fd, SIOCSIFFLAGS, &ifr) == -1)
      log_msg(LOG_ERR, "ioctl(SIOCSIFFLAGS): %s", strerror(errno)), exit(1);

   return ii->fd;
}


void *outside_if_maintainer(if_info_t *ii)
{
   char hwaddr[ETHER_ADDR_LEN];

   pa_cleanup(&ii->mtbl);
   if (ii->router_valid < 2 && search_router(&ii->mtbl, hwaddr) < ii->mtbl.size)
   {
      //log_msg(LOG_DEBUG, "router found");
      pthread_mutex_lock(&ii->mutex);
      if (HWADDR_CMP(ii->hwrouter, hwaddr))
      {
         log_msg(LOG_NOTICE, "router address changed on %s", ii->ifname);
         HWADDR_COPY(ii->hwrouter, hwaddr);
         ii->router_valid = 1;
      }
      pthread_mutex_unlock(&ii->mutex);
   }
   return NULL;
}


void *inside_if_maintainer(if_info_t *ii)
{
   char hwaddr[ETHER_ADDR_LEN], addr[16], netmask[4];
   int v;

   pthread_mutex_lock(&ii->mutex);
   v = ii->hwclient_valid;
   pthread_mutex_unlock(&ii->mutex);

   if (!v && search_client(&ii->mtbl, hwaddr, addr) < ii->mtbl.size)
   {
      pthread_mutex_lock(&ii->mutex);
      v = ii->hwclient_valid;
      if (!v)
      {
         log_msg(LOG_NOTICE, "client identified on %s", ii->ifname);
         HWADDR_COPY(ii->hwclient, hwaddr);
         ii->hwclient_valid = 1;
      }
      pthread_mutex_unlock(&ii->mutex);

      memset(&netmask, -1, sizeof(netmask));
      if (!v && ii->out->gate != NULL)
         tun_ipv4_config(ii->out->gate->ifname, (struct in_addr*) addr, (struct in_addr*) &netmask);
      else if (v)
         log_msg(LOG_EMERG, "hwclient was set by other thread");
   }
   return NULL;
}
 

/*! This is a wrapper function. */
void *state_maintainer(if_info_t *ii)
{
   cleanup_states(ii->st);
   return NULL;
}


void *maintainer(void *p)
{
   if_info_t *ii = p;
   inc_thread_cnt();

   for (;;)
   {
      sleep(10);
      (void) ii->if_maintainer(ii);
   }
}


void usage(const char *cmd)
{
   printf(
         "usage: %s [options]\n"
         "  -a <age> .......... Set max age of addresses. 0 means infinity.\n"
         "  -d ................ Output debug info.\n"
         "  -i <inif> ......... Name of inside interface.\n"
         "  -o <outif> ........ Name of outside interface.\n"
         "  -r <hwaddr> ....... Set hardware address of router to <hwaddr>.\n"
         "  -w <pcap> ......... Write packets to file.\n",
         cmd
         );
}


int main(int argc, char **argv)
{
   int c;
   if_info_t ii[3];
   char *pcapname = NULL;
   char *hwrouter = NULL;
   state_table_t st;
   char name[16];

   memset(ii, 0, sizeof(ii));
   strlcpy(ii[1].ifname, "eth0", sizeof(ii[1].ifname));
   strlcpy(ii[0].ifname, "eth1", sizeof(ii[0].ifname));

   while ((c = getopt(argc, argv, "a:dhi:o:r:vw:")) != -1)
   {
      switch (c)
      {
         case 'a':
            set_max_age(atoi(optarg));
            log_msg(LOG_DEBUG, "max_age_ = %d", set_max_age(-1));
            break;

         case 'd':
            debug_level_ = 7;
            break;

         case 'h':
            usage(argv[0]);
            exit(0);

         case 'i':
            strlcpy(ii[0].ifname, optarg, sizeof(ii[0].ifname));
            break;

         case 'r':
            hwrouter = optarg;
            break;

         case 'o':
            strlcpy(ii[1].ifname, optarg, sizeof(ii[1].ifname));
            break;

         case 'v':
            printf("%s\n", PACKAGE_STRING);
            exit(0);

         case 'w':
            pcapname = optarg;
            break;
      }
   }

   new_state_table(&st, STATETABLESIZE);

   pthread_mutex_init(&ii[1].mutex, NULL);
   init_socket(&ii[1]);
   ii[1].out = &ii[0];
   ii[1].gate = &ii[2];
   init_mac_table(&ii[1].mtbl, MACTABLESIZE, MACTABLESIZE);
   ii[1].wfd = create_file(pcapname, SNAPLEN);
   ii[1].filter = filter_in_outside;
   ii[1].st = &st;
   ii[1].if_maintainer = (void *(*)(void*)) outside_if_maintainer;
   if (hwrouter != NULL && set_hwrouter(&ii[1], hwrouter) == -1)
      printf("ill hwaddr: \"%s\"\n", hwrouter), exit(1);

   pthread_mutex_init(&ii[0].mutex, NULL);
   if (strcmp(ii[0].ifname, "null"))
      init_socket(&ii[0]);
   ii[0].out = &ii[1];
   init_mac_table(&ii[0].mtbl, MACTABLESIZE, MACTABLESIZE);
   ii[0].wfd = ii[1].wfd;
   ii[0].filter = filter_accept /* filter_in_inside */;
   ii[0].if_maintainer = (void *(*)(void*)) inside_if_maintainer;

   pthread_mutex_init(&ii[2].mutex, NULL);
   ii[2].fd = tun_alloc(ii[2].ifname, sizeof(ii[2].ifname));
   ii[2].out = &ii[1];
   init_mac_table(&ii[2].mtbl, MACTABLESIZE, MACTABLESIZE);
   ii[2].wfd = -1;
   ii[2].off = 10;
   ii[2].filter = filter_out_tunnel;
   ii[2].if_maintainer = (void *(*)(void*)) state_maintainer;
   ii[2].st = &st;
   // set invalid address to tunnel if struct to circument detection of own address which is (0:0:0:0:0:0)
   memset(ii[2].hwaddr, -1, ETHER_ADDR_LEN);

   ii[1].wfd = ii[0].wfd;

   for (int i = 0; i < 3; i++)
   {
      snprintf(name, sizeof(name), "recv%d", i);
      if (run_thread(name, bridge_receiver, &ii[i]))
         log_msg(LOG_ERR, "run_thread() failed"), exit(1);

      snprintf(name, sizeof(name), "mnt%d", i);
      if (run_thread(name, maintainer, &ii[i]))
         log_msg(LOG_ERR, "run_thread() failed"), exit(1);
   }

   // wait for all threads to be ready
   wait_thread_cnt(6);
   //run cli
   cli(stdin, stdout, ii, 3);

   if (ii[0].wfd > 0)
      close(ii[0].wfd);

   return 0;
}

#ifndef HAVE_STRLCPY
#include "strlcpy.c"
#endif

