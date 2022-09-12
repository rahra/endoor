#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <errno.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#include "endoor.h"
#include "pcap.h"
#include "log.h"
#include "bridge.h"
#include "tun.h"

#define SNAPLEN 4096
#define MACTABLESIZE 1024
#define STATETABLESIZE 16384


extern int debug_level_;


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


int init_socket(if_info_t *ii)
{
   struct sockaddr_ll sa;
   struct ifreq ifr;

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


void if_maintainer(if_info_t *ii)
{
   char hwaddr[ETHER_ADDR_LEN];

   pa_cleanup(&ii->mtbl);
   if (search_router(&ii->mtbl, hwaddr))
   {
      pthread_mutex_lock(&ii->mutex);
      if (HWADDR_CMP(ii->hwrouter, hwaddr))
      {
         log_msg(LOG_INFO, "router address changed");
         HWADDR_COPY(ii->hwrouter, hwaddr);
         ii->router_valid = 1;
      }
      pthread_mutex_unlock(&ii->mutex);
   }
}
 

void *maintainer(void *p)
{
   if_info_t *ii = p;
   int i;

   pthread_detach(pthread_self());
   for (;;)
   {
      sleep(10);

      for (i = 0; i < 3; i++)
         if_maintainer(&ii[i]);
      cleanup_states(ii[2].st);
   }
}


void log_hex(const char *buf, int len)
{
   char s[16 * 3];

   data_to_hex(s, buf, len > 16 ? 16 : len);
   log_msg(LOG_DEBUG, "data: %s", s);
}


void usage(const char *cmd)
{
   printf(
         "usage: %s [options]\n"
         "  -d ................ Output debug info.\n"
         "  -i <inif> ......... Name of inside interface.\n"
         "  -o <outif> ........ Name of outside interface.\n"
         "  -w <pcap> ......... Write packets to file.\n",
         cmd
         );
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
}


int main(int argc, char **argv)
{
   int c;
   pthread_t ordr;
   if_info_t ii[3];
   char *pcapname = NULL;
   state_table_t st;

   memset(ii, 0, sizeof(ii));
   strlcpy(ii[1].ifname, "eth0", sizeof(ii[1].ifname));
   strlcpy(ii[0].ifname, "eth1", sizeof(ii[0].ifname));

   while ((c = getopt(argc, argv, "dhi:o:w:")) != -1)
   {
      switch (c)
      {
         case 'd':
            debug_level_ = 7;
            break;

         case 'h':
            usage(argv[0]);
            exit(0);

         case 'i':
            strlcpy(ii[0].ifname, optarg, sizeof(ii[0].ifname));
            break;

         case 'o':
            strlcpy(ii[1].ifname, optarg, sizeof(ii[1].ifname));
            break;

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
   //ii[1].wfd = create_file(pcapname, SNAPLEN);
   ii[1].filter = filter_incoming;
   ii[1].st = &st;

   pthread_mutex_init(&ii[0].mutex, NULL);
   init_socket(&ii[0]);
   ii[0].out = &ii[1];
   init_mac_table(&ii[0].mtbl, MACTABLESIZE, MACTABLESIZE);
   //ii[0].wfd = ii[1].wfd;
   ii[0].wfd = create_file(pcapname, SNAPLEN);
   ii[0].filter = filter_inside_set_ip;

   pthread_mutex_init(&ii[2].mutex, NULL);
   ii[2].fd = tun_alloc(ii[2].ifname, sizeof(ii[2].ifname));
   ii[2].out = &ii[1];
   init_mac_table(&ii[2].mtbl, MACTABLESIZE, MACTABLESIZE);
   ii[2].wfd = 0;
   ii[2].off = 10;
   ii[2].filter = filter_tun_out;
   ii[2].st = &st;
   // set invalid address to tunnel if struct to circument detection of own address which is (0:0:0:0:0:0)
   memset(ii[2].hwaddr, -1, ETHER_ADDR_LEN);

   ii[1].wfd = ii[0].wfd;

   pthread_create(&ordr, NULL, maintainer, ii);

   pthread_create(&ordr, NULL, bridge_receiver, &ii[1]);
   pthread_create(&ordr, NULL, bridge_receiver, &ii[0]);
   pthread_create(&ordr, NULL, bridge_receiver, &ii[2]);

   cli(ii, 3);

   if (ii[0].wfd > 0)
      close(ii[0].wfd);

   return 0;
}

#ifndef HAVE_STRLCPY
#include "strlcpy.c"
#endif

