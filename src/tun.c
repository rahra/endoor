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

/*! \file tun.c
 *  These functions create and initialized the TUN/TAP device. This code is
 *  mainly derived from my OnionCat project (see
 *  https://github.com/rahra/onioncat) and was reworked a little bit.
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2022/09/13
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_LINUX_IF_H
#include <linux/if.h>
#endif
#ifdef HAVE_LINUX_IF_TUN_H
#include <linux/if_tun.h>
#endif
#ifdef HAVE_LINUX_IPV6_H
#include <linux/ipv6.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "endoor.h"
#include "log.h"

char *tun_dev_ = "/dev/net/tun";

#define IFCBUF 1024


#if 0
#define ENVLEN 64
extern char **environ;


/*! This function executes the ifup script (see option -e). The function forks
 * a child, sets the environment variables OCAT_IFNAME, OCAT_ADDRESS,
 * OCAT_PREFIX, and OCAT_PREFIXLEN and finally executes the ifup shell script
 * by calling execlp(3).
 * The parent does not wait for the child to exit.
 * @param ifname Pointer to interface name string.
 * @param astr Pointer to literal IPv6 address string.
 * @param prefix_len Prefix length.
 * @return On success (if the child could be forked) 0 is returned, otherwise
 * -1 is returned.
 */
int run_tun_ifup(const char *ifname, const char *astr, int prefix_len)
{
   char env_ifname[ENVLEN], env_address[ENVLEN], env_prefix[ENVLEN], env_prefix_len[ENVLEN], env_onion_url[ENVLEN], env_onion3_url[ENVLEN], env_domain[ENVLEN];
   char *env[] = {env_ifname, env_address, env_prefix, env_prefix_len, env_onion_url, env_onion3_url, env_domain, NULL};
   pid_t pid;

   if (ifname == NULL || astr == NULL)
   {
      log_msg(LOG_EMERG, "NULL pointer caught in run_tun_ifup()");
      return -1;
   }

   log_msg(LOG_INFO, "running ifup script \"%s\"", CNF(ifup));
   switch (pid = fork())
   {
      // fork failed
      case -1:
         log_msg(LOG_ERR, "could not fork sub process for script execution: \"%s\"", strerror(errno));
         return -1;

      // child
      case 0:
         snprintf(env_ifname, sizeof(env_ifname), "OCAT_IFNAME=%s", ifname);
         snprintf(env_address, sizeof(env_address), "OCAT_ADDRESS=%s", astr);
         strlcpy(env_prefix, "OCAT_PREFIX=", sizeof(env_prefix));
         inet_ntop(AF_INET6, &NDESC(prefix), env_prefix + strlen(env_prefix), sizeof(env_prefix) - strlen(env_prefix));
         snprintf(env_prefix_len, sizeof(env_prefix_len), "OCAT_PREFIXLEN=%d", prefix_len);
         snprintf(env_onion_url, sizeof(env_onion_url), "OCAT_ONION_URL=%s", CNF(onion_url));
         snprintf(env_onion3_url, sizeof(env_onion3_url), "OCAT_ONION3_URL=%s", CNF(onion3_url));
         snprintf(env_domain, sizeof(env_domain), "OCAT_DOMAIN=%s", CNF(domain));
         environ = env;

         execlp(CNF(ifup), CNF(ifup), NULL);

         log_msg(LOG_ERR, "execlp(\"%s\") failed: %s", CNF(ifup), strerror(errno));
         _exit(1);

      // parent
      default:
         return 0;
   }
}
#endif


/*! mk_in6_mask() creates an IPv6 network mask according to the number
 * specified in prefixlen.
 * @param msk Pointer to in6_addr which will receive the result.
 * @param prefixlen Prefix length.
 * @return On success 0 is returned, otherwise -1.
 */
int mk_in6_mask(struct in6_addr *msk, int prefixlen)
{
   char *buf;

   // safety check
   if (msk == NULL)
   {
      log_msg(LOG_EMERG, "NULL pointer caught in mk_in6_mask()");
      return -1;
   }

   memset(msk, 0, sizeof(*msk));
   for (buf = (char*) msk; prefixlen >= 8; buf++, prefixlen -= 8)
      *buf = 0xff;

   if (prefixlen > 0)
      *buf = ~((8 - prefixlen) - 1);

   return 0;
}


/*! sin_set_addr() fills in a sockaddr_in structure appropriately.
 * @param sin Pointer to a sockaddr_in structure which will be filled in.
 * @param addr Network address which will be copied into sin.
 * @return On success 0 is return, otherwise -1. The function may only fail of
 * NULL pointers are passed.
 * FIXME: This function should be moved to ocatlibe.c.
 */
int sin_set_addr(struct sockaddr_in *sin, const struct in_addr *addr)
{
   if (sin == NULL || addr == NULL)
   {
      log_msg(LOG_EMERG, "NULL pointer caught in sin_set_addr()");
      return -1;
   }
#ifdef HAVE_SIN_LEN
   sin->sin_len = sizeof(struct sockaddr_in);
#endif
   sin->sin_family = AF_INET;
   sin->sin_addr = *addr;

   return 0;
}


/*! sin6_set_addr() fills in a sockaddr_in6 structure appropriately.
 * @param sin Pointer to a sockaddr_in6 structure which will be filled in.
 * @param addr Network address which will be copied into sin.
 * @return On success 0 is return, otherwise -1. The function may only fail of
 * NULL pointers are passed.
 * FIXME: This function should be moved to ocatlibe.c.
 */
int sin6_set_addr(struct sockaddr_in6 *sin6, const struct in6_addr *addr)
{
   if (sin6 == NULL || addr == NULL)
   {
      log_msg(LOG_EMERG, "NULL pointer caught in sin6_set_addr()");
      return -1;
   }
#ifdef HAVE_SIN_LEN
   sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
   sin6->sin6_family = AF_INET6;
   sin6->sin6_addr = *addr;

   return 0;
}


/*! tun_config() does some basic initialization on the newly opened tun device.
 * This is highly OS-specific.
 * @param fd File descriptor of tunnel device.
 * @param dev Pointer to string which may contain interface name.
 * @param devlen Number of bytes available in dev.
 * @return Returns 0 on success.
 */
int tun_config(int fd, char *dev, int devlen)
{
#ifdef __linux__
   struct ifreq ifr;

   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN;

   // safety checks
   if (dev != NULL && *dev)
      strlcpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));

   if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0)
   {
      log_msg(LOG_ERR, "could not set TUNSETIFF: %s", strerror(errno));
      return -1;
   }

   if (dev != NULL)
      strlcpy(dev, ifr.ifr_name, devlen);
#endif
   return 0;
}


/*! This function configures an IPv6 address to the network device (TUN).
 *  @param dev Char pointer to device name.
 *  @param addr Pointer to IPv6 address.
 *  @param prefix_len Prefix length.
 *  @return Returns 0 on success, otherwise -1 is returned.
 */
int tun_ipv6_config(const char *dev, const struct in6_addr *addr, int prefix_len)
{
   char astr[INET6_ADDRSTRLEN];
   inet_ntop(AF_INET6, addr, astr, INET6_ADDRSTRLEN);
   int sockfd;

   log_msg(LOG_NOTICE, "setting interface IPv6 address %s/%d", astr, prefix_len);
   if ((sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP)) == -1)
   {
      log_msg(LOG_ERR, "failed to create temp socket: %s", strerror(errno));
      return -1;
   }

   struct in6_ifreq ifr6;
   struct ifreq ifr;

   memset(&ifr, 0, sizeof(ifr));
   strlcpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
   if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
   {
      log_msg(LOG_ERR, "SIOCGIFINDEX: %s", strerror(errno));
   }

   ifr6.ifr6_addr = *addr;
   ifr6.ifr6_ifindex = ifr.ifr_ifindex;
   ifr6.ifr6_prefixlen = prefix_len;

   log_debug("calling ioctl(SIOCSIFADDR)");
   if (ioctl(sockfd, SIOCSIFADDR, &ifr6) == -1)
   {
      log_msg(LOG_ERR, "SIOCSIFADDR: %s", strerror(errno));
   }

   close(sockfd);

   return 0;
}


/*! This function configures an IPv4 address to the network device (TUN).
 *  @param dev Char pointer to device name.
 *  @param addr Pointer to IPv6 address.
 *  @param prefix_len Prefix length.
 *  @return Returns 0 on success, otherwise -1 is returned.
 */
int tun_ipv4_config(const char *dev, const struct in_addr *addr, const struct in_addr *netmask)
{
   char addrstr[32], nmstr[32];
   int sockfd;

   log_msg(LOG_NOTICE, "setting interface IPv4 address %s/%s", inet_ntop(AF_INET, addr, addrstr, sizeof(addrstr)), inet_ntop(AF_INET, netmask, nmstr, sizeof(nmstr)));
   if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1)
   {
      log_msg(LOG_ERR, "failed to create temp socket: %s", strerror(errno));
      return -1;
   }

   struct ifreq ifr;

   memset(&ifr, 0, sizeof(ifr));
   strlcpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));

   sin_set_addr((struct sockaddr_in*) &ifr.ifr_addr, addr);
   log_debug("calling ioctl(SIOCSIFADDR)");
   if (ioctl(sockfd, SIOCSIFADDR, &ifr) == -1)
   {
      log_msg(LOG_ERR, "SIOCSIFADDR: %s", strerror(errno));
   }

   sin_set_addr((struct sockaddr_in*) &ifr.ifr_netmask, netmask);
   log_debug("calling ioctl(SIOCSIFNETMASK)");
   if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) == -1)
   {
      log_msg(LOG_ERR, "SIOCSIFNETMASK: %s", strerror(errno));
   }
   close(sockfd);

   return 0;
}


/*! This function simply set the interface link up.
 *  @param dev Char pointer to device name.
 *  @return Returns 0 on success, otherwise -1 is returned.
 */
int tun_ifup(const char *dev)
{
   struct ifreq ifr;
   int sockfd;

   log_msg(LOG_INFO, "bringing up interface %s", dev);
   if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1)
   {
      log_msg(LOG_ERR, "failed to create temp socket: %s", strerror(errno));
      return -1;
   }

   memset(&ifr, 0, sizeof(ifr));
   strlcpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));

   if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1)
   {
      log_msg(LOG_ERR, "SIOCGIFFLAGS: %s", strerror(errno));
      ifr.ifr_flags = 0;
   }

   ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
   if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1)
   {
      log_msg(LOG_ERR, "SIOCSIFFLAGS: %s", strerror(errno));
   }

   close(sockfd);

   return 0;
}


/*! Completely set up tun device for Onioncat.
 * @param dev Char pointer to ifname if the name should be customized (only
 * supported for Linux yet), must point otherwise to a string with length 0
 * (i.e. it points to a \0-char). The string will be initialized by this
 * function.
 * @param dev_s Number of bytes available in dev.
 * @return On success it returns a filedescriptor >= 0, otherwise -1 is returned.
 */
int tun_alloc(char *dev, int dev_s)
{
   int fd;

   log_debug("opening tun \"%s\"", tun_dev_);
   if ((fd = open(tun_dev_, O_RDWR)) == -1)
   {
      log_msg(LOG_ERR, "could not open tundev %s: %s", tun_dev_, strerror(errno));
      return -1;
   }

   log_debug("tun base config");
   tun_config(fd, dev, dev_s);

#if 0
   if (CNF(ifup) != NULL)
   {
      char astr[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &CNF(ocat_addr), astr, INET6_ADDRSTRLEN);
      log_debug("running ifup script");
      run_tun_ifup(dev, astr, NDESC(prefix_len));
      return fd;
   }
#endif

   // bring up device
   tun_ifup(dev);

   return fd;
}

