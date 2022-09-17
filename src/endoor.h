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

/*! \file endoor.h
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2022/09/14
 */

#ifndef RWPACK_H
#define RWPACK_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdint.h>
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
#ifdef HAVE_NETINET_IP6_h
#include <netinet/ip6.h>
#endif
#ifdef HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif
#ifdef HAVE_NETINET_ETHER_H
#include <netinet/ether.h>
#endif

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif

#ifndef ETHERTYPE_IP
//! Ether type for IPv4.
#define ETHERTYPE_IP 0x0800
#endif
#ifndef ETHERTYPE_IPV6
//! Ether type for IPv6.
#define ETHERTYPE_IPV6 0x86dd
#endif

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

// At least on Solaris the Ethernet addresses are defined as struct containing
// an array of bytes.  This is different from most other OSes which define the
// addresses directly as array.
#ifdef HAVE_ETHER_ADDR_OCTET
#define ether_dst ether_dhost.ether_addr_octet
#define ether_src ether_shost.ether_addr_octet
#else
#define ether_dst ether_dhost
#define ether_src ether_shost
#endif

//! copy an IPv6 address from b to a
#define IN6_ADDR_COPY(a,b) memcpy(a, b, sizeof(struct in6_addr))

typedef struct thelper
{
   pthread_t th;
   void *(*func)(void*);
   void *p;
} thelper_t;

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#endif

