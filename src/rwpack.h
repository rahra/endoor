/* Copyright 2008-2022 Bernhard R. Fischer.
 *
 * This file is part of OnionCat.
 *
 * OnionCat is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * OnionCat is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OnionCat. If not, see <http://www.gnu.org/licenses/>.
 */

/*! \file ocat.h
 * This file is the central header file of OnionCat. It includes all other
 * headers and contains all macros, structures, typedefs,...
 * \author Bernhard R. Fischer <bf@abenteuerland.at>
 * \date 2022/07/28
 */

#ifndef RWPACK_H
#define RWPACK_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdint.h>
#include <syslog.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ether.h>

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
#ifdef ETHERADDRL
#define ETHER_ADDR_LEN ETHERADDRL
#endif
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

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

int write_packet(const char *, int );

extern char hwaddr_[6];

#endif

