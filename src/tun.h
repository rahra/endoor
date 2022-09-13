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

/*! \file tun.h
 *  These functions create and initialized the TUN/TAP device. This code is
 *  mainly derived from my OnionCat project (see
 *  https://github.com/rahra/onioncat) and was reworked a little bit.
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2022/09/13
 */

#ifndef TUN_H
#define TUN_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

int mk_in6_mask(struct in6_addr *msk, int prefixlen);
int sin_set_addr(struct sockaddr_in *sin, const struct in_addr *addr);
int sin6_set_addr(struct sockaddr_in6 *sin6, const struct in6_addr *addr);
int tun_config(int fd, char *dev, int devlen);
int tun_ipv6_config(const char *dev, const struct in6_addr *addr, int prefix_len);
int tun_ipv4_config(const char *dev, const struct in_addr *addr, const struct in_addr *netmask);
int tun_ifup(const char *dev);
int tun_alloc(char *dev, int dev_s);

#endif

