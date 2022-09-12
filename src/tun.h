/* Copyright 2008-2019 Bernhard R. Fischer.
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

/*! \file ocattun.c
 *  These functions create and initialized the TUN/TAP device.
 *
 *  @author Bernhard R. Fischer <rahra _at_ cypherpunk at>
 *  \date 2019/09/08
 */

#ifndef TUN_H
#define TUN_H

int mk_in6_mask(struct in6_addr *msk, int prefixlen);
int sin_set_addr(struct sockaddr_in *sin, const struct in_addr *addr);
int sin6_set_addr(struct sockaddr_in6 *sin6, const struct in6_addr *addr);
int tun_config(int fd, char *dev, int devlen);
int tun_ipv6_config(const char *dev, const struct in6_addr *addr, int prefix_len);
int tun_ipv4_config(const char *dev, const struct in_addr *addr, const struct in_addr *netmask);
int tun_ifup(const char *dev);
int tun_alloc(char *dev, int dev_s);

#endif

