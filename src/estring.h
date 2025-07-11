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

/*! \file estring.h
 * This file contains various string functions for the output of information to
 * the CLI.
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2022/09/19
 */

#ifndef ESTRING_H
#define ESTRING_H

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
#include "state.h"
#include "json.h"


char *ether_ntoa_rz(const struct ether_addr *, char *);
int addr_ntop(int , const char *, char *, int );
int snprint_proto_addr(char *, int , const proto_addr_t *);
int snprint_palist(char *, int , const proto_addr_t *, int );
int snprint_mac_table(char *, int , proto_addr_t *);
int snprint_states(state_table_t *, char *, int );
int fprintj_palist(FILE *, proto_addr_t *, int );
int jpalist(json_t*, proto_addr_t *, int );

#endif

