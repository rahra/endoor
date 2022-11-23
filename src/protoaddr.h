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

/*! \file protoaddr.c
 * This file contains the code for managing the protocol address lists (mac
 * address table).
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2022/09/13
 */

#ifndef PROTOADDR_H
#define PROTOADDR_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pthread.h>

#define HWADDR_COPY(x, y) memcpy(x, y, 6)
#define HWADDR_CMP(x, y) memcmp(x, y, 6)

#define MAX_AGE 120
#define PA_ROUTER 1
#define PA_CLIENT 2


typedef struct proto_addr
{
   //! address family (0, AF_PACKET, AF_INET, AF_INET6)
   int family;
   //! address
   char addr[16];
   //! last time seen
   time_t age;
   //! number of hits
   unsigned hits;
   //! various flags, (PA_ROUTER)
   int flags;
   //! size of protocol address list
   int size;
   //! number of entries in protocal address list
   int cnt;
   //! protocol address list
   struct proto_addr *list;
   //! mutex
   pthread_mutex_t mutex;
} proto_addr_t;


int init_mac_table(proto_addr_t *, int , int );
int update_table(proto_addr_t *, const char *, int , const char *, int );
void pa_cleanup(proto_addr_t *);
int search_router(proto_addr_t *, char *);
int search_client(proto_addr_t *, char *, char *);
int set_max_age(int);

#endif

