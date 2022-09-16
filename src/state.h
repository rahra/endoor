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

/*! \file state.h
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2022/09/13
 */

#ifndef STATE_H
#define STATE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pthread.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#define MAX_STATE_AGE 180

typedef struct state
{
   //! address family, AF_INET or AF_INET6
   int family;
   //! protocol, IPPROTO_UDP, IPPROTO_TCP, IPPROTO_ICMP, IPPROTO_ICMPV6
   int proto;
   //! source address
   union
   {
      struct sockaddr_in src;
      struct sockaddr_in6 src6;
   };
   //! destination address
   union
   {
      struct sockaddr_in dst;
      struct sockaddr_in6 dst6;
   };
   //! timestamp of entry
   time_t age;
} state_t;


typedef struct state_table
{
   //! max number of available entries in state table
   int size;
   //! number of used elements in state table
   int num;
   //! arrray of states
   state_t *state;
   //! maintainer thread
   pthread_t th;
   //! table mutex
   pthread_mutex_t mutex;
} state_table_t;


enum {INCOMING, OUTGOING};

int new_state_table(state_table_t *, int );
int update_state(state_table_t *, struct ether_header *, int , int);
int update_state_if_exists(state_table_t *, struct ether_header *, int , int);
int has_state(state_table_t *, struct ether_header *, int , int);
void cleanup_states(state_table_t *);
int snprint_states(state_table_t *, char *, int );


#endif

