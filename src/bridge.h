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

/*! \file bridge.h
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2022/09/13
 */

#ifndef BRIDGE_H
#define BRIDGE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pthread.h>
#ifdef HAVE_LINUX_IF_H
#include <linux/if.h>
#endif

#include "endoor.h"
#include "pcap.h"
#include "log.h"
#include "protoaddr.h"
#include "state.h"

typedef struct if_info
{
   //! if name
   char ifname[IFNAMSIZ];
   //! input fd
   int fd;
   //! pcap fd
   int wfd;
   //! filter function
   int (*filter)(struct if_info*, char *, int);
   //! output interface
   struct if_info *out;
   //! gate (tunnel if)
   struct if_info *gate;
   //! mac address table
   proto_addr_t mtbl;
   //! read offset
   int off;
   //! local mac address
   char hwaddr[ETHER_ADDR_LEN];
   //! state table
   state_table_t *st;
   //! thread struct for bridge
   pthread_t th_bridge;
   //! thread hanalde for mac table maintainer
   thelper_t th_tbl;
   //! mutex for hwclient
   pthread_mutex_t mutex;
   //! assumed client mac address
   char hwclient[ETHER_ADDR_LEN];
   //! is client address valid
   int hwclient_valid;
   //! assumed router address
   char hwrouter[ETHER_ADDR_LEN];
   int router_valid;
} if_info_t;


enum {FI_ACCEPT, FI_DROP};


void *bridge_receiver(void *p);
int filter_accept(if_info_t *, char *, int );
int filter_in_inside(if_info_t *, char *, int );
int filter_out_tunnel(if_info_t *, char *, int );
int filter_in_outside(if_info_t *, char *, int );


#endif

