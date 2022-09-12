#ifndef BRIDGE_H
#define BRIDGE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pthread.h>
#include <linux/if.h>

#include "rwpack.h"
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
int filter_inside_set_ip(if_info_t *, char *, int );
int filter_tun_out(if_info_t *, char *, int );
int filter_incoming(if_info_t *, char *, int );


#endif

