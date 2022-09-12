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
int snprint_mac_table(char *, int , proto_addr_t *);
int addr_ntop(int , const char *, char *, int );

#endif

