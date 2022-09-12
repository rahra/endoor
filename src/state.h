#ifndef STATE_H
#define STATE_H

#include <pthread.h>
#include <netinet/in.h>

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
   int size;
   int num;
   state_t *state;
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

