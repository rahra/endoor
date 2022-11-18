#ifndef NETBIOS_H
#define NETBIOS_H

typedef struct nbds
{
   char type;
   char flags;
   int16_t id;
   uint32_t src;
   uint16_t sport;
   uint16_t len;
   uint16_t off;
} nbds_t;


#endif

