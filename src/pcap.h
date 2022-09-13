#ifndef PCAP_H
#define PCAP_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>


typedef struct pcap_header
{
   int32_t magic;
   int16_t major;
   int16_t minor;
   int32_t res1, res2;
   int32_t snaplen;
   int32_t linktype;
} pcap_header_t;

typedef struct packet_header
{
   uint32_t sec;
   int32_t usec;
   int32_t caplen;
   int32_t origlen;
} packet_header_t;


int save_packet(int fd, const char *buf, int len);
int create_file(const char *name, int snaplen);

#endif
