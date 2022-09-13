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

/*! \file pcap.h
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2022/09/13
 */

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
