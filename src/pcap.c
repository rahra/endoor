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

/*! \file pcap.c
 * This file contains the code for writing a pcap file.
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2022/09/13
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include "log.h"
#include "pcap.h"


static pthread_mutex_t mutex_ = PTHREAD_MUTEX_INITIALIZER;


int create_file(const char *name, int snaplen)
{
   pcap_header_t ph;
   int fd;

   // safety check
   if (name == NULL)
      return -1;

   memset(&ph, 0, sizeof(ph));
   ph.magic = 0xa1b2c3d4;
   ph.major = 2;
   ph.minor = 4;
   ph.snaplen = snaplen;
   ph.linktype = 1;

   if ((fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP )) == -1)
   {
      log_msg(LOG_ERR, "could not open file %s: %s", name, strerror(errno));
      return -1;
   }

   if (write(fd, &ph, sizeof(ph)) == -1)
   {
      log_msg(LOG_ERR, "could not write pcap header: %s", strerror(errno));
      close(fd);
      return -1;
   }

   return fd;
}


int save_packet(int fd, const char *buf, int len)
{
   struct timeval tv;
   packet_header_t ph;

   if (fd <= 0)
      return -1;

   gettimeofday(&tv, NULL);
   ph.sec = tv.tv_sec;
   ph.usec = tv.tv_usec;
   ph.caplen = ph.origlen = len;

   (void) pthread_mutex_lock(&mutex_);
   write(fd, &ph, sizeof(ph));
   write(fd, buf, len);
   (void) pthread_mutex_unlock(&mutex_);

   return 0;
}


