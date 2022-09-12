#include <stdio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

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


