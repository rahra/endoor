/* Copyright 2008 Bernhard R. Fischer, Daniel Haslinger.
 *
 * This file is part of OnionCat.
 *
 * OnionCat is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * OnionCat is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OnionCat. If not, see <http://www.gnu.org/licenses/>.
 */

/*! @file
 *  File contains logging functions.
 *  @author Bernhard R. Fischer
 *  @version 2008/10/1
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <errno.h>
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include "log.h"

#define TIMESTRLEN 64
#define CBUFLEN 1024

#ifndef LOG_PRI
#define LOG_PRI(p) ((p) & LOG_PRIMASK)
#endif

static pthread_mutex_t log_mutex_ = PTHREAD_MUTEX_INITIALIZER;
static const char *flty_[8] = {"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"};

int debug_level_ = 6;
FILE *logf_ = NULL;


void __attribute__((constructor)) init_logf(void)
{
   logf_ = stderr;
}


/*! Log a message to a file.
 *  @param out Open FILE pointer
 *  @param lf Logging priority (equal to syslog)
 *  @param fmt Format string
 *  @param ap Variable parameter list
 */
void vlog_msgf(FILE *out, int lf, const char *fmt, va_list ap)
{
   struct timeval tv;
   struct tm *tm;
   time_t t;
   char timestr[TIMESTRLEN] = "", timez[TIMESTRLEN] = "";
   int level = LOG_PRI(lf);
   char buf[1024];

   if (debug_level_ < level)
      return;

   //t = time(NULL);
   if (gettimeofday(&tv, NULL) == -1)
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, strerror(errno)), exit(1);
   t = tv.tv_sec;
   if ((tm = localtime(&t)))
   {
      (void) strftime(timestr, TIMESTRLEN, "%a, %d %b %Y %H:%M:%S", tm);
      (void) strftime(timez, TIMESTRLEN, "%z", tm);
   }

   (void) pthread_mutex_lock(&log_mutex_);
   if (out)
   {
      fprintf(out, "%s.%03d %s [%6s] ", timestr, (int) (tv.tv_usec / 1000), timez, flty_[level]);
      vfprintf(out, fmt, ap);
      fprintf(out, "\n");
   }
   else
   {
      // log to syslog if no output stream is available
      //vsyslog(level | LOG_DAEMON, fmt, ap);
      vsnprintf(buf, sizeof(buf), fmt, ap);
      syslog(level | LOG_DAEMON, "%s", buf);

   }
   (void) pthread_mutex_unlock(&log_mutex_);
}


/*! Log a message. This function automatically determines
 *  to which streams the message is logged.
 *  @param lf Log priority.
 *  @param fmt Format string.
 *  @param ... arguments
 */
void log_msg(int lf, const char *fmt, ...)
{
   va_list ap;

   va_start(ap, fmt);
   vlog_msgf(logf_, lf, fmt, ap);
   va_end(ap);
   if (lf & LOG_FERR)
   {
      va_start(ap, fmt);
      vfprintf(stderr, fmt, ap);
      va_end(ap);
      fprintf(stderr, "\n");
   }
}

