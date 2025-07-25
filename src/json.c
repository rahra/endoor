/* Copyright 2022-2025 Bernhard R. Fischer.
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

/*! \file json.c
 * This file contains the functions to create rules file in JSON format.
 * The implementation shall follow the JSON specification:
 * https://www.json.org/json-en.html
 *
 *  \author Bernhard R. Fischer, <bf@abenteuerland.at>
 *  \date 2025/07/07
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#include "log.h"
#include "json.h"


static int condensed_ = 0;
static int indent_ = 1;


/*! This function returns the index of the first occurence of c in the string
 * s.
 * \param s Pointer to string.
 * \param c Character to search for in s.
 * \return The function returns index of c in s. If c does not occur in s, -1
 * is returned.
 */
int strpos(const char *s, int c)
{
   char *d;

   if ((d = strchr(s, c)) == NULL)
      return -1;
   return d - s;
}


/*! This function escapes characters in the string src and puts the resulting
 * string into dst. The chars are escape with a backslash. Thereby all chars
 * found in echars are replaced by the corresponding character in uchars and
 * are prepended by a single backslash.
 * The destination buffer dst obviously must be bigger than src. In the worst
 * case it is twice as large as src if every charcter has to be escaped. The
 * destination buffer will be 0-terminated, thus the buffer must also have 1
 * byte extra space for it. That means dlen should be src.len * 2 + 1 to be
 * safe.
 * If dst is NULL the function will escape the source string src but will not
 * write the result anywhere. Thus, it returns the number of bytes which would
 * be needed for the escape buffer (exluding the terminating \0).
 * \param src The source string as a bstring_t structure.
 * \param dst A pointer to the destination buffer.
 * \param dlen The size of the destination buffer.
 * \param echars A character array of the chars which shall be escaped.
 * \param uchars A character array which are the replacements.
 * \return The function returns the length of the destination string excluding
 * the terminating \0 char, i.e. it is the strlen(dst).
 * In case of error, -1 is returned.
 */
int stresc(const char *src, int slen, char *dst, int dlen, const char *echars, const char *uchars)
{
   int len, n;

   // safety check
   if (src == NULL || echars == NULL || uchars == NULL || strlen(echars) != strlen(uchars))
   {
      log_msg(LOG_EMERG, "NULL pointer caught, or strlen(echars) != strlen(uchars))");
      return -1;
   }

   if (dst == NULL)
      dlen = slen * 2 + 1;

   dlen--;
   for (len = 0; slen > 0 && len < dlen; src++, slen--, len++, dst++)
   {
      if ((n = strpos(echars, *src)) == -1)
      {
         if (dst != NULL)
            *dst = *src;
         continue;
      }

      // check if there is enough space in destination
      if (dlen - len < 2)
         return -1;

      if (dst != NULL)
      {
         *dst++ = '\\';
         *dst = uchars[n];
      }

      len++;
   }

   if (dst != NULL)
      *dst = '\0';

   return len;
}


int jesc(const char *src, int slen, char *dst, int dlen)
{
   return stresc(src, slen, dst, dlen, "\"\\/\b\f\n\r\t", "\"\\/bfnrt");
}


int findent(FILE *f, int n)
{
   if (condensed_ || !indent_)
      return 0;

   int len = n * INDENT;
   char buf[n * INDENT];

   memset(buf, ' ', len);
   return fwrite(buf, 1, len, f);
}


int funsep(FILE *f)
{
   fseek(f, -2, SEEK_CUR);
   return fprintf(f, "%c", CCHAR);
}


int fochar(FILE *f, char c)
{
   return fprintf(f, "%c%c", c, CCHAR);
}


int fcchar(FILE *f, char c)
{
   return fprintf(f, "%c,%c", c, CCHAR);
}


int flabel(FILE *f, const char *k, int indent)
{
   int in = findent(f, indent);
   return fprintf(f, "\"%s\": ", k) + in;
}


int fint(FILE *f, const char *k, long v, int indent)
{
   int in = findent(f, indent);
   return fprintf(f, "\"%s\": %ld,%c", k, v, CCHAR) + in;
}

int fstring(FILE *f, const char *k, const char *v, int indent)
{
   char buf[strlen(v) * 2 + 2];
   int len;

   if ((len = jesc(v, strlen(v), buf, sizeof(buf))) == -1)
      return 0;

   int in = findent(f, indent);
   return fprintf(f, "\"%s\": \"%s\",%c", k, buf, CCHAR) + in;
}


/* This function increases the JSON output buffer by JBUFBLK bytes.
 * @param J Pointer to JSON handling structure.
 * @return On success 0 is returned, otherwise -1 and errno is set
 * appropriately.
 */
int jrealloc(json_t *J)
{
   char *buf;

   if ((buf = realloc(J->buf, J->size + JBUFBLK)) == NULL)
   {
      log_msg(LOG_ERR, "cannot increase json buffer: %s", strerror(errno));
      return -1;
   }
   J->buf = buf;
   J->size += JBUFBLK;
   return 0;
}


/*! This function grows the JSON output buffer that len bytes fit into it. The
 * buffer is not resized if len already fits into it, so repeated calls do not
 * change anything.
 * @param J Pointer to JSON handling structure.
 * @param len Number of additional bytes to fit into the buffer.
 * @return On success 0 is returned, otherwise -1 and errno is set
 * appropriately.
 */
int jgrow(json_t *J, int len)
{
   while (J->size - J->len < len)
      if (jrealloc(J) == -1)
         return -1;
   return 0;
}


char jsep(json_t *J)
{
   return J->condensed ? ' ' : '\n';
}


int jindent(json_t *J, int n)
{
   if (J->condensed)
      return 0;

   int len = n * INDENT;

   // return if jgrow() fails
   if (jgrow(J, len))
      return 0;

   memset(J->buf + J->len, ' ', len);
   J->len += len;
   return len;
}


int junsep(json_t *J)
{
   if (J->len < 2)
      return 0;

   J->buf[J->len - 2] = J->buf[J->len - 1];
   J->len--;
   return -1;
}


int jochar(json_t *J, char c)
{
   // return if jgrow() fails
   if (jgrow(J, 2))
      return 0;

   J->buf[J->len++] = c;
   J->buf[J->len++] = jsep(J);
   return 2;
}


int jcchar(json_t *J, char c)
{
   // return if jgrow() fails
   if (jgrow(J, 3))
      return 0;

   J->buf[J->len++] = c;
   J->buf[J->len++] = ',';
   J->buf[J->len++] = jsep(J);
   return 3;
}


int jlabel(json_t *J, const char *k, int indent)
{
   int len;
   int in = jindent(J, indent);

   for (len = J->size; len >= J->size - J->len;)
   {
      len = snprintf(J->buf + J->len, J->size - J->len, "\"%s\": ", k);
      if (len >= J->size - J->len)
      {
         // return if jgrow() fails
         if (jgrow(J, len + 1))
            return 0;
         len = J->size;
      }
   }
   J->len += len;
   return len + in;
}


int jint(json_t *J, const char *k, long v, int indent)
{
   int len;
   int in = jlabel(J, k, indent);

   for (len = J->size; len >= J->size - J->len;)
   {
      len = snprintf(J->buf + J->len, J->size - J->len, "%ld,%c", v, jsep(J));
      if (len >= J->size - J->len)
      {
         // return if jgrow() fails
         if (jgrow(J, len + 1))
            return 0;
         len = J->size;
      }
   }
   J->len += len;
   return len + in;
}


int jstring(json_t *J, const char *k, const char *v, int indent)
{
   char buf[strlen(v) * 2 + 2];
   int len;
   int in = jlabel(J, k, indent);

   if ((len = jesc(v, strlen(v), buf, sizeof(buf))) == -1)
      return 0;

   // return if jgrow() fails
   if (jgrow(J, len + 5))
      return 0;

   len = snprintf(J->buf + J->len, J->size - J->len, "\"%s\",%c", buf, jsep(J));
   J->len += len;
   return len + in;
}


int jinit(json_t *J)
{
   memset(J, 0, sizeof(*J));
   return jrealloc(J);
}


void jfree(json_t *J)
{
   free(J->buf);
   J->buf = NULL;
   J->size = J->len = 0;
}

