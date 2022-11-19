/*! \file json.c
 * This file contains the functions to create rules file in JSON format.
 * The implementation shall follow the JSON specification:
 * https://www.json.org/json-en.html
 *
 *  \author Bernhard R. Fischer, <bf@abenteuerland.at>
 *  \date 2022/04/06
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "log.h"
#include "bstring.h"
#include "json.h"


static int condensed_ = 0;
static int indent_ = 1;


/*! This function returns the index of the first occurence if c in the string
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
 * prepended by a single backslash.
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
int bs_stresc(bstring_t src, char *dst, int dlen, const char *echars, const char *uchars)
{
   int len, n;

   // safety check
   if (src.buf == NULL || echars == NULL || uchars == NULL || strlen(echars) != strlen(uchars))
   {
      log_msg(LOG_EMERG, "NULL pointer caught, or strlen(echars) != strlen(uchars))");
      return -1;
   }

   if (dst == NULL)
      dlen = src.len * 2 + 1;

   dlen--;
   for (len = 0; src.len > 0 && len < dlen; src.buf++, src.len--, len++, dst++)
   {
      if ((n = strpos(echars, *src.buf)) == -1)
      {
         if (dst != NULL)
            *dst = *src.buf;
         continue;
      }

      // check if there is enough space in destinatin
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


/*! This function is a wrapper for bs_stresc(). */
int stresc(const char *src, int slen, char *dst, int dlen, const char *echars, const char *uchars)
{
   return bs_stresc((bstring_t) {slen, (char*) src}, dst, dlen, echars, uchars);
}


int jesc(const char *src, int slen, char *dst, int dlen)
{
   return stresc(src, slen, dst, dlen, "\"\\/\b\f\n\r\t", "\"\\/bfnrt");
}


void findent(FILE *f, int n)
{
   if (condensed_ || !indent_)
      return;

   int len = n * INDENT;
   char buf[n * INDENT];

   memset(buf, ' ', len);
   fwrite(buf, len, 1, f);
}


void funsep(FILE *f)
{
   fseek(f, -2, SEEK_CUR);
   fprintf(f, "%c", CCHAR);
}


void fochar(FILE *f, char c)
{
   fprintf(f, "%c%c", c, CCHAR);
}


void fcchar(FILE *f, char c)
{
   fprintf(f, "%c,%c", c, CCHAR);
}


void fint(FILE *f, const char *k, long v, int indent)
{
   findent(f, indent);
   fprintf(f, "\"%s\": %ld,%c", k, v, CCHAR);
}


void fbstring(FILE *f, const char *k, const bstring_t *v, int indent)
{
   char buf[v->len * 2 + 2];
   int len;

   if ((len = jesc(v->buf, v->len, buf, sizeof(buf))) == -1)
      return;

   findent(f, indent);
   fprintf(f, "\"%s\": \"%.*s\",%c", k, len, buf, CCHAR);
}


void fstring(FILE *f, const char *k, const char *v, int indent)
{
   char buf[strlen(v) * 2 + 2];
   int len;

   if ((len = jesc(v, strlen(v), buf, sizeof(buf))) == -1)
      return;

   findent(f, indent);
   fprintf(f, "\"%s\": \"%s\",%c", k, buf, CCHAR);
}


