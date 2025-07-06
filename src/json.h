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

/*! \file json.h
 * Header file for the JSON functions.
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2025/07/06
 */

#ifndef JSON_H
#define JSON_H


#define INDENT 3
#define CCHAR (condensed_ ? ' ' : '\n')
#define JBUFBLK 65536


typedef struct json
{
   int condensed;
   int size;
   int len;
   char *buf;
} json_t;


int strpos(const char *s, int c);
int stresc(const char *src, int slen, char *dst, int dlen, const char *echars, const char *uchars);
int jesc(const char *src, int slen, char *dst, int dlen);
int findent(FILE *f, int n);
int funsep(FILE *f);
int fochar(FILE *f, char c);
int fcchar(FILE *f, char c);
int flabel(FILE *f, const char *k, int indent);
int fint(FILE *f, const char *k, long v, int indent);
int fstring(FILE *f, const char *k, const char *v, int indent);
int jindent(json_t*, int n);
int junsep(json_t*);
int jochar(json_t*, char c);
int jcchar(json_t*, char c);
int jlabel(json_t*, const char *k, int indent);
int jint(json_t*, const char *k, long v, int indent);
int jstring(json_t*, const char *k, const char *v, int indent);
int jinit(json_t *J);
void jfree(json_t *J);

#endif

