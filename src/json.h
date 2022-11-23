#ifndef JSON_H
#define JSON_H

#include "bstring.h"


#define INDENT 3
#define CCHAR (condensed_ ? ' ' : '\n')


int strpos(const char *s, int c);
int bs_stresc(bstring_t src, char *dst, int dlen, const char *echars, const char *uchars);
int stresc(const char *src, int slen, char *dst, int dlen, const char *echars, const char *uchars);
int jesc(const char *src, int slen, char *dst, int dlen);
int findent(FILE *f, int n);
int funsep(FILE *f);
int fochar(FILE *f, char c);
int fcchar(FILE *f, char c);
int flabel(FILE *f, const char *k, int indent);
int fint(FILE *f, const char *k, long v, int indent);
int fbstring(FILE *f, const char *k, const bstring_t *v, int indent);
int fstring(FILE *f, const char *k, const char *v, int indent);

#endif

