#ifndef JSON_H
#define JSON_H


#define INDENT 3
#define CCHAR (condensed_ ? ' ' : '\n')
#define JBUFBLK 4096


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


#endif

