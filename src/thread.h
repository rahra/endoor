#ifndef THREAD_H
#define THREAD_H

#include <pthread.h>

#define MAX_THREADS 32


typedef struct thelper
{
   int id;
   pthread_t th;
   char name[16];
} thelper_t;


int run_thread(const char *, void *(*)(void*), void *);
void wait_thread_cnt(int);
void inc_thread_cnt(void);
char *thread_name(char *, int);


#endif

