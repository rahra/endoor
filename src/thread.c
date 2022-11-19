#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "endoor.h"
#include "thread.h"
#include "log.h"


static thelper_t th_[MAX_THREADS];
static int tcnt_ = 0;
static pthread_mutex_t mutex_ = PTHREAD_MUTEX_INITIALIZER;
static int th_cnt_ = 0;
static pthread_mutex_t th_mtx_ = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t th_cnd_ = PTHREAD_COND_INITIALIZER;


void __attribute__((constructor)) init_threads(void)
{
   memset(th_, 0, sizeof(th_));
   th_[0].id = ++tcnt_;
   th_[0].th = pthread_self();
   strlcpy(th_[0].name, "main", sizeof(th_[0].name));
}


static int get_highest_id(void)
{
   int i, max = 0;
   for (i = 0; i < MAX_THREADS; i++)
      if (th_[i].id > max)
         max = th_[i].id;
   return max;
}


static thelper_t *get_thelper(void)
{
   int i;

   for (i = 0; i < MAX_THREADS; i++)
      if (!th_[i].id)
      {
         memset(&th_[i], 0, sizeof(th_[i]));
         th_[i].id = ++tcnt_;
         break;
      }

   if (i == MAX_THREADS)
      return NULL;

   // prevent int overflow
   if (tcnt_ >= INT32_MAX)
      tcnt_ = get_highest_id();

   return &th_[i];
}


int run_thread(const char *name, void *(*func)(void*), void *p)
{
   thelper_t *th;
   int e;

   pthread_mutex_lock(&mutex_);
   if ((th = get_thelper()) == NULL)
   {
      e = ENOMEM;
      goto rt_exit;
   }

   strlcpy(th->name, name, sizeof(th->name));
   e = pthread_create(&th->th, NULL, func, p);

rt_exit:
   pthread_mutex_unlock(&mutex_);
   return e;
}


char *thread_name(char *dst, int size)
{
   if (dst == NULL)
      return NULL;

   pthread_mutex_lock(&mutex_);
   for (int i = 0; i < MAX_THREADS; i++)
   {
      if (!th_[i].id)
         continue;
      if (pthread_equal(pthread_self(), th_[i].th))
      {
         strlcpy(dst, th_[i].name, size);
         break;
      }
   }
   pthread_mutex_unlock(&mutex_);

   return dst;
}


void wait_thread_cnt(int n)
{
   pthread_mutex_lock(&th_mtx_);
   while (n < th_cnt_)
      pthread_cond_wait(&th_cnd_, &th_mtx_);
   pthread_mutex_unlock(&th_mtx_);
}


void inc_thread_cnt(void)
{
   pthread_mutex_lock(&th_mtx_);
   th_cnt_++;
   pthread_cond_broadcast(&th_cnd_);
   pthread_mutex_unlock(&th_mtx_);
}

