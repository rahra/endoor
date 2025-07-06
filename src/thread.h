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

/*! \file thread.h
 * Header for the thread handling functions.
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2025/07/06
 */

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

