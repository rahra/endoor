/* Copyright 2008-2022 Bernhard R. Fischer.
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

/*! \file ocat.h
 * This file is the central header file of OnionCat. It includes all other
 * headers and contains all macros, structures, typedefs,...
 * \author Bernhard R. Fischer <bf@abenteuerland.at>
 * \date 2022/07/28
 */

#ifndef LOG_H
#define LOG_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <syslog.h>

#define LOG_FCONN 0x400
#define LOG_FERR 0x800


int open_connect_log(const char*);
void log_msg(int, const char *, ...) __attribute__((format (printf, 2, 3)));


#ifdef DEBUG
#define log_debug(fmt, x...) log_msg(LOG_DEBUG, "%s() " fmt, __func__, ## x)
#else
#define log_debug(fmt, x...)
#endif

#endif

