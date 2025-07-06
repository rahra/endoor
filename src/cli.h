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

/*! \file cli.h
 * Header file for the CLI.
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2025/07/06
 */

#ifndef CLI_H
#define CLI_H

//#include "bridge.h"

//! maximum number of arguments of cli parser
#define MAX_ARGS 10
 
void cli(FILE *, FILE *, if_info_t *, int );
int parse_cmd0(char *, char **, int , const char *);
int parse_cmd(char *, char **, int);

#endif

