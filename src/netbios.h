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

/*! \file netbios.h
 * Header for the NetBIOS decoder.
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2025/07/06
 */

#ifndef NETBIOS_H
#define NETBIOS_H

typedef struct nbds
{
   char type;
   char flags;
   int16_t id;
   uint32_t src;
   uint16_t sport;
   uint16_t len;
   uint16_t off;
} nbds_t;


#endif

