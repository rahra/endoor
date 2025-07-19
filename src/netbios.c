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

/*! \file netbios.c
 * This file contains the Netbios packet and name decoder.
 *
 *  \author Bernhard R. Fischer <bf@abenteuerland.at>
 *  \date 2025/07/19
 */

#include <stdio.h>
#include <stdint.h>

#include "netbios.h"


static int nb_char_valid(char c)
{
   return c >= 'A' && c <= 'P';
}


/*! This function decodes a NetBIOS name given in src of length slen into the
 * buffer dst. slen must be an even number because of the encoding algorithm.
 * The size of the destionation buffer dst given by dsize must be at least of
 * slen * 2 + 1 bytes. The result in dst will be \0-terminated. The function
 * will never write more than dsize bytes to dst.
 * @param src Pointer to the source buffer.
 * @param slen Bytes within src to decode.
 * @param dst Pointer to the destination buffer.
 * @param dsize Size of dst.
 * @return The function will return the number of bytes written to dst
 * excluding the \0-termination. In case of error a negative value will be
 * returned. -1 indicates a parameter problem, either src is NULL, slen is an
 * odd number or the destination buffer is too small. -2 is returned if the
 * input buffer contains illegal characters.
 */
int decode_nbname(const char *src, int slen, char *dst, int dsize)
{
   int dlen;

   //safety check
   if (src == NULL || slen & 1 || dsize <= slen >> 1)
      return -1;

   for (dlen = 0; slen > 0; slen -= 2, src += 2, dst++, dlen++)
   {
      if (!nb_char_valid(src[0]) || !nb_char_valid(src[1]))
         return -2;

      *dst = (src[0] - 'A') << 4 | (src[1] - 'A');
   }

   *dst = '\0';

   return dlen;
}


int check_netbios(const nbds_t *nb, int len)
{
   return 0;
}

