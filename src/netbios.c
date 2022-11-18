#include <stdio.h>


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

