
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "log.h"
#include "http.h"
#include "bridge.h"
#include "cli.h"
#include "json.h"
#include "endoor.h"
#include "estring.h"


const char *status(int n)
{
   switch (n)
   {
      case 200:
         return "HTTP/1.0 200 OK";

      case 400:
         return "HTTP/1.0 400 Bad Request";

      case 404:
         return "HTTP/1.0 404 Not Found";

      case 500:
         return "HTTP/1.0 500 Internal Server Error";

      default:
      case 501:
         return "HTTP/1.0 501 Not Implemented";
   }
}


int handle_request(int fd, if_info_t *ii)
{
   char buf[4096];
   char *argv[16];
   char *s, *r;
   int len, argc, code;
   char *url = "/api/v1/";
   json_t J;

   log_msg(LOG_DEBUG, "handling HTTP request on %d", fd);
   if ((len = read(fd, buf, sizeof(buf))) == -1)
   {
      log_msg(LOG_ERR, "read failed: %s", strerror(errno));
      return -1;
   }

   if (!len)
   {
      log_msg(LOG_DEBUG, "eof on %d", fd);
      return 0;
   }

   code = 500;
   if (jinit(&J) == -1)
     goto hr_exit;

   log_msg(LOG_DEBUG, "read %d bytes on %d", len, fd);
   buf[len] = '\0';
   s = strtok_r(buf, "\r\n", &r);
   argc = parse_cmd(s, argv, 4);

   code = 400;
   if (argc < 3 || (strcmp(argv[2], "HTTP/1.0") && strcmp(argv[2], "HTTP/1.1")))
      goto hr_exit;

   code = 501;
   if (strcmp(argv[0], "GET"))
      goto hr_exit;

   code = 404;
   if (strlen(argv[1]) <= strlen(url) || strncmp(argv[1], url, strlen(url)))
      goto hr_exit;

   if ((argc = parse_cmd0(argv[1] + strlen(url), argv, 16, "?&")) < 1)
      goto hr_exit;

   if (!strcmp(argv[0], "dump"))
   {
      code = 200;
      jochar(&J, '{');
      jpalist(&J, &ii->mtbl, 1);
      junsep(&J);
      jcchar(&J, '}');
      junsep(&J);
   }

hr_exit:
   len = snprintf(buf, sizeof(buf), "%s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", status(code), J.len);
   if (len >= (int) sizeof(buf))
      len = sizeof(buf);
   write(fd, buf, len);
   write(fd, J.buf, J.len);
   return 0;
}


void *handle_http(void *p)
{
   http_param_t *hp = (http_param_t*) p;
   struct sockaddr_in saddr;
   socklen_t addrlen;
   int fd;

   for (;;)
   {
      log_msg(LOG_DEBUG, "waiting for connections on %d", hp->fd);
      addrlen = sizeof(saddr);
      if ((fd = accept(hp->fd, (struct sockaddr*) &saddr, &addrlen)) == -1)
      {
         log_msg(LOG_ERR, "accept failed: %s", strerror(errno));
         continue;
      }
      handle_request(fd, hp->ii);
      close(fd);
   }
}

