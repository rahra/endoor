
AC_PREREQ([2.69])
AC_INIT([endoor],[[2.3.0]],[bf@abenteuerland.at])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_SUBST([CFLAGS], [["$CFLAGS -Wall -Wextra"]])
AC_CONFIG_HEADERS([config.h])

AX_PTHREAD
LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"

AC_SEARCH_LIBS([bind], [socket])
AC_SEARCH_LIBS([inet_ntop], [nsl])
AC_C_CONST

AC_HEADER_STDC
AC_PROG_EGREP

AC_CHECK_HEADERS([arpa/inet.h endian.h fcntl.h linux/if.h linux/if_packet.h linux/if_tun.h linux/ipv6.h net/ethernet.h net/if.h net/if_tun.h netinet/ether.h netinet/icmp6.h netinet/if_ether.h netinet/in6.h netinet/in.h netinet/ip6.h netinet/ip.h netinet/udp.h net/tun/if_tun.h sys/endian.h sys/ethernet.h sys/ioctl.h syslog.h sys/socket.h sys/time.h time.h], [], [],
[[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_NETINET6_IN6_VAR_H
#include <netinet6/in6_var.h>
#endif
]]
)

AC_CHECK_TYPES([struct ip6_hdr], , ,
[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif
])

AC_CHECK_TYPES([struct iphdr], , ,
[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
])

AC_CHECK_TYPES([struct ip], , ,
[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
])

AC_CHECK_TYPES([struct ifreq, struct ifaliasreq, struct in6_ifreq, struct in6_aliasreq], , ,
[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_NETINET6_IN6_VAR_H
#include <netinet6/in6_var.h>
#endif
])

AC_CHECK_MEMBER([struct sockaddr_in.sin_len],
      [ AC_DEFINE(HAVE_SIN_LEN, 1, [Do we have sockaddr_in.sin_len?]) ],
      [],
      [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
])

AC_CHECK_MEMBER([struct ether_header.ether_dhost.ether_addr_octet],
                [AC_DEFINE(HAVE_ETHER_ADDR_OCTET, 1, [Do we have ether_header.ether_dhost.ether_addr_octet])],
                [],
                [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_ETHERNET_H
#include <sys/ethernet.h>
#endif
])


AC_CHECK_FUNCS([strlcpy ether_ntoa ether_ntoa_r])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

