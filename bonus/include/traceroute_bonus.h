#ifndef TRACEROUTE_H 
# define TRACEROUTE_H 

# include <stdio.h>
# include <unistd.h>
# include <stdlib.h>
# include <string.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netdb.h>
# include <netinet/ip_icmp.h>
# include <arpa/inet.h>
# include <sys/time.h>

# define COMMON_OPTSTR "h"
# define LONG_PORT 33434 
# define RECV_TIMEOUT 1

typedef struct s_trace
{
	char *ip_name;
	char ip_addr[INET_ADDRSTRLEN];
	struct addrinfo *info_addr;
	struct sockaddr_in sin;
	int send_sock;
	int recv_sock;
	int pkg_bytes;
	int hops;
	} t_trace;

#endif
