#ifndef TRACEROUTE_H 
# define TRACEROUTE_H 

# include <stdio.h>
# include <unistd.h>
# include <stdlib.h>
# include <string.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netdb.h>
# include <ctype.h>
# include <netinet/ip_icmp.h>
# include <arpa/inet.h>
# include <sys/time.h>

# define COMMON_OPTSTR "hmpfq"
# define LONG_PORT 33434
# define RECV_TIMEOUT 1

typedef struct s_trace
{
	char *ip_name;
	char ip_addr[INET_ADDRSTRLEN];
	char source_addr;
	struct addrinfo *info_addr;
	struct sockaddr_in sin;
	int send_sock;
	int recv_sock;
	int pkg_bytes;
	int port;
	int hops;
	int pkg_x_hop;
	int ttl_val;
	} t_trace;

#endif
