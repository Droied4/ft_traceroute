#ifndef TRACEROUTE_H 
# define TRACEROUTE_H 

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netdb.h>
# include <arpa/inet.h>

# define COMMON_OPTSTR "h"

/*
 *  struct addrinfo {
    int              ai_flags;
    int              ai_family;
    int              ai_socktype;
    int              ai_protocol;
    socklen_t        ai_addrlen;
    struct sockaddr *ai_addr;
    char            *ai_canonname;
    struct addrinfo *ai_next;
};
*/

typedef struct s_trace
{
	char *ip_name;
	char ip_addr[INET_ADDRSTRLEN];
	struct addrinfo *info_addr;
} t_trace;

#endif
