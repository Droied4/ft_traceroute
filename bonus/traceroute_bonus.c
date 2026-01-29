#include "traceroute_bonus.h" 

static void safeExit(t_trace *t)
{
	if (t->ip_name)
		free(t->ip_name);
	if (t->send_sock > 0)
	{
		close(t->send_sock);	
		t->send_sock = -1;
	}
	if (t->recv_sock > 0)
	{
		close(t->recv_sock);	
		t->recv_sock = -1;
	}
	if (t->info_addr)
		freeaddrinfo(t->info_addr);
	exit(1);
}

static void error(char *msg, t_trace *t)
{
	dprintf(2, "traceroute: %s\n", msg);
	safeExit(t);
}

static void usage(void)
{
	printf("Usage\n" 
		  "\tping [options] <destination>\n"
		  "Options:\n" 
		  "-h \t\t display help\n"
		  "-m \t\t max number of hops\n"
		  "-p \t\t specifies the destination port\n"
		  "-f \t\t specifies with what ttl to start. default to 1\n"
		  "-q \t\t sets the number of probe packets per hop. The default is 3\n"
		  );
	exit(1);
}

static char options_allowed(char *str, char ch)
{
	for (unsigned int i = 0; i < strlen(str); ++i)
	{
		if (str[i] == ch)
			return (ch);
	}
	return (1);
}

static char mini_getopt(int ac, char *av[], char **opt_value, char *str)
{
	char ch;

	for (int i = 0; i < ac; ++i)
	{
		for (unsigned int j = 0; j < strlen(av[i]); ++j)
		{
			if (av[i][j] == '-')
			{
				ch = options_allowed(str, av[i][j + 1]);
				if ((i + 1) < ac)
					*opt_value = strdup(av[i + 1]);
				return (ch);
			}
		}
	}
	return (0);
}

static int is_number(char *str)
{
	for (size_t i = 0; i < strlen(str); ++i)
	{
		if (!isdigit(str[i]))
			return (1);
	}
	return (0);
}

static int update_trace(int *value, char *str)
{
	int res;
	res = 0;
	if (!str)
		return (1);
	if (is_number(str))
		return (1);
	res = atoi(str);
	*value = res;
	return (0);
}

static void flagCases(int ac, char *av[], t_trace *t)
{
	int ch;
	char *opt;
	opt = NULL;

	ch = mini_getopt(ac, av, &opt, COMMON_OPTSTR);
	switch (ch)
	{
		case 0: 
			break ;
		case 1:
			error("bad option", t);
			break ;
		case 'h':
			usage();
			break ;
		case 'm' :
			if (update_trace(&t->hops, opt))
				error("invalid argument for the option", t);
			break ;
		case 'p' :
			if (update_trace(&t->port, opt))
				error("invalid argument for the option", t);
			break ;
		case 'f' :
			if (update_trace(&t->ttl_val, opt))
				error("invalid argument for the option", t);
			break ;
		case 'q' :
			if (update_trace(&t->pkg_x_hop, opt))
				error("invalid argument for the option", t);
			break ;
	}
}

static int getAddr(char *av[])
{
	int i;

	i = 1;
	while(av[i + 1])
	{
		if (av[i][0] == '-')
		{
			if (!(av[i + 2]))
				return (i + 1);
			else
				return (i + 2);
		}
		i++;
	}
	return (i);
}

static int open_socket(t_trace *t, int sock_type, int sock_protocol)
{
	int sock_fd;

	sock_fd = socket(AF_INET, sock_type, sock_protocol); 
	if (sock_fd < 1)
		error("socket file descriptor not received", t);
	return (sock_fd);
}

static void init(char *av[], t_trace *t)
{
	int pos = 0;

	pos = getAddr(av);	
	t->ip_name = strdup(av[pos]);
	if (!t->ip_name)
		error("malloc error", t);
	t->ttl_val = 1;
	t->info_addr = NULL;
	t->send_sock = open_socket(t, SOCK_DGRAM, IPPROTO_UDP);
	t->recv_sock = open_socket(t, SOCK_RAW, IPPROTO_ICMP);
	t->hops = 30;
	t->port = 33434;
	t->pkg_x_hop = 3;
	t->pkg_bytes = 60;
}

static char *reverse_dns_resolver(char *ip_addr, struct sockaddr_in *addr) 
{
	socklen_t len;
	char buf[NI_MAXHOST], *ret_buf;

	addr->sin_addr.s_addr = inet_addr(ip_addr);
	len = sizeof(struct sockaddr_in);

	if (getnameinfo((struct sockaddr *)addr, len, buf, sizeof(buf), NULL, 0, 0)) 
	{
		printf("Could not resolve reverse lookup of hostname\n");	 
		return (NULL);
	}
	ret_buf = (char *)malloc((strlen(buf) + 1) * sizeof(char));
	if (!ret_buf)
		return (NULL);
    strcpy(ret_buf, buf);
	return(ret_buf);
}

static int dns_resolver(char *domain, char *ipstr, struct addrinfo **info)
{
	struct addrinfo hint;
	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(domain, NULL, &hint, info) != 0)
		return (1);
	struct sockaddr_in *ip = (struct sockaddr_in *)(* info)->ai_addr;
	inet_ntop(AF_INET, &(ip->sin_addr), ipstr, INET_ADDRSTRLEN);
	return (0);
}

static void send_package(t_trace *t, char *payload)
{
	if (sendto(t->send_sock, payload, t->pkg_bytes, 0, (struct sockaddr*)&t->sin, sizeof(t->sin)) <= 0)
		safeExit(t);
}

static int recieve_package(t_trace *t, char *hop_ip)
{
	socklen_t raddr_len;
	char rbuf[sizeof(struct icmphdr) + t->pkg_bytes + sizeof(struct ip)];
	struct sockaddr_in r_addr;

	raddr_len = sizeof(r_addr);
	if (recvfrom(t->recv_sock, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&r_addr, &raddr_len) > 0)
	{
		struct ip *ip_hdr = (struct ip *)rbuf;
		int ip_hdr_len = ip_hdr->ip_hl * 4;
		struct icmphdr *icmp_hdr = (struct icmphdr *)(rbuf + ip_hdr_len);

		inet_ntop(AF_INET, &r_addr.sin_addr, hop_ip, INET_ADDRSTRLEN);

		if (icmp_hdr->type == ICMP_TIME_EXCEEDED)
			return (1);
		if (icmp_hdr->type == ICMP_DEST_UNREACH &&
				icmp_hdr->code == ICMP_PORT_UNREACH)
			return (2);
	}	
	return (0);
}

static void response(int ttl, long *elapsed, int len_elapsed, char *hop_ip, struct sockaddr_in *addr)
{
	char *hop_name;

	hop_name = reverse_dns_resolver(hop_ip, addr);
	if (!hop_ip[0])
	{
		printf(" %i ", ttl);
		for (int i = 0; i < len_elapsed; ++i)
			printf(" *");
	}
	else
	{
		printf(" %i  %s (%s)", ttl, hop_name, hop_ip);
		for (int i = 0; i < len_elapsed; ++i)
			printf(" %.3f ms ", (double)elapsed[i]/1000);
	}
	printf("\n");
	free(hop_name);
}

static void prepare_package(t_trace *t)
{
	t->sin.sin_family = AF_INET; 	
	t->sin.sin_port = htons(t->port + t->ttl_val);
	inet_pton(AF_INET, t->ip_addr, (struct in_addr *)&t->sin.sin_addr);
}

static void trace(t_trace *t)
{
	struct timeval start, end, tv_out;
	long elapsed[t->pkg_x_hop];  
	int res = 0;
	char payload[t->pkg_bytes];
	char hop_ip[INET_ADDRSTRLEN];

	memset(payload, 0, t->pkg_bytes);
	tv_out.tv_sec = RECV_TIMEOUT;
	tv_out.tv_usec = 0;
	printf("traceroute to %s (%s), %i hops max, %i bytes packets\n", t->ip_name, t->ip_addr, t->hops, t->pkg_bytes);

	setsockopt(t->recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out));
	for (; t->ttl_val <= t->hops; ++t->ttl_val)
	{
		hop_ip[0] = '\0';
		prepare_package(t);
		for (int i = 0; i < t->pkg_x_hop; ++i)
		{
		  	setsockopt(t->send_sock, SOL_IP, IP_TTL, &t->ttl_val, sizeof(t->ttl_val));	
			gettimeofday(&start, NULL);
			send_package(t, payload);
			res = recieve_package(t, hop_ip);
			gettimeofday(&end, NULL);
			elapsed[i] = (end.tv_sec - start.tv_sec) * 1000000L + (end.tv_usec - start.tv_usec);
		}
		response(t->ttl_val, elapsed, t->pkg_x_hop, hop_ip, &t->sin);	
		if (res == 2)
			return ;
	}
}

static void manage_funny_people(t_trace *t)
{
	if (t->hops <= 0)
		error("firts hop out of range", t);
	if (t->hops > 255)
		error("max hops cannot be more than 255", t);
	if (t->port < 0 || t->port >= 65534)
		error("the original works changing the port value. \ni'm not going to do that, try with a valid port :D", t);
	if (t->pkg_x_hop <= 0 || t->pkg_x_hop > 10)
		error("no more than 10 probes per hop", t); 
	if (t->ttl_val <= 0 || t->ttl_val > 30)
		error("first hop out of range", t);
}

static void traceroute(int ac, char *av[])
{
	t_trace t;

	init (av, &t);
	flagCases(ac, av, &t);
	if (dns_resolver(t.ip_name, t.ip_addr, &t.info_addr) == 1)
		safeExit(&t);
	manage_funny_people(&t);
	trace(&t);
	safeExit(&t);
}

int main (int ac, char *av[])
{
	if (ac != 1)
	{
		if (getuid())
		{
			printf("traceroute: should be executed with root permision\n");
			return (1);
		}
		traceroute(ac, av);
		return (0);
	} 
	usage();
	return (1);
}
