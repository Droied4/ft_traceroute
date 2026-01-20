#include "traceroute.h" 

static void safeExit(t_trace *t)
{
	if (t->ip_name)
		free(t->ip_name);
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

static char mini_getopt(int ac, char *av[], char *str)
{
	for (int i = 0; i < ac; ++i)
	{
		for (unsigned int j = 0; j < strlen(av[i]); ++j)
		{
			if (av[i][j] == '-')
				return 	(options_allowed(str, av[i][j + 1]));
		}
	}
	return (0);
}

static void flagCases(int ac, char *av[], t_trace *t)
{
	int ch;

	ch = mini_getopt(ac, av, COMMON_OPTSTR);
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

static void init(char *av[], t_trace *t)
{
	int pos = 0;

	pos = getAddr(av);	
	t->ip_name = strdup(av[pos]);
	if (!t->ip_name)
		error("malloc error", t);
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

static void traceroute(int ac, char *av[]) 
{
	t_trace t;

	init (av, &t);
	flagCases(ac, av, &t);
	if (dns_resolver(t.ip_name, t.ip_addr, &t.info_addr) == 1)
		safeExit(&t);
	printf("addr-> %s\nip->%s", t.ip_name, t.ip_addr);
	safeExit(&t);
}

int main (int ac, char *av[])
{
	if (ac != 1)
	{
		traceroute(ac, av);
		return (0);
	} 
	usage();
	return (1);
}
