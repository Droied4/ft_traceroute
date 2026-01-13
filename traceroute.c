#include "traceroute.h" 

static int error(int error_code, char *msg)
{
	dprintf(2, "traceroute: %s\n", msg);
	return (error_code);
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

static void traceroute(int ac, char *av[]) 
{
	int pos;
	char *addr;
	(void)ac;

	pos = getAddr(av);	
	addr = strdup(av[pos]);
	if (!addr)
		error(1, "FUCK");
	printf("addr-> %s\n", addr);
	free(addr);
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
