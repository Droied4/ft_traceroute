#include "traceroute.h" 

static int error(int error_code, char *msg)
{
	dprintf(2, "traceroute: %s\n", msg);
	return (error_code);
}

int main (int ac, char *av[])
{
	(void)av;
	if (ac != 1)
	{
		printf("siuu\n");
		return (0);
	} 
	return (error(2, "ufas fallo"));
}
