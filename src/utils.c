#include "utils.h"

void print_usage() {
	fprintf(stderr, "Usage: netdiag <hostname> [-t <max_ttl> | -p <packet_size>]\n");
	exit(2);
}

void exit_err(char * str) {
	perror(str);
	exit(2);
}

unsigned short chksum(unsigned short *ptr, int nbytes)
{
    register long sum;
    u_short oddbyte;
    register u_short answer;
 
    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
 
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) & oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }
 
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
 
    return (answer);
}

int iptohost(in_addr_t addr, char ** result)
{
	struct hostent *hent;
	*result = NULL;
	if((hent = gethostbyaddr((char *)&(addr), sizeof(addr), AF_INET))) {
		*result = strdup(hent->h_name);
		return 1;
	}
	*result = strdup(inet_ntoa(*(struct in_addr *)&addr));
	return 0;
}

void writeline(char * servername, double pingtime, int ttl, double loss) {
	printf("%3d\t%6.1f ms\t%6.2f%% \t%s\n", ttl, pingtime, loss, servername);
}