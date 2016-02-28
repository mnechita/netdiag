#include <stdio.h>
#include "utils.h"
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/time.h>
#include <linux/icmp.h>
#include <signal.h>
#include <string.h>
#include <ncurses.h>
#include <unistd.h>
#include <getopt.h>

int opensocket_icmp() {
	int sockfd;
	//raw icmp socket
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0 ) {
		perror("error at socket\n");
		return -1;
	}
	int on = 1;
	//allowing socket to send broadcasts
	if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
		perror("error at setsocket\n");
		close(sockfd);
		return -1;
	}
	struct icmp_filter filter;
	filter.data = ~((1 << ICMP_ECHOREPLY) | (1 << ICMP_TIME_EXCEEDED) | (1 << ICMP_DEST_UNREACH));
	if (setsockopt(sockfd, SOL_RAW, ICMP_FILTER, &filter, sizeof(filter)) < 0 ) {
		perror("error at setsocket filter\n");
		close(sockfd);
		return -1;
	}
	return sockfd;
}
int ping_send (in_addr_t dest_addr , int ttl, double * time_took) {
	int sockfd = opensocket_icmp();
	if (sockfd < 0) {
		perror("[ping_send] Invalid socket\n");
		return -1;
	}
	struct icmphdr  sicmp;
	bzero(&sicmp, sizeof(sicmp));
	sicmp.type = ICMP_ECHO;
	sicmp.code = 0;
	sicmp.un.echo.id = htons(getpid() & 0xFFFF);
	sicmp.un.echo.sequence = htons(ttl);
	sicmp.checksum = 0;
	sicmp.checksum = chksum((unsigned short * ) &sicmp, sizeof(sicmp));
	if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == -1) {
		perror("[ping_send] Error at setsocket ttl\n");
		close(sockfd);
		return PING_ERROR;
	}
	
	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = dest_addr;
	struct timeval start, end;
	char recvbuf[200];
	bzero(recvbuf, sizeof(recvbuf));
	gettimeofday(&start, NULL);
	int sent_size;
	sent_size = sendto(sockfd, &sicmp, sizeof(sicmp), 0, (struct sockaddr *) &servaddr, sizeof(servaddr));
	if(sent_size != sizeof(sicmp)){
		perror("[ping_send] Error at sending packet\n");
		close(sockfd);
		return PING_ERROR;
	}
	struct sockaddr_in replyaddr;
	socklen_t len;
	fd_set fds;
	int nr;
	struct timeval tv;
	FD_ZERO(&fds);
	FD_SET(sockfd, &fds);
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	while(1) {
		nr = select(sockfd + 1, &fds, NULL, NULL, &tv);
		if (nr == 0 ) {
			close(sockfd);
			where();
			return PING_DEST_UNREACH;
		}
		else if (nr == -1) {
			perror("[ping_send] Error at select()\n");
			close(sockfd);
			return PING_ERROR;
		}
		int nrbytes = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr * ) &replyaddr, &len);
		if (nrbytes < 0) {
			perror("[ping_send] Error at recvfrom\n");
			close(sockfd);
			return PING_ERROR;
		}
		//sleep(2);
		gettimeofday(&end, NULL);
		*time_took = (end.tv_sec - start.tv_sec) * 1000 + (double)(end.tv_usec - start.tv_usec) / 1000;
		if (*time_took > 5000) {
			close(sockfd);
			return PING_DEST_UNREACH;
		}
		
		if (nrbytes < sizeof(struct iphdr) + sizeof(struct icmphdr) )
			continue;
		
		struct iphdr * rip = (struct iphdr *) recvbuf;
		int iplen = rip->ihl << 2;
		
		if (nrbytes < iplen + sizeof(struct icmphdr))
			continue;
		struct icmphdr * ricmp = (struct icmphdr *) (recvbuf + iplen);		
		if (ricmp->type == ICMP_ECHOREPLY) {
			if (ricmp->un.echo.id == sicmp.un.echo.id && ricmp->un.echo.sequence == sicmp.un.echo.sequence) {
				break;
			}
			continue;
		}
		else if (ricmp->type == ICMP_DEST_UNREACH || ricmp->type == ICMP_TIME_EXCEEDED) {
			int offset = iplen + sizeof(ricmp);
			if(nrbytes - offset < sizeof(struct iphdr)) 
				continue;
			struct iphdr * rip2 = (struct iphdr *) (recvbuf + offset);
			offset += (rip2->ihl << 2);
			if (nrbytes - offset < sizeof(struct icmphdr))
				continue;
			struct icmphdr * ricmp2 = (struct icmphdr *) (recvbuf + offset);
			if (ricmp2->un.echo.id == sicmp.un.echo.id && ricmp2->un.echo.sequence == sicmp.un.echo.sequence) {
				close(sockfd);
				if (ricmp->type == ICMP_DEST_UNREACH)
					return PING_DEST_UNREACH;
				else
					return PING_TTL_EXPIRED;
			}
		}
	}
	close(sockfd);
	return PING_SUCCESS;
}


void tracert( struct in_addr dest_addr, int ttlmax, int payload_size) {
	int sockfd = opensocket_icmp();
	if (sockfd < 0 ) {
		where();
		exit_err("[tracert] Error at getting socket!\n");
	}
	char * buf = (char *) malloc( sizeof(struct icmphdr) + payload_size);
	struct icmphdr * sicmp = (struct icmphdr *) buf; 
	bzero(sicmp, sizeof(sicmp));
	sicmp->type = ICMP_ECHO;
	sicmp->code = 0;
	sicmp->un.echo.id = htons(getpid() & 0xFFFF);
	
	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(struct sockaddr_in));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr = dest_addr;
	int ttl;
	char recvbuf[300];
	struct timeval start, end;
	uint16_t packet_nr = 0;
	uint16_t * replies = (uint16_t *) malloc (ttlmax * sizeof(uint16_t));
	bzero(replies, ttlmax * sizeof(uint16_t));
	char servername[300] = {0};
	struct sockaddr_in replyaddr;
	bzero(&replyaddr, sizeof(replyaddr));
	socklen_t len = sizeof(replyaddr);
	int maxwidth = 0;
	double timediff;
	uint32_t rndsq = 213;
	printf("%s\t%9s\t%7s \t%s\n", "TTL", "Time", "Loss", "Hostname" );
	while(1) {
		int again = 0;
		packet_nr++;
		for (ttl = 1; ttl <= ttlmax && again == 0; ttl++) {
			bzero(servername, sizeof(servername));
			if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == -1) {
				close(sockfd);
				exit_err("[tracert] Error at setsocket ttl\n");
			}
			rndsq += 256;
			sicmp->un.echo.sequence = htons(rndsq);
			sicmp->checksum = 0;
			sicmp->checksum = chksum((unsigned short *)sicmp, sizeof(sicmp) );
			bzero(recvbuf, sizeof(recvbuf));
			gettimeofday(&start, NULL);
			int sent_size = sendto(sockfd, sicmp, sizeof(sicmp) + payload_size, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
			if (sent_size != sizeof(sicmp) + payload_size) {
				close(sockfd);
				exit_err("[tracert] Error at send to target\n");
			}
			while(1) {
				fd_set fds;
				struct timeval tv;
				FD_ZERO(&fds);
				FD_SET(sockfd, &fds);
				tv.tv_sec = 5;
				tv.tv_usec = 0;
				int nr = select(sockfd + 1, &fds, NULL, NULL, &tv);
				if (nr == 0) {
					strcpy(servername, "???");
					break;
				}
				else if (nr == -1) {
					close(sockfd);
					exit_err("[tracert] Error at select()\n");
				}
				
				int nrbytes = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *) &replyaddr, &len);
				if (nrbytes < 0) {
					close(sockfd);
					exit_err("[tracert] Error at recvfrom\n");
				}
				gettimeofday(&end, NULL);
				timediff = (end.tv_sec - start.tv_sec) * 1000 + (double)(end.tv_usec - start.tv_usec) / 1000;
				if (timediff > 5000) {
					strcpy(servername, "???");
					break;
				}
				
				if (nrbytes < sizeof(struct iphdr) + sizeof(struct icmphdr) )
					continue;
			   
				struct iphdr * rip = (struct iphdr *) recvbuf;
				int iplen = rip->ihl << 2;
			   
				if (nrbytes < iplen + sizeof(struct icmphdr))
					continue;
				struct icmphdr * ricmp = (struct icmphdr *) (recvbuf + iplen);     
				if (ricmp->type == ICMP_ECHOREPLY) {
					if (ricmp->un.echo.id == sicmp->un.echo.id && ricmp->un.echo.sequence == sicmp->un.echo.sequence) {
						again = 1;
						char * host_name;
						if (iptohost(replyaddr.sin_addr.s_addr, &host_name)) {
							sprintf(servername, "%s [%s]", host_name, inet_ntoa(replyaddr.sin_addr));
						}
						else {
							sprintf(servername, "%s", inet_ntoa(replyaddr.sin_addr));
						}
						free(host_name);
						replies[ttl-1] ++;
						break;
					}
					continue;
				}
				
				if (ricmp->type == ICMP_DEST_UNREACH || ricmp->type == ICMP_TIME_EXCEEDED) {
				
					int offset = iplen + sizeof(ricmp);
					if(nrbytes - offset < sizeof(struct iphdr))
						continue;
					struct iphdr * rip2 = (struct iphdr *) (recvbuf + offset);
					offset += (rip2->ihl << 2);
					if (nrbytes - offset < sizeof(struct icmphdr))
						continue;
					struct icmphdr * ricmp2 = (struct icmphdr *) (recvbuf + offset);
					if (ricmp2->un.echo.id == sicmp->un.echo.id && ricmp2->un.echo.sequence == sicmp->un.echo.sequence) {
						if (ricmp->type == ICMP_DEST_UNREACH) {
							strcpy(servername, "???");
							break;
						}
						// type = ICMP_TIME_EXCEEDED
						char * host_name;
						if (iptohost(replyaddr.sin_addr.s_addr, &host_name)) {
							sprintf(servername, "%s [%s]", host_name, inet_ntoa(replyaddr.sin_addr));
						}
						else {
							sprintf(servername, "%s", inet_ntoa(replyaddr.sin_addr));
						}
						free(host_name);
						replies[ttl-1] ++;
						break;
					}
				}
			}
			if (servername[0] == '?')
				timediff = 0.0;
			printf("\x1b[2K");
			fflush(stdout);
			writeline(servername, timediff, ttl, (double)(packet_nr - replies[ttl-1]) / packet_nr * 100.0 );
			sleep(0.5);
		}
		printf("\x1b[%dA\n", ttl);
		fflush(stdout);
		/// priting format here
	}
	free(sicmp);
	free(replies);
	close(sockfd);
}


int main(int argc, char **argv)
{
	if (argc < 2 ) {
		print_usage();
	}
	struct hostent * dest, * src;
	struct in_addr dest_addr;
	if (getuid() != 0) {
		exit_err("Root is required!\n");
	}
	dest = gethostbyname(argv[1]);
	if (!dest) {
		if (!inet_aton(argv[1], &dest_addr)) {
			fprintf(stderr, "Unknown host [%s].\n", argv[1]);
			print_usage();
		}
	}
	else {
		dest_addr = *(struct in_addr *)dest->h_addr;
	}
	int opt, ttlmax = 30, packet_size = 36;
	while ((opt = getopt(argc, argv, "t:p:")) != -1) {
		switch(opt) {
		case 't':
			ttlmax = atoi(optarg);
			break;
		case 'p':
			packet_size = atoi(optarg);
			break;
		default:
			print_usage();
		}
	}
	
	tracert(dest_addr, ttlmax, packet_size);
	return 0;
}
