#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "flags.h"
#include <netinet/in.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>

#define DEBUG

#ifdef DEBUG
#define where() fprintf(stderr, "%s %d:\n", __FILE__, __LINE__);
#endif

void print_usage();
void exit_err(char * str);
unsigned short checksum(unsigned short *ptr, int nbytes);
int iptohost(in_addr_t addr, char ** result);
void writeline(char * servername, double pingtime, int ttl, double loss);
#endif