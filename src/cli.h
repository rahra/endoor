#ifndef CLI_H
#define CLI_H

//#include "bridge.h"

//! maximum number of arguments of cli parser
#define MAX_ARGS 10
 
void cli(FILE *, FILE *, if_info_t *, int );
int parse_cmd0(char *, char **, int , const char *);
int parse_cmd(char *, char **, int);

#endif

