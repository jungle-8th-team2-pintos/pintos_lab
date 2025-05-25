#ifndef __LIB_UTIL_H
#define __LIB_UTIL_H

#include "include/userprog/process.h"

char *extract_program_name(const char *cmdline);
int parse_arguments(char *file_name, char **argv);

#endif /* lib/util.h */
