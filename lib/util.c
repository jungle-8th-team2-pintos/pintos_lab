#include "lib/util.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"

/* cmdline에서 첫 번째 " "가 등장하기 직전까지 자른다. */
char *extract_program_name(const char *cmdline) {
    char *save_ptr;
    char *prog_name = strtok_r(cmdline, " ", &save_ptr);
    return cmdline;
}