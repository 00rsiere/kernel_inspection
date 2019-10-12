#ifndef INSPECT_HEADER
#define INSPECT_HEADER

#include <stddef.h>

int inspect_memory(unsigned long long addr, char *out_buf, size_t len);
int inspect_msr(unsigned int msr, unsigned long long *out_msr);

#endif
