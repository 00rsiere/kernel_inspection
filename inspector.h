#ifndef INSPECTOR_HEADER
#define INSPECTOR_HEADER

#define MAX_COPY_LEN 0x1000

#include <asm/ioctl.h>

enum inspection_type {
  INVALID_TYPE,
  INSPECT_MEMORY,
  INSPECT_MSR
};

struct ioctl_inspect_mem_arg {
  union {
    unsigned long long addr;
    unsigned long long val;
  };
  unsigned long long len;
  union {
    char *out_buf;
    unsigned long long out_ull;
  };
  size_t out_len;
};

#define INSPECTOR_MAGIC 'i'

#define INSPECT_MSR_IOCTL _IOWR(INSPECTOR_MAGIC, 0x1, struct ioctl_inspect_mem_arg)
#define INSPECT_MEMORY_IOCTL _IOWR(INSPECTOR_MAGIC, 0x2, struct ioctl_inspect_mem_arg)

#endif
