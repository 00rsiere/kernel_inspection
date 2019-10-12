#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "lib/inspect.h"
#include "inspection.h"


// TODO: return values
int inspect_memory(unsigned long long addr, char *out_buf, size_t len)
{
  int fd;
  char *buf = NULL;
  struct ioctl_inspect_mem_arg arg = { 0 };

  if (!out_buf) {
    return 1;
  }

  arg.addr = addr;
  arg.len = len;
  arg.out_buf = out_buf;
  arg.out_len = len;

  fd = open("/dev/tracer", O_NONBLOCK);

  if (fd == -1) {
    return 1;
  }

  if (ioctl(fd, INSPECT_MEMORY_IOCTL, (unsigned long)&arg)) {
    return 1;
  }

  return 0;
}

int inspect_msr(unsigned int msr, unsigned long long *out_msr)
{
  int fd;
  struct ioctl_inspect_mem_arg arg = { 0 };

  if (!out_msr) {
    return 1;
  }

  arg.val = msr; // MSR_LSTAR

  fd = open("/dev/tracer", O_NONBLOCK);

  if (fd == -1) {
    return 1;
  }

  if (ioctl(fd, INSPECT_MSR_IOCTL, &arg)) {
    return 1;
  }

  *out_msr = arg.out_ull;

  return 0;
}

