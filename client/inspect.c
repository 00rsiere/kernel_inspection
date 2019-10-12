#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <capstone/capstone.h>

#include "../inspector.h"

int disassemble(char *code, size_t len, unsigned long long offset)
{
  csh handle;
  cs_insn *insn;
  size_t count;

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    return -1;

  count = cs_disasm(handle, code, len, offset, 0, &insn);
  if (count > 0) {
    size_t j;
    for (j = 0; j < count; j++) {
      printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
          insn[j].op_str);
    }

    cs_free(insn, count);
  } else {
    printf("ERROR: Failed to disassemble given code!\n");
  }

  cs_close(&handle);

  return 0;
}

// TODO: return values
int inspect_memory(unsigned long long addr, size_t len)
{
  int fd;
  char *buf = NULL;
  struct ioctl_inspect_mem_arg arg = { 0 };

  buf = malloc(len);
  if (!buf) {
    printf("malloc fail\n");
    return 1;
  }

  arg.addr = addr;
  arg.len = len;
  arg.out_buf = buf;
  arg.out_len = len;

  fd = open("/dev/tracer", O_NONBLOCK);

  if (fd == -1) {
    return 1;
  }

  if (ioctl(fd, INSPECT_MEMORY_IOCTL, (unsigned long)&arg)) {
    return 1;
  }

  if (disassemble(buf, len, addr)) {
    return 1;
  }

  return 0;
}

int inspect_msr(unsigned int msr)
{
  int fd;
  struct ioctl_inspect_mem_arg arg = { 0 };

  arg.val = msr; // MSR_LSTAR

  fd = open("/dev/tracer", O_NONBLOCK);

  if (fd == -1) {
    return 1;
  }

  if (ioctl(fd, INSPECT_MSR_IOCTL, &arg)) {
    return 1;
  }

  printf("msr: %llx\n", arg.out_ull);

  return 0;
}

void print_usage_and_exit(char **argv)
{
  printf("usage: %s [-a address size] / [-m msr]\n", argv[0]);
  exit(1);
}

#ifndef SHARED_LIB_MODE
int main(int argc, char **argv)
{
  int opt;
  int len = 0;
  unsigned long long addr = 0;
  unsigned int msr = 0;

  enum inspection_type mode = INVALID_TYPE;

  if (geteuid()) {
    printf("WARNING: inspection requires root privileges, things will probably not work.\n");
  }

  while ((opt = getopt(argc, argv, "am")) != -1) {
    switch (opt) {
      case 'a':
        if (mode || 
            optind >= (argc-1)) {
          print_usage_and_exit(argv);
          return 1;
        }
        mode = INSPECT_MEMORY;
        addr = strtoull(argv[optind], NULL, 16);
        len = strtoull(argv[optind+1], NULL, 16);
        break;
      case 'm':
        if (mode) {
          print_usage_and_exit(argv);
          return 1;
        }
        mode = INSPECT_MSR;
        msr = strtoull(argv[optind], NULL, 16);
        break;
      default:
        print_usage_and_exit(argv);
    }
  }

  switch (mode) {
    case INSPECT_MEMORY:
      if(inspect_memory(addr, len)) {
        printf("inspect_memory failed\n");
      }
      break;
    case INSPECT_MSR:
      if (inspect_msr(msr)) {
        printf("inspect_msr failed\n");
      }
      break;
    default:
      print_usage_and_exit(argv);
  }

  return 0;
}
#endif
