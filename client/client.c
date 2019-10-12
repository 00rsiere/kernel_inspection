#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>

#include <capstone/capstone.h>

#include "lib/inspect.h"
#include "inspection.h"


int disassemble(char *code, size_t len, unsigned long long offset)
{
  csh handle;
  cs_insn *insn;
  size_t count;

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    return 1;

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

int do_inspect_memory(unsigned long long addr, size_t len)
{
  int err = 0;
  char *buf = NULL;

  buf = (char *)malloc(len);

  if (!buf) {
    err = 1;
    goto finish;
  }

  if (inspect_memory(addr, buf, len)) {
    err = 1;
    goto finish;
  }

  if (disassemble(buf, len, addr)) {
    return 1;
  }

finish:
  if (buf) {
    free(buf);
  }

  return err;
}

int do_inspect_msr(unsigned int msr)
{
  unsigned long long out_msr = 0;

  if (inspect_msr(msr, &out_msr)) {
    return 1;
  }

  printf("%llx\n", out_msr);

  return 0;
}

void print_usage_and_exit(char **argv)
{
  printf("usage: %s [-a address size] / [-m msr]\n", argv[0]);
  exit(1);
}

int main(int argc, char **argv)
{
  int opt;
  int len = 0;
  unsigned long long addr = 0;
  unsigned int msr = 0;
  unsigned long long out_msr = 0;

  enum inspection_type mode = INVALID_TYPE;

  if (geteuid()) {
    printf("WARNING: inspection requires root privileges, inspection will probably not work.\n");
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
      if(do_inspect_memory(addr, len)) {
        printf("inspect_memory failed\n");
      }
      break;
    case INSPECT_MSR:
      if (do_inspect_msr(msr)) {
        printf("inspect_msr failed\n");
      }
      break;
    default:
      print_usage_and_exit(argv);
  }

  return 0;
}
