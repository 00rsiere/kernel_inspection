#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <capstone/capstone.h>

struct ioctl_arg {
   unsigned long long addr;
   unsigned long long len;
   char *out_buf;
   size_t out_len;
};

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

int main(int argc, char **argv)
{
  int fd;
  char *buf = NULL;
  int len = 0;
  unsigned long long addr = 0;
  struct ioctl_arg arg;
  
  if (argc < 3) {
    printf("usage: %s address size\n", argv[0]);
    return 1;
  }

  len = strtoull(argv[2], NULL, 16);
  buf = malloc(len);
  if (!buf) {
    printf("malloc fail\n");
    return 1;
  }

  addr = strtoull(argv[1], NULL, 16);

  arg.addr = addr;
  arg.len = len;
  arg.out_buf = buf;
  arg.out_len = len;

  fd = open("/dev/tracer", O_NONBLOCK);
  ioctl(fd, (unsigned long)&arg);

  disassemble(buf, len, addr);
  return 0;
}
