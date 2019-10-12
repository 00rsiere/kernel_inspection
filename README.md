A simple tool to inspect disassembly of kernel addresses and MSRs.
The code inspects a running kernel, any bug may cause system instability - use at your own risk

### Installation

make all
sudo insmod driver/inspector.ko

#### Usage

sudo ./client/inspect_client -m [ msr_number ]
sudo ./client/inspect_client -a [ kernel_address ] length

#### Example

grab address of syscall entry (x86-64) (MSR_LSTAR) and disassemble 100 bytes

entry_syscall_addr=`sudo ./client/inspect_client -m 0xc0000082` && sudo ./client/inspect_client -a $entry_syscall_addr 100
