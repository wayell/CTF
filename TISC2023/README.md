# TISC 2023 - Writeups
Solved 6 levels of TISC 2023 and got stuck at flag part 2 of Level 7 (DevSecMeow) sadly :( skill issue

![solves](img/solves.png)

Todo writeups! <br /><br />

Level 1: Disk Archaeology (Forensics)

Level 2: XIPHEREHPIX’s Reckless Mistake (Crypto)

Level 3: KPA (Mobile)

Level 4: Really Unfair Battleships Game (Pwn, Misc)

Level 5: PALINDROME’s Invitation (OSINT, Misc)

Level 6B: The Chosen Ones (Web)

Level 7B: DevSecMeow - Flag 1 :< (Cloud) <br /><br />

# Level 1: Disk Archaeology

> Unknown to the world, the sinister organization PALINDROME has been crafting a catastrophic malware that threatens to plunge civilization into chaos. Your mission, if you choose to accept it, is to infiltrate their secret digital lair, a disk image exfiltrated by our spies. This disk holds the key to unraveling their diabolical scheme and preventing the unleashing of a suspected destructive virus.   
> 
>You will be provided with the following file:  
> - md5(challenge.tar.xz) = 80ff51568943a39de4975648e688d6a3  
>  
>  Notes:  
>  - challenge.tar.xz decompresses into challenge.img  
>  - FLAG FORMAT is TISC{some text you have to find}
>  
>   Attached Files
>   challenge.tar.xz

Extract the tar and we get a `challenge.img`

```python
┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/1]
└─$ file challenge.img
challenge.img: Linux rev 1.0 ext4 filesystem data, UUID=2b4fee55-fd5f-483c-a85f-856944731f0f (extents) (64bit) (large files) (huge files)
```

Open up in autopsy and explore the filesystem. While exploring, there is a deleted ELF file. The strings in the file hints to parts of the flag: TISC{w4s_th3r3_s0m3th1ng_l3ft_%s}

![lvl-1-deleted-elf](img/lvl-1-deleted-elf.png)

We probably have to run this file or do some static analysis to get the rest of the flag.

But wait! We can’t actually run it yet. The binary requires `ld-musl-x86_64.so.1` interpreter, which after some searching, is part of the Alpine Linux: [https://pkgs.alpinelinux.org/contents?branch=edge&name=musl&arch=x86_64&repo=main](https://pkgs.alpinelinux.org/contents?branch=edge&name=musl&arch=x86_64&repo=main)

```python
┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/1]
└─$ ./f0000008.elf 
bash: ./f0000008.elf: cannot execute: required file not found

┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/1]
└─$ ldd f0000008.elf                                                                                                                                                                       
        linux-vdso.so.1 (0x00007fffeca09000)
        libc.musl-x86_64.so.1 => not found

┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/1]
└─$ file f0000008.elf                                                                                                                                                                      
f0000008.elf: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-x86_64.so.1, with debug_info, not stripped
```

Using `apt-find` you can actually find the package that contains the library. This gave me the interpreter which i needed to execute the binary and get the flag.

```python
┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/1]
└─$ sudo apt-file find ld-musl-x86_64.so.1
musl: /lib/ld-musl-x86_64.so.1
┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/1]
└─$ sudo apt install musl
┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/1]
└─$ ./f0000008.elf 
TISC{w4s_th3r3_s0m3th1ng_l3ft_ubrekeslydsqdpotohujsgpzqiojwzfq}
```

# Level 2: XIPHEREHPIX’s Reckless Mistake

> Our sources told us that one of PALINDROME's lieutenants, XIPHEREHPIX, wrote a special computer program for certain members of PALINDROME. We have somehow managed to get a copy of the source code and the compiled binary. The intention of the program is unclear, but we think encrypted blob inside the program could contain a valuable secret.
> 
>   Attached Files
>   prog.c
>   XIPHEREHPIX

Running the binary, we can see that it asks for a password that is more than 40 characters long, which we do not have.

```python
┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/2]
└─$ ./XIPHEREHPIX 
Hello PALINDROME member, please enter password:
The password should be at least 40 characters as per PALINDROME's security policy.

┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/2]
└─$ ./XIPHEREHPIX 
Hello PALINDROME member, please enter password:
Failure!
```


The source code is provided as part of the challenge files. Rough description of the different functions:

**`main()`**

- Requests for a password that is at least 40 characters
- Checks our password against `verify_password()`
- Runs `initialise_key()` followed by `show_welcome_message()` with the key that was generated

```python
int main(int argc, char **argv)
{
    char password[MAX_PASSWORD_SIZE + 1] = { 0 };
    int password_length;

    unsigned char key[32];

    printf("Hello PALINDROME member, please enter password:");

    password_length = input_password(password);
    if (password_length < 40) {
        printf("The password should be at least 40 characters as per PALINDROME's security policy.\n");
        exit(0);
    }

    if (!verify_password(password, password_length)) {
        initialise_key(key, password, password_length);
        show_welcome_msg(key);
    }
        
    else {
        printf("Failure! \n");
        exit(0);
    }
}
```

`verify_password()`

- Compares our password against a SHA256 hash `962fe02a147163af8003eb5b7ff756523220981f9f027e35fb933faadd7944b7`
- This probably can’t be bruteforced or guessed, since the password length is minimally 40 characters.
- If the password provided by the user matches the hash, then returns 0 (due to memcmp)

```python
int verify_password(char *password, int password_length) {
    unsigned char mdVal[EVP_MAX_MD_SIZE];
    unsigned int i;

    calculate_sha256(mdVal, password, password_length);

    uint64_t hash[] = { 0x962fe02a147163af,
                        0x8003eb5b7ff75652,
                        0x3220981f9f027e35,
                        0xfb933faadd7944b7};

    return memcmp(mdVal, hash, 32);
}
```

`initialise_key()` and `accumulate_xor()`

- Seed is initialized as "PALINDROME IS THE BEST!", which is used later in the first `calculate_sha256` call
- Creates an array `arr` of 20 elements, each with a size of 256 bits (due to uint256_t)
- The first element of the array is the SHA256 hash of our seed, and the subsequent elements are the SHA256 hash of the element preceding it.
    - First element arr[0]: SHA256("PALINDROME IS THE BEST!")
    - Second element: SHA256(arr[0])
    - Third element: SHA256(arr[1])
    - and so on…
- Loops through each character in our password and subsequenty each bit in the password (in the for (j = 0; j < 8; j++) { loop)
    - `counter` is set so that for each iteration of the bitloop, it’ll go through the next element of the array (so first iter select arr[0], next select arr[1] and so on, until it goes back to arr[0])
    - If the current bit in `ch` we are comparing is 0, no operation will be made
    - however, if the current bit in `ch` is 1, this runs the `accumulate_xor()`
        - which would just XOR the current key256 (which initially is set to 0s) with the selected arr element (based on counter)

```python
void initialise_key(unsigned char *key, char *password, int password_length) {
    const char *seed = "PALINDROME IS THE BEST!";
    int i, j;
    int counter = 0;

    uint256_t *key256  = (uint256_t *)key;

    key256->a0 = 0;
    key256->a1 = 0;
    key256->a2 = 0;
    key256->a3 = 0;

    uint256_t arr[20] = { 0 };

    calculate_sha256((unsigned char *) arr, (unsigned char *) seed, strlen(seed));

    for (i = 1; i < 20; i++) {
        calculate_sha256((unsigned char *)(arr+i), (unsigned char *) (arr+i-1), 32);
    }

    for (i = 0; i < password_length; i++) {
        int ch = password[i];
        for (j = 0; j < 8; j++) {
            counter = counter % 20;

            if (ch & 0x1) {
                accumulate_xor(key256, arr+counter);
            }

            ch = ch >> 1;
            counter++;
        }
    }
}

void accumulate_xor(uint256_t *result, uint256_t *arr_entry) {
    result->a0 ^= arr_entry->a0;
    result->a1 ^= arr_entry->a1;
    result->a2 ^= arr_entry->a2;
    result->a3 ^= arr_entry->a3;

}
```

`show_welcome_msg()`

- AES-GCM implementation to decrypt the ciphertext
- iv, tags etc are all known/fixed, which isn’t an ideal implementation
- However without knowledge of the correct key, we’re unable to really attack this implementation

```python
void show_welcome_msg(unsigned char *key) {
    int plaintext_length;
    unsigned char *iv = "PALINDROME ROCKS";
    
    unsigned char plaintext[128] = { 0 };
    const unsigned char * const header = "welcome_message";
    unsigned char ciphertext[] =
        "\xad\xac\x81\x20\xc6\xd5\xb1\xb8\x3a\x2a\xa8\x54\xe6\x5f\x9a\xad"
        "\xa4\x39\x05\xd9\x21\xae\xab\x50\x98\xbd\xe4\xc8\xe8\x2a\x3c\x63"
        "\x82\xe3\x8e\x5d\x79\xf0\xc6\xf4\xf2\xe7";

    unsigned char tag[] =
        "\xbd\xfc\xc0\xdb\xd9\x09\xed\x66\x37\x34\x75\x11\x75\xa2\x7a\xaf";

    plaintext_length = gcm_decrypt(ciphertext, 
                42,
                (unsigned char *)header,
                strlen(header),
                tag,
                key, 
                iv,
                16,
                plaintext);

    printf("Welcome PALINDROME member. Your secret message is %.*s\n", plaintext_length, plaintext);
}
```

From here, we can get the rough idea on how we can solve the challenge. The weakness lies in the `initialize_key` implementation, which essentially reduces the keyspace size to 2^20 due to the commutative properties of XOR. We’re not interested in the possible passwords anymore, but instead the possible keys that could have been used in the decryption function. We can do a keyspace brute force which allows us to recover the flag.


To solve this, we change the main function as follows. This will just test the `show_welcome_message` against every single possible key. Also do note that the size has been passed in as 3 bytes, as we’re trying to brute force 20 bits, essentially taking up 3 bytes. 


2^20 equates to 1048576, alternatively we can also use `i < (1 << 20)` instead of `i < 1048576`

```python
int main(int argc, char **argv)
{
    char password[MAX_PASSWORD_SIZE + 1] = { 0 };
    int password_length;

    unsigned char key[32];

    printf("Hello PALINDROME member, please enter password:");

    for(int i = 0; i < 1048576; i++) {
        unsigned char * bruteKey = (unsigned char *)&i;
        initialise_key(key, bruteKey, 3);
        show_welcome_msg(key);
    }
}
```


Compile and run the program, we can grep for the flag format and get our flag:

```python
┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/2]
└─$ gcc solve.c -o solve -lcrypto

┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/2]
└─$ ./solve | grep TISC
Welcome PALINDROME member. Your secret message is TISC{K3ysP4ce_1s_t00_smol_d2g7d97agsd8yhr}
```

# Level 3: KPA

> We've managed to grab an app from a suspicious device just before it got reset! The copying couldn't finish so some of the last few bytes got corrupted... But not all is lost! We heard that the file shouldn't have any comments in it! Help us uncover the secrets within this app!
> 
>   Attached Files
>   kpa.apk

TODO

# Level 4: Really Unfair Battleships Game

> After last year's hit online RPG game "Slay The Dragon", the cybercriminal organization PALINDROME has once again released another seemingly impossible game called "Really Unfair Battleships Game" (RUBG). This version of Battleships is played on a 16x16 grid, and you only have one life. Once again, we suspect that the game is being used as a recruitment campaign. So once again, you're up!
>
> Things are a little different this time. According to the intelligence we've gathered, just getting a VICTORY in the game is not enough.
>
> PALINDROME would only be handing out flags to hackers who can get a FLAWLESS VICTORY.
>
> You are tasked to beat the game and provide us with the flag (a string in the format TISC{xxx}) that would be displayed after getting a FLAWLESS VICTORY. Our success is critical to ensure the safety of Singapore's cyberspace, as it would allow us to send more undercover operatives to infiltrate PALINDROME.
>
> Godspeed!
>
> You will be provided with the following:
>
> 1) Windows Client (.exe)
    - Client takes a while to launch, please wait a few seconds.
    - If Windows SmartScreen pops up, tell it to run the client anyway.
    - If exe does not run, make sure Windows Defender isn't putting it on quarantine.
>
> 2) Linux Client (.AppImage)
    - Please install fuse before running, you can do "sudo apt install -y fuse"
    - Tested to work on Ubuntu 22.04 LTS
> 
>   Attached Files
>   rubg-1.0.0.AppImage
>   rubg_1.0.0.exe

TODO

# Level 5: PALINDROME’s Invitation

> Valuable intel suggests that PALINDROME has established a secret online chat room for their members to discuss on plans to invade Singapore's cyber space. One of their junior developers accidentally left a repository public, but he was quick enough to remove all the commit history, only leaving some non-classified files behind. One might be able to just dig out some secrets of PALINDROME and get invited to their secret chat room...who knows?
>  
>  Start here: https://github.com/palindrome-wow/PALINDROME-PORTAL

TODO

# Level 6B: The Chosen Ones

> We have discovered PALINDROME's recruitment site. Infiltrate it and see what you can find!
>
> http://chals.tisc23.ctf.sg:51943

TODO

# Level 7B: DevSecMeow - Flag 1

> Palindrome has accidentally exposed one of their onboarding guide! Sneak in as a new developer and exfiltrate any meaningful intelligence on their production system.
>
> https://d3mg5a7c6anwbv.cloudfront.net/
>
> Note: Concatenate flag1 and flag2 to form the flag for submission.

TODO
