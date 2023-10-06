# TISC 2023 - Writeups
Solved 6 levels of TISC 2023 and got stuck at flag part 2 of Level 7 (DevSecMeow) sadly :( skill issue

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

TODO

# Level 2: XIPHEREHPIX’s Reckless Mistake

> Our sources told us that one of PALINDROME's lieutenants, XIPHEREHPIX, wrote a special computer program for certain members of PALINDROME. We have somehow managed to get a copy of the source code and the compiled binary. The intention of the program is unclear, but we think encrypted blob inside the program could contain a valuable secret.
> 
>   Attached Files
>   prog.c
>   XIPHEREHPIX

TODO

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
