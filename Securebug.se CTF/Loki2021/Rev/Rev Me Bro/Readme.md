### Rev Me Bro

I'm not good at doing reverse challenges, and have very limited coding and maths knowledge so I'm really happy to be able to have solved this one. Unfortunately I couldn't solve Medium and Hard rev challenges, but I'll be looking and learning from other people's writeups.

Difficulty: Easy

Given an APK file, and we have to reverse it.

Flag format: SBCTF{.....}

After the usual initial static enumeration (file, exiftool, etc), we can change this APK into a JAR file to further analyze it as we'll be able to see the Java code.

Using d2j-dex2jar we can convert APKs to JAR.

```
$ d2j-dex2jar RevMeBro.apk rev.jar.jar
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
dex2jar RevMeBro.apk -> ./RevMeBro-dex2jar.jar
dex2jar rev.jar.jar -> ./rev.jar-dex2jar.jar
java.nio.file.NoSuchFileException: rev.jar.jar
        at java.base/sun.nio.fs.UnixException.translateToIOException(UnixException.java:92)
        at java.base/sun.nio.fs.UnixException.rethrowAsIOException(UnixException.java:111)
        at java.base/sun.nio.fs.UnixException.rethrowAsIOException(UnixException.java:116)
        at java.base/sun.nio.fs.UnixFileSystemProvider.newByteChannel(UnixFileSystemProvider.java:219)
        at java.base/java.nio.file.Files.newByteChannel(Files.java:371)
        at java.base/java.nio.file.Files.newByteChannel(Files.java:422)
        at java.base/java.nio.file.Files.readAllBytes(Files.java:3206)
        at com.googlecode.dex2jar.tools.Dex2jarCmd.doCommandLine(Dex2jarCmd.java:108)
        at com.googlecode.dex2jar.tools.BaseCmd.doMain(BaseCmd.java:290)
        at com.googlecode.dex2jar.tools.Dex2jarCmd.main(Dex2jarCmd.java:33)
```

Now we have a .jar file which we can decompile. I am using jd-gui.

We go to MainActivity.class (similar to main() in C).

MainActivity.class()

```
package com.example.sbctf_rev_me;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
  protected void onCreate(Bundle paramBundle) {
    super.onCreate(paramBundle);
    setContentView(2131427356);
    ((Button)findViewById(2131230807)).setOnClickListener(new View.OnClickListener() {
          public void onClick(View param1View) {
            if ((new doer()).doer("yourMessage").equals("[IITO{LHZPb_EUNRTIHfXE_IVNe0:}")) {
              Toast.makeText(MainActivity.this.getApplicationContext(), "you got it", 1).show();
            } else {
              Toast.makeText(MainActivity.this.getApplicationContext(), "better lock next time", 1).show();
            } 
          }
        });
  }
}
```

Looks like the code will take our input, parse it through doer() function, and compare the output with "[IITO{LHZPb_EUNRTIHfXE_IVNe0:}"

We can take a further look at the doer() function.

```
package com.example.sbctf_rev_me;

import java.util.Random;

public class doer {
  public String doer(String paramString) {
    char[] arrayOfChar = paramString.toCharArray();
    int[] arrayOfInt = new int[6];
    Random random = new Random();
    byte b;
    for (b = 0; b < 5; b++)
      arrayOfInt[b] = random.nextInt(9); 
    int i = arrayOfChar.length;
    boolean bool = false;
    int j = 0;
    for (b = 0; b < i; b++) {
      char c = arrayOfChar[b];
      arrayOfChar[j] = (char)(char)(arrayOfInt[j % 6] + c);
      j++;
    } 
    for (b = 0; b < arrayOfChar.length; b++) {
      if (b % 2 == 0)
        arrayOfChar[b] = (char)(char)(arrayOfChar[b] ^ 0x2); 
    } 
    for (b = 0; b < arrayOfChar.length; b++) {
      if (b % 5 == 0)
        arrayOfChar[b] = (char)(char)(arrayOfChar[b] + 255 - 255); 
      if (b % 3 == 0)
        arrayOfChar[b] = (char)(char)(arrayOfChar[b] + 282 - 282); 
    } 
    StringBuilder stringBuilder = new StringBuilder();
    j = arrayOfChar.length;
    for (b = bool; b < j; b++)
      stringBuilder.append(arrayOfChar[b]); 
    return stringBuilder.toString();
  }
}
```

The first time I saw this I was thinking that it looks pretty complicated. However taking a more in-depth look, it wasn't too difficult and we can break it down into a few parts:

Your input is stored in char format, in a list (inputList).

1. An integer array of 6 indexes is created (intList). This array is looped through from index 0-4, and each loop a random.nextInt(9) function is called to generate a random number from 0-8 and add it to each element of the index. However, the last index (5) is untouched, which by default will equal 0.

2. Loops through each item in our inputList, and adds intList[inputList % 6] to it. This means for first character in inputList, it will add first element of intList, and so on, 6th character 6th element, 7th character 1st element (due to modulus).

3. Loops through each item in our inputList, if the index is divisible by 2 (%2), then it will do an XOR with 2 for the element in that index. (inputList[i] ^ 0x02)

4. Loops through each item in our inputList, if index divisible by 5 or divisible by 3, it will add +255-255 or +282-282 respectively, which in other words it will do absolutely nothing because it will just add 0.

Afterwards, it will join back our inputList and compare it with the string '[IITO{LHZPb_EUNRTIHfXE_IVNe0:}'

Breaking down the code into different parts really helped me get a better idea of how to reverse it. With this information we can start to craft our code to reverse it.

I managed to make the following code with very limited Python knowledge. There are probabaly many way more efficient ways to do it, but this what I could come up with.

---

### The code


Since I am reversing it from the encoded string itself, I needed to code it such that it started from the last step to the first step.

The problem comes when we want to reverse step 1&2, because we do not know what the random.nextInt(9) has generated for the intArray.

To solve this, we can map the first 5 characters to SBCTF, which is the flag format, and get the first 5 elements by subtracting the char value of the encoded string with the char values of SBCTF.

1. First do the % 5 and % 3 code, actually this part can be omitted because it wouldn't do anything anyways.

2. Then, for each even number index, we will XOR with 2

3. Compare the difference between the first 5 elements of our encoded string with SBCTF to get the values of intArray. Then add a 0 as intArray contains 6 indexes but the last one was not randomly generated and would be 0.

4. Now we can loop through our encoded string and subtract each element with the corresponding value in intArray. 

Change it from char back into ASCII format and we will get our string.

```
cipher = list('[IITO{LHZPb_EUNRTIHfXE_IVNe0:}')

compare = list('SBCTF')

for i in range(len(compare)):
    compare[i] = ord(compare[i])

#stage 3 - does absolutely nothing
for i in range(len(cipher)):
    cipher[i] = ord(cipher[i])
    if cipher[i] % 5 == 0:
        cipher[i] = cipher[i] + 255 - 255
    elif cipher[i] % 3 == 0:
        cipher[i] = cipher[i] + 282 - 282

#stage 2
for i in range(len(cipher)):
    if i % 2 == 0:
        cipher[i] = cipher[i]^0x2

#finding offset
for i in range(len(compare)):
    compare[i] = cipher[i] - compare[i]

#append 0 to list (intarray 6 indexes but only 5 have values)
compare.append(0)

#stage 1
for i in range(len(cipher)):
    c = compare[i%6]
    cipher[i] = chr(cipher[i] - c)

print(''.join(cipher))
```

Running the script:
```
$ python3 pysolve.py 
SBCTF{HAPPY_ANDROID_REVING_01}
```
