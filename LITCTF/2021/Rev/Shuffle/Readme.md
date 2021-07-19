# Shuffle
>How can we possibly decode this? (Please note that [:-1] does not remove anything from the flag, as it just strips the newline character)
>
>138 solves / 119 points

We are provided with the shuffle.py, shuffle.txt file.

The shuffle.py code uses random.shuffle() to generate the shuffle.txt file.

However, the random.seed is generated using randint(0,1000) which we can easily brute force.

```
$ python3 shufflesolve.py | grep flag
flag{y0u_are_gen1051ty_0rz}
```
