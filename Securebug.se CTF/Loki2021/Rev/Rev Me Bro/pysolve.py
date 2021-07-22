cipher = list('[IITO{LHZPb_EUNRTIHfXE_IVNe0:}')

compare = list('SBCTF')

# turn cipher into chararray
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
