# Androids Encryption

## Contents
[Briefing](https://github.com/willwam845/CTF-Writeups/blob/master/AndroidEncryption/Writeup.md#Briefing)

[Intro](https://github.com/willwam845/CTF-Writeups/blob/master/AndroidEncryption/Writeup.md#Intro)

[Writeup](https://github.com/willwam845/CTF-Writeups/blob/master/AndroidEncryption/Writeup.md#Writeup)

[Conclusion](https://github.com/willwam845/CTF-Writeups/blob/master/AndroidEncryption/Writeup.md#Conclusion)

## Briefing
```
We intercept an algorithm that is used among Androids. There are many hidden variables. Is it possible to recover the message?

Author: andre_smaira

Server: nc encryption.pwn2.win 1337
```
## Intro

This challenge was one of the crypto challenges in Pwn2WinCTF 2020, which was the most solved, and at the end was worth 115 points.

It provided a python script, `server.py`, and a network service running this script.

## Writeup

### Part 0x00 - AES Fundamentals

Seeing as this was one of the simpler challenges, I thought I would start from the very basics of this challenge, starting with talking about AES-EBC and AES-CBC.

The actual AES part itself, which I will be representing as `->` for the rest of this writeup, simply takes in a key, and then does some weird things that I won't go into detail into, and then outputs a string the same length as the input.

AES-EBC, when encrypting, will take each block of ciphertext based on key length, and then putting each block through AES encryption. These encrypted blocks are then concatenated together and returned.

AES-CBC on the other hand, when encrypting, will first XOR the first block of **plaintext** with another string, called the IV or **initialization vector**, which is the same length as the block. After this XOR process, we then encrypt as if it were AES-EBC, simply putting it through the AES. Then, for the next block, the first block of **ciphertext** as the initialization vector, which we XOR with the next block of **plaintext**, and then put it through AES, and so on and so on.

Once this is done, the encrypted blocks are then concatenated and returned.

### Part 0x01 - Reversing the script

It is probably easier to look at the flow of the program and seeing what it does before actually trying to reverse the specific parts, so that we don't fall into too many rabbit holes.

We can see that it starts by calling `main`, which then calls `menu`.

```py
def menu():
    while True:
        print('MENU')
        options = [('Encrypt your secret', enc_plaintext),
                   ('Encrypt my secret', enc_flag),
                   ('Exit', sys.exit)
                   ]
        for i, (op, _) in enumerate(options):
            print(f'{i+1} - {op}')
        print('Choice: ', end='')
        op = input().strip()
        assert op in ['1', '2', '3'], 'Invalid option'
        options[ord(op)-ord('1')][1]()
```

The menu function appears to takes in a user input, and then calls a function based on this input.

It will call `enc_plaintext` if the input is 1, `enc_flag` if the input is 2, and `sys.exit` if the input is 3.

Let's take a look at the `enc_plaintext` function first.

```py
def enc_plaintext():
    print('Plaintext: ', end='')
    txt = base64.b64decode(input().rstrip())
    print(encrypt(txt, key1, iv1))
```

This appears to take in an input, base64 decode it, and then print the result of `encrypt()` with the parameters of the base64 decoded input, `key1` (which is the AES key used), and `iv1` (which is the initialization vector used).

If we look further up, we can see that `key1` and `iv1` are imported from a `secrets` package, meaning that they are constant and we will not be able to get access to them. There is also, interestingly, a flag variable being imported from `secrets` as well.

Ok, well now let's take a look at the `enc_flag` function.

```py
def enc_flag():
    print(encrypt(flag, key2, iv2))
```

This looks fairly simple. It simply prints the output of `encrypt()` with parameters `flag`, which is most likely the flag, and is being imported from `secrets`, `iv2`, and `key2`.

But wait, where are `key2` and `iv2` being gotten from if we don't import them? Well...

If we look further down, we can see these two lines.

```py
iv2 = AES.new(key1, AES.MODE_ECB).decrypt(iv1)
key2 = xor(to_blocks(flag))
```

We can see that `iv2` is being calculated by decrypting `iv1` using AES-EBC (the one that only requires a key), and using `key1` as the key.

We see `key2` is calculated by running the `xor` function on the output of the `to_blocks` function with the parameter `flag`, which is the one imported at the start.

But what do these `xor` and `to_blocks` functions do in the first place? Well, let's take a look at them then.

(Don't worry, I'll get onto `encrypt` later...)

### Part 0x02 - Other functions

So we saw the `xor` and `to_blocks` functions. But what do they actually do?

Let's start with the `to_blocks` function.

```py
def to_blocks(txt):
    return [txt[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE] for i in range(len(txt)//BLOCK_SIZE)]
```

Wow, this looks like a mess. Let's try and clean this up a bit.

The `BLOCK_SIZE` variable is 16, so let's start by replacing that. Let's also put the loop at the start to make it look tidier.

```py
def to_blocks(txt):
  o = []
  for i in range(len(txt)//16):
    o.append(txt[i*16:(i+1)*16])
    return o
```

Ah, this looks much easier to reverse. So, we can see that we have a for loop that repeats the number of times the `txt` parameter is divisible by 16, with the remainder ignored.

We then see that the string takes a chunk of 16 chars by adding the chars from index `i*16` to `(i+1)*16` to the array of `o`. The array is then returned.

So it basically just splits the `txt` parameter into chunks of 16 chars, and returns it.

Now, let's take a look at the `xor` function.

```py
def xor(b1, b2=None):
    if isinstance(b1, list) and b2 is None:
        assert len(set([len(b) for b in b1])) == 1, 'xor() - Invalid input size'
        assert all([isinstance(b, bytes) for b in b1]), 'xor() - Invalid input type'
        x = [len(b) for b in b1][0]*b'\x00'
        for b in b1:
            x = xor(x, b)
        return x
    assert isinstance(b1, bytes) and isinstance(b2, bytes), 'xor() - Invalid input type'
    return bytes([a ^ b for a, b in zip(b1, b2)])
```
Wow, this also looks really messy. Seeing as most of this is just checking different things, for example that the first parameter is a list, we are going to remove these and take a look at what the function is actually doing.

We can see this function is called with the `to_blocks` function, so we know the input has to be a list. If we actually take an output of this function, we can see the output is something like:

```
[b'helphelphelphelp', b'helphelphelphelp', b'helphelphelphelp', b'helphelphelphelp']
```

So we know that the input for `xor` is just a list of bytes.

Now, what does the `xor` function actually do? Well, to save you all the time of me debugging it, I found out that this function simply takes in the list, and then does a bitwise XOR on each block, XORing every block with each other, and then returning the result.

So now that we have that figured out. However, there is still one function we haven't looked at, and it is the biggest one, and most important one...

### Part 0x03 - The encrypt() function

```py
def encrypt(txt, key, iv):
    global key2, iv2
    assert len(key) == BLOCK_SIZE, f'Invalid key size'
    assert len(iv) == BLOCK_SIZE, 'Invalid IV size'
    assert len(txt) % BLOCK_SIZE == 0, 'Invalid plaintext size'
    bs = len(key)
    blocks = to_blocks(txt)
    ctxt = b''
    aes = AES.new(key, AES.MODE_ECB)
    curr = iv
    for block in blocks:
        ctxt += aes.encrypt(xor(block, curr))
        curr = xor(ctxt[-bs:], block)
    iv2 = AES.new(key2, AES.MODE_ECB).decrypt(iv2)
    key2 = xor(to_blocks(ctxt))
    return str(base64.b64encode(iv+ctxt), encoding='utf8')
```

Wow, this is definitely a very big function. However, if we just reverse it, we can actually see it is way simpler than upon first looking.

We can see a few checks at the start to make sure that the key, iv are of length 16, and the plaintext, or `txt`, is has a length which is a multiple of 16.

We then see the `to_blocks` function being run on the plaintext, and stored in `blocks`

Next, it appears to encrypt the first **block** in `blocks` with AES-EBC, however it appears to perform the `xor` function on the **block** and the `curr` variable. If we look at the lines above, we can see this `curr` variable is actually the `iv` parameter at first.

It then takes the output of this AES and then adds it to the `ctxt` variable.

Then, the `curr` variable is updated to be the xoring of the previous ciphertext block and the current block.

If we look at this as a whole, this seems exactly like AES-CBC encryption, and therefore all of this was just a distraction.

After the `ctxt` variable is worked out, `iv2` and `key2` appear to be recalculated, where `iv2` is the decrypted version of the previous `iv2` using the current `key2` as the key for this. The `key2` variable is calculated by performing the `xor` function on the recently worked out `ctext` variable.

The original `iv` parameter and recently worked out `ctxt` variables are then concatenated, base64d, and then returned.

### Part 0x04 - Exploitation

The end goal is to get the `flag` variable, so it appears the `enc_plaintext` function is useless to us, and we only need to focus on the `enc_flag` function.

Now, we know that the `flag` variable is encrypted using AES-CBC with `key2` as the key and `iv2` as the iv. We know that these are recalculated each time, so they do not remain constant and we need to find a way to get them.

However, we know how they are calculated, as `key2` is simply just the ciphertext blocks of the previous encryption XORed together. And, we don't need to calculate `iv2` if we want, because it will get returned to us with the ciphertext at the end.

This means it is possible to retrieve a **ct**, **iv**, **key** triplet in just 2 calls of the `enc_flag` function.

We can get the **iv** and **ct** pair from just calling the function once, but because the key is calculated with the old **ctxt**, we cannot work out it with just one call of the function.

So, our plan is:

- call the function once to get an **iv** + **ct**, and then we work out `key2` for the next time we call the function by XORing the **ct** blocks together
- call the function once more to get the **iv** and **ct** that work with the `key2` that we just calculated.
- decrypt the **ct** with the **key** of `key2` that we calculated and the **iv** which is prepended to the output to get the flag!

### Part 0x05 - Decryption

(These aren't real values, I forgot to get some actual ones for the previous ct)

So, with one call of the function, we were able to get the hex output of
```
9ff910a973cd270b96cae3db067bc4e7
f01856fce5089119c83f3b9aa42e56c1
6fe1465596c5b6125ef5d841a2559226
3b7180e752edc27da0a4251f094aa7e0
```

The first block is our iv, and then the next three lines are our ciphertext blocks. We XOR these together to get our key2 for the next round, which is:`a488904e2120e576366ec6c40f316307`

We then call the function again to get another output, which is
```
e10073fb055574939c9d94f002d52f09
1cc12214c5225d1534a147acc20a3b2d
8ee135ae9390c281c2684cb1a080bd2f
7ef96352769853980a57772b04aeebee
```

The first block again, is our iv, and the rest is our ciphertext. Now that we have the key that goes with this iv:ct pair, we can write a short script to decrypt this, which is in solve.py.

We can then use this to get the flag.

#### Flag: CTF-BR{kn3W_7h4T_7hEr3_4r3_Pc8C_r3pe471ti0ns?!?}

## Conclusion

In conclusion, this was a fairly basic crypto challenge where the challenge was more in figuring out what each bit did, rather than the actual crypto part.

Overall, it was a pretty fun challenge! Thanks to the organizers of Pwn2WinCTF for making this my one and only solve during the competition, it was very fun to work through :)
