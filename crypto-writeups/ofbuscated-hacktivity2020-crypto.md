# HacktivityConCTF - OFBuscated

## OFBuscation

## Briefing

```text
I just learned some lesser used AES versions and decided to make my own!

Connect here:
nc jh2i.com 50028
```

### Intro

This challenge was one of the crypto challenges in Hacktivity CTF

It provided a python script, `ofbuscated.py`, and a network service running this script.

### Writeup

#### Part 0x00: AES-OFB mode

Like my other writeups, I'll start with the fundamentals of this challenge. In this case, I'll have a look at AES-OFB \(which is what the title hints at\).

OFB \(Output FeedBack\) mode is a mode that has become quite redundant due to the fact that it has no real advantage over the more common CTR mode.

The method of encryption is as follows:

Firstly, like any AES mode, there is a key, and then with OFB, you also have an IV. Then:

* Encrypt the IV using AES-ECB and the key as the key.
* Sets the new IV to the encrypted IV
* Xor the plaintext block with the encrypted IV, and then these blocks are concatenated and then outputted.

This repeats for each block.

This means that, if the IV and key are kept constant, encryption and decryption are exactly the same, since it uses the same keystream.

#### Part 0x01: Reversing the script

The only important functions are the `handle`, `encrypt`,`byte_xor` and `shuffle` functions.

```python
def handle(self):
    assert len(flag) % 16 == 1
    blocks = self.shuffle(flag)
    ct = self.encrypt(blocks)
    self.send(binascii.hexlify(ct))

def byte_xor(self, ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def encrypt(self, blocks):
    curr = iv
    ct = []
    cipher = AES.new(key, AES.MODE_ECB)
    for block in blocks:
        curr = cipher.encrypt(curr)
        ct.append(self.byte_xor(block, curr))
    return b''.join(ct)

def shuffle(self, pt):
    pt = pad(pt, 16)
    pt = [pt[i: i + 16] for i in range(0, len(pt), 16)]
    random.shuffle(pt)
    return pt
```

First, let's get the easy two function out of the way, which are `byte_xor` and `shuffle` `byte_xor` does exactly what you would expect, it XOR's two byte string together.

`shuffle`:

* takes in the `pt`
* pads it using PKSC7
* splits it into blocks of 16
* randomly shuffles these blocks, returning them.

Ok, that's those two out of the way, let's look at `encrypt`.

`encrypt` takes in `blocks`, then:

* sets the `curr` variable to `iv`, and creates an array `ct`

  Then, for each `block` in `blocks`:

* Encrypts `curr` with ECB using the key as the key.
* XORs the block with this encrypted `curr`
* Appends this XORed block to `ct`

  After this, it just returns all the blocks concatenated together.

Finally, let's look at `handle`, this appears to be the actual flow of the program.

`handle`:

* reads "flag.txt", which is presumably the flag
* makes sure the length of `flag` is a multiple of 16 plus 1
* calls the shuffle function on the flag
* calls the encrypt function on the blocks returned by shuffle
* outputs the hex of the encrypted blocks.

So, the entire program basically, on a connection:

* It takes the flag.txt, and reads this
* Pads this data using pkcs7 padding
* Splits the data into blocks of 16 bytes
* Randomly shuffles these blocks
* Encrypts the blocks with the OFB we mentioned above.
* Outputs the hex of the encrypted blocks concatenated together

#### Part 0x02: Exploitation

We start by receiving one set of data.

`fb1f66cd01ffcc75787bfbd27d4d22cd652fb2a6ae6732fb47eb3870203ceb493fb165f56203bb0bebe6812da4eeb0db`

This doesn't tell us much, but it tells us that the plaintext consists of three blocks. Knowing this, and knowing that, from earlier, the ciphertext has to have length of a multiple of 16 plus 1, which means we know that the length of the plaintext must be 33 bytes.

Knowing this, we can get even further, since we know that the flag is in flag{flag} format, and so we know that the last character is "}". Since the data is also PKCS7 padded, we can deduce that the last block is "}\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f".

This means that it is possible to partially recover the keystream used for encryptions, since we know for certain one of the blocks is the block mentioned above. Since there are only three blocks, bruteforce is very feasible.

#### Part 0x03: Decryption

To check which keystream we have recovered, we need to receive another set of data.

`f24f00b65180b6161b2b9da92d2e42ae771cbab58a7528e774dd255b0b27ed5624d20b9d166edb74bb80fa7ddf96d6a7`

Now, we can simply XOR each block of our first received data, and then XOR that key against this to see which block was the known block.

```text
fb1f66cd01ffcc75787bfbd27d4d22cd ^ 7d0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f = 861069c20ef0c37a7774f4dd72422dc2
652fb2a6ae6732fb47eb3870203ceb49 ^ 7d0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f = 1820bda9a1683df448e4377f2f33e446
3fb165f56203bb0bebe6812da4eeb0db ^ 7d0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f = 42be6afa6d0cb404e4e98e22abe1bfd4
```

One of these will result in the correct key, because one of these blocks is definitely the 7d0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f block.

So, we concatenate our potential keystream, and then XOR that with our second set of data.

This gives us `745f69745f70756c6c5f69745f6c6f6c6f3c071c2b1d15133c39122424140910666c61677b626f705f69745f74776973`, which we can decode from hex to get `t_it_pull_it_lolo<..+...<9.$$..flag{bop_it_twis`, which is our flag.

**Flag: flag{bop\_it\_twist\_it\_pull\_it\_lol}**

### Conclusion

Overall, a fun and quick challenge from HacktivityConCTF 2020. Thanks to Soul for making it :\)

**\(P.S. I genuinely don't know how that worked, since we should only have recovered the keystream for one block, but if it works, it works?\)**

