# DUCTF-Survey

## Survey

## Description

Survey was a 10 point survey challenge from DUCTF. Like many survey challenges, this survey is vulnerable to a KPBSA, but as usual, with a twist.

```
The organising team have put a lot of effort and love into making DUCTF. We would really appreciate your honest feedback!

https://duc.tf/feedback
```

The link redirects to a Google Form with URL `https://docs.google.com/forms/d/e/1FAIpQLSe0p_fubEBQWwr0jtxiEXA64hali4QR_EC1YCnWEV0LnJEnkw/viewform`. If we remind ourselves about other survey challenges, we know that Google Forms is vulnerable to a KPBSA.

## Challenge

Now, as usual, we are looking for a flag, and conveniently, they have provided us with a sample flag! This will be very useful in KPBSA, as it is a "Known Plaintext" attack after all. We are given: `DUCTF{th1s_i5_4_s4mpl3_fl4g'+!-.@#$%?}`, so let's try and use this for our KPBSA.

Again, Google Forms are all the same, encrypted with Rot26, followed by a XOR with key 0x00000000000000000000000000000000, and finally encrypted with secure 2048-bit RSA using e=1.

However, Google appears to have patched this. If we look at the release notes for the new update, we see:

```
Update 4.55
- Increased the security of the encryption to prevent against KPBSA:
  - Changed ROT26 to ROT2600 for maximum security
  - Quad grade XOR encryption implemented, source code below
  - Using d instead of e for encryption, since apparently using e = 1 is not secure...
- Patched error where forensics could be selected for worst category
- Removed the option to select OSINT as a category
- Added an upside down survey option for the Australians
```
```python
# Quad grade XOR!
c = [] # Our plaintext
m1 = os.urandom(len(c))
for i in range(2, 2**(random.randint(2, 10))):
  c = xor(m1, xor(m1, xor(xor(m1, xor(c, m1)), m1)))
return c
```

Now, we have to modify our script in order to bypass these checks.

Firstly, we need to bypass ROT2600. This is the equivalent of ROT26 100 times. ROT26 is very secure, but what if we do it multiple times?

Let's think about it like this:

ROT26 + ROT26 = ROT0, since the rot26's cancel out. This is in the case of ROT52, or ROT26 * 2.

Now, we have ROT2600, or ROT26 * 100, which also means that this will also resolve to ROT0!

Next, we have the quad grade XOR encryption. We see that it does XOR many times, with a random string too? How are we ever going to bypass this?

The thing to notice is the number of times XOR is done is a multiple of 2. This means that, like the ROT26, it will cancel out, leaving us with a plaintext which is XORed with 0x00000000000000000000000000000000. We know how to reverse this from our old KPBSA, so that is sorted.

Finally, the RSA. Using d to encrypt? How are we going to bypass that?

Well, we know that e=1, and therefore, d will also equal 1. Therefore, we do the exact same thing as before, but using d instead of e.

We yoink our old KPBSA script, replacing the parts that need replacing, and then use the flag format, `DUCTF{` as our known plaintext.

Script below.

```python
import codecs
import requests
from Crypto.Util.number import long_to_bytes, bytes_to_long
import random

def xor(a, b):
    return bytes([_a ^ _b for _a, _b in zip(a, b)])

def decode(line):
  # e = 1, therefore c ** 1 mod n = c, we can decrypt this easily
  n = 2226661665757498986810932425216066347092520769069409495331289128234142688050692464852518101428721435013655794120144547554083022505951465212531044535217504740896602849731680614215633892716262100477476994953423947983933420914709779352687976241752644573955277203987656815646922449168203031499488024798333296412175930765827008394700546657807715318520619975956990281083211405881847851847071572606496061748291017203574300353812240244014286149489972572050518166373893115167788421845782467614019084139321785768362788649710491539038528336497113331667233284607166508277788402817066814086201044424756001919350599970402822234757722266616657574989868109324252160663470925207690694094953312891282341426880506924648525181014287214350136557941201445475540830225059514652125310445352175047408966028497316806142156338927162621004774769949534239479839334209147097793526879762417526445739552772039876568156469224491682030314994880247983332964121759307658270083947005466578077153185206199759569902810832114058818478518470715726064960617482910172035743003538122402440142861494899725720505181663738931151677884218457824676140190841393217857683627886497104915390385283364971133316672332846071665082777884028170668140862010444247560019193505999704028222347577
  c = bytes_to_long(line.encode())
  d = 1
  e = pow(d,-1,n)
  pt = pow(c,d,n) # decrypting the line
  line = long_to_bytes(pt)
  key = b'\x00' * len(line)
  for i in range(2, 2**(random.randint(2, 10))):
    line = xor(key,line) # decrypting the xor
  line = line.decode()
  line = codecs.encode(line, 'rot_13')
  line = codecs.encode(line, 'rot_13').encode() # decrypting the Rot0!
  return line

r = requests.get("https://docs.google.com/forms/d/e/1FAIpQLSe0p_fubEBQWwr0jtxiEXA64hali4QR_EC1YCnWEV0LnJEnkw/viewform")
lines = r.text.split("\n")

for line in lines:
  if len(line) < 1024:
    try:
      line = decode(line).decode()
      if "DUCTF" in line:
        print(line)
    except:
	    pass
```

Output:

```
,[665504207,"Was DUCTF run at a good time and date for you? If not why?",null,0,[[1937027417,null,0]
,[1325193297,"How much CTF experience did you have before DUCTF?",null,5,[[1010680425,[["1"]
,[2134451865,"How difficult did you find DUCTF overall?",null,5,[[1332825563,[["1"]
,[169492811,"DUCTF Feedback",null,8]
,[378259988,"How much did you learn from DUCTF?",null,5,[[1868606821,[["1"]
,[1917796698,"How has DUCTF influenced your interest in cybersecurity?",null,5,[[1934700602,[["1"]
,["Thank you for playing DownUnderCTF. Your feedback is appreciated!\n\nHere is your flag: DUCTF{th4nk_y0u_f0r_p4rt1c1pating_in_DUCTF!1!1}",0,0,0,0]
```

And so our flag is `DUCTF{th4nk_y0u_f0r_p4rt1c1pating_in_DUCTF!1!1}`
