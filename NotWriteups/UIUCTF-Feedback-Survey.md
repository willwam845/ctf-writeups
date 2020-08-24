# Feedback Survey

# Description
Feedback Survey was a 20 point miscellaneous challenge in this years UIUCTF. You have to fill out a vulnerable survey and then exploit this vulnerability to get the flag.


The description reads as follows:
```
Please fill out the feedback survey here! https://forms.gle/qfWGeN6jFf5kRcZW8
```

# Challenge

Now, from previous CTF experience, I know that many CTF's tend to have survey challenges, which are often much harder than their point values they say they are, since they often have small twists that make them different to each other, and so relying on past CTF writeups to go brrr is quite unreliable.


Before I get onto how the challenge is solved, there is an important thing to know about survey challenges. This is the fact that they often take the layout of a couple multiple choice questions, often starting with very basic things like your team name, your favourite challenge/favourite category, then followed by a slightly longer question on things like what could be improved.


The real killer, however, for these survey challenges is often the long question at the end asking for any other comments, which often requires a deep level of understanding the inner working of the CTF and the key components, such as the sleep schedule balancer, the perfect infrastructure star, and of course, the sanity checker.


Often with survey challenges and its counterparts, for example Sanity Checks, or Discord challenges, they have very low point values for some reason, despite their sheer difficulty and steps required to solve them. I would like to invite you to join the #MorePointsForSanityCheck movement, as these challenges are severly underated and I give my respect to anyone who has the ability to understand, let alone solve these difficult challenges.


Enough rambling however, let's get into the challenge.


We are obviously provided with a Google Forms link to the survey, a pretty standard website for this sort of stuff, nothing different there, therefore
so far, this was looking fine.


Obviously, this "looking fine" was rather short lived, as we all know how hard these challenges can be.


The first thing I noticed when looking at this challenge is the fact that some questions were required to be filled in, while others did not. This could be some sort of steganography. Taking a required question as a 1 and an unrequired question as a 0, we could get a binary string 101111111000. However, we can see that this is way too short to get anything out of it. I also tried various other encodings, like morse, which I attempted to decode by splitting each letter by the question type. This decoded to `AIIIETM`, which didn't appear to be a flag, so I ruled out the possibility of this being useful.


Another thing that was noticed was the odd capitalization of some of the words in a few of the questions, for example the C in "Can", or every first letter of each word in the question "Which Challenge Was Your Favorite". This would have been my next move, until I got word from my team that this could potentially be a vulnerable survey.


For those of you who are unfamiliar with surveys, their vulnerabilities and how you can exploit them, I'll briefly cover it here.


Survey vulnerabilities are based around the idea that it is possible to skip the survey entirely through viewing the source code and then searching for a known plaintext string. This is often known as a Known Plaintext Survey Blood attack. Since the encryption method for the source code is just Rot26, followed by a XOR with key 0x00000000000000000000000000000000, and finally encrypted with secure 2048-bit RSA using e=1, this is still quite a challenge, but doable as long as we know flag format (i.e. the known plaintext).


In this scenario we have a massive problem however. We do not know flag format. This means we don't have a known string which we could use to carry out a known plaintext attack.


So, what is there to exploit? Everything here seems very secure and wouldn't leak anything at all. Also, flag format is not given, so we don't know what flags look like at all, meaning this makes things much, much harder. We could always try searching for a curly brace, however one look at the source code made it obvious that this was not going to be feasible.


Well, the vulnerability lies in the fact that this survey uses Google Forms. The main vulnerability with Google Forms is that you can skip the survey entirely, as you are able to see the message that will be displayed after the flag. 


We might have to do a bit of local testing to figure out how we can apply this known plaintext attack, but since there is no canary, PIE, KASLR, SMAP, or Miller-Rabin primality test, it is fairly easy to get a plaintext string which we can search for. 


To start, we create a form with Google Docs, but we make it very short so that it is possible to complete it and get a and b by using the Pohlig Hellman algorithm. From here, we can explore possible strings we can use for our Known Plaintext Survey Blood Attack.


We have a very interesting string that appears to be not added by us, which is "Your response has been recorded". This looks very promising, as after some more local testing, I found that this string will always appear at the end of a survey.

However, I ran into a problem, as the Google Docs exploit doesn't actually pick this up if you simply carry out the exploit using "Your response has been recorded." as the known plaintext string. The problem is that the exploit only works to where the author of the survey can control, and because this string is controlled server side, we cannot use it as a plaintext string to use with our attack.


So, we were basically back to square one. However, I remembered an exploit we could use which helped during HouseplantCTF, where even though we knew flag format, there were no plaintext strings we could use to get the flag. We can guess what sort of word/phrases that would be used, for example "flag", or "thank you" are common phrases used in surveys, especially at the end where you have to exploit vulnerable 
surveys like this. 


We first took a few surveys from past CTFs (I ended up going with the redpwnCTF, rgbCTF and HouseplantCTF surveys), and then built an AI which spit out common words or phrases used in them. This gave us a set of 20 or so words that the AI generated, but we had to discard about half of them due to the fact that they weren't actual words, or they seemed rather weird. We ended up with 6 words at the end. Wordlist
is below:


```
flag
thanks
thank you
feedback
we appreciate
response
```

Using these strings as our plaintext, we can write a python script to attempt to apply this known plaintext attack.

```python
import codecs
import requests
from Crypto.util.number import long_to_bytes, bytes_to_long

def xor(a, b):
    return bytes([_a ^ _b for _a, _b in zip(a, b)])

def decode(line):
  # e = 1, therefore c ** 1 mod n = c, we can decrypt this easily
  n = 22266616657574989868109324252160663470925207690694094953312891282341426880506924648525181014287214350136557941201445475540830225059514652125310445352175047408966028497316806142156338927162621004774769949534239479839334209147097793526879762417526445739552772039876568156469224491682030314994880247983332964121759307658270083947005466578077153185206199759569902810832114058818478518470715726064960617482910172035743003538122402440142861494899725720505181663738931151677884218457824676140190841393217857683627886497104915390385283364971133316672332846071665082777884028170668140862010444247560019193505999704028222347577
  c = bytes_to_long(line.encode())
  e = 1
  d = pow(e,-1,n)
  pt = pow(c,d,n) # decrypting the line
  line = long_to_bytes(pt)
  key = b'\x00' * len(line)
  line = xor(key,line).decode() # decrypting the xor
  line = codecs.encode(line, 'rot_13')
  line = codecs.encode(line, 'rot_13').encode() # decrypting the Rot26
  return line

r = requests.get("https://docs.google.com/forms/d/e/1FAIpQLScSIF6p2ZWpuOVw6zCQyq0SAKAKHw7Cst0KwTKRR7g29Xz7RA/viewform")
lines = r.text.split("\n") 

words = ["flag", "thanks", "thank you", "feedback", "we appreciate", "response"] # ai generated wordlist :3
for word in words:
  for line in lines:
    if len(line) < 256:
      line = decode(line).decode()
      if word in line:
        print(line)

```


Looking at the output of this, we can see there are two lines of interest. One appears to be a really long and irrelevant string, but, if we take a look at the other one...

```
,["Thank you for your response. uiuctf{your_input_is_important_to_us}",0,0,1,0]
```

What do we have here? It's a flag! Swiftly I submitted it and I was the 69th person to solve this very tough challenge.


# Conclusion
As you can see, this challenge is truly a very difficult challenge, much like other survey challenges, as survey exploits are very hard to do, especially like in the case of this scenario, where flag format was not known. Overall, I enjoyed this challenge a lot, and hope to see what the developers do in the future to make this even more interesting!

Flag: `uiuctf{your_input_is_important_to_us}`
