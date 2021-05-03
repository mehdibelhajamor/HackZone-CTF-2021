# Lubear Revenge Challenge


We were given a source code and a netcat server ```nc 52.236.0.242 1337``` :

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ecdsa
import os
import sys
from lupa import LuaRuntime
import random
import secrets

bear = """

 {"`-'"}
  (o o)
,--`Y'--.
`-:,-.;-'
  /`_'\
 (_/ \_)

LuBear is back!
Can you beat it again?

"""

print(bear)

sk = ecdsa.SigningKey.generate()
vk = sk.get_verifying_key()

print(vk.to_pem().decode('utf-8'))

def randbelow(n, payload):
    """
        Super fast cryptographically strong pseudo-random numbers suitable for
        managing secrets such as account authentication, tokens, and similar.
        Return a random int in the range [1, n)
    """
    L=LuaRuntime(encoding=None)

    fastgen = L.eval('''
    function(n, r, p)
        local w = r
        if next(p) ~= nil then
            w = {}
            setmetatable(w, p)
        end
        return w(n)
    end
    ''')
    rand = fastgen(str(n), lambda n: str(secrets.randbelow(int(n))), L.eval(payload))
    return int(rand)

def sign():
    allowed_cmds = ['cat s*', 'ls', 'whoami']
    cmd = input("cmd=")
    payload = input("payload=") or "{}"
    k = randbelow(sk.curve.order, payload)
    if cmd not in allowed_cmds:
        print("you can only exec %s" % allowed_cmds)
    else:
        sig = sk.sign(cmd.encode("utf-8"), k=k)
        print("sig= %s" % sig.hex())

def execute():
    cmd = input("cmd= ")
    signature = input("sig= ")
    signature = bytes.fromhex(signature)
    try:
        vk.verify(signature, cmd.encode('utf-8'))
        print("OK!")
        os.system(cmd)
    except ecdsa.BadSignatureError:
        print("KO! Invalid sig")
    return

menu = {
    '1': sign,
    '2': execute,
    '3': sys.exit
}
while True:
    print("1. sign")
    print("2. exec")
    print("3. bye")
    cmd = input("choose:")
    try:
        menu[cmd]()
    except KeyError:
        print("Invalid selection")
```

Connecting to the netcat server we got this prompt :

![2021-05-02 23_17_41-Kali - VMware Workstation](https://user-images.githubusercontent.com/62826765/116829635-a798f800-ab9c-11eb-9bcd-f79d9babc0e1.png)

we have 3 choices :
```
1 - sign : sign a commande ['cat s*', 'ls', 'whoami']
2 - exec : execute a commande given it's signature
3 - exit
```
First, i thought it's the usual **ECDSA** where we can forge a signature for chosen command using 2 signatures. But then i realized that the secret ```k``` is generating everytime i sign, so that won't help at all.

The challenge contains 2 parts :
- Exploiting ```randbelow()``` function to get the secret ```k```
- Breaking ECDSA and sign the command "cat flag"

![2020-12-08 18_37_24-b00t2root-2020-CTF-Crypto-Challenges_README md at main · MehdiBHA_b00t2root-2020](https://user-images.githubusercontent.com/62826765/101520233-79641300-3984-11eb-888f-1ad5c2c6d68c.png)


### Exploiting ```randbelow()``` :

By looking at the source code, we can see that ```k``` is generating as shown :
```python
k = randbelow(sk.curve.order, payload)
```
Looking at the function :
```python
def randbelow(n, payload):
    """
        Super fast cryptographically strong pseudo-random numbers suitable for
        managing secrets such as account authentication, tokens, and similar.
        Return a random int in the range [1, n)
    """
    L=LuaRuntime(encoding=None)

    fastgen = L.eval('''
    function(n, r, p)
        local w = r
        if next(p) ~= nil then
            w = {}
            setmetatable(w, p)
        end
        return w(n)
    end
    ''')
    rand = fastgen(str(n), lambda n: str(secrets.randbelow(int(n))), L.eval(payload))
    return int(rand)
```
We see that it returns a random number in range(1, n). But how it works here ?

Basically, it evaluates ```fastgen``` function which is written with **Lua Programmation Language** given arguments (the order n as string ```str(n)```, function that returns a random number as string in range(1, n) ```lambda n: str(secrets.randbelow(int(n)))```, the evaluation of our input payload ```L.eval(payload)```). If ```next(p) ~= nil``` then it will set a metatable ```p``` to the table ```w``` and apply it to n, else it will apply ```lambda n: str(secrets.randbelow(int(n)))```.

I'm not going through details cause i don't even know what is Lua Programmation Language x) But what i understand is that we need to inject some payload so that verifies ```next(p) ~= nil``` and ```setmetatable(w, p)``` will sets a function to ```w``` which can returns what we want.

I spent some time reading about Lua Programmation Language (especially next() and setmetatable() functions), trying instructions and dealing with errors. But finally i found that injecting a table that contains a metamethod \_\_call with a function can give us what we need.

After many tries, i got this simple payload :
```
payload = "{ __call = function(n) return '123456789'; end }"
```
Using this payload, ```randbelow(sk.curve.order, payload)``` will return ```123456789``` as a secret ```k```.

![2020-12-08 18_37_24-b00t2root-2020-CTF-Crypto-Challenges_README md at main · MehdiBHA_b00t2root-2020](https://user-images.githubusercontent.com/62826765/101520233-79641300-3984-11eb-888f-1ad5c2c6d68c.png)

### Breaking ECDSA :

![2021-05-03 04_41_54-Elliptic Curve Digital Signature Algorithm - Wikipedia](https://user-images.githubusercontent.com/62826765/116839450-5bfd4300-abca-11eb-861b-5b950455b283.png)

We have the secret ```k```, so by using a signature of a commande (e.g. ls) we can calculate the private key ```da``` and sign a command we want :

![tt](https://user-images.githubusercontent.com/62826765/116840582-4722ae80-abce-11eb-8bb7-754a5387d9ce.png)

**Solver :**
```python
from Crypto.Util.number import inverse
import ecdsa
from pwn import *

conn = remote("52.236.0.242", 1337)
#conn = process("./Lubear_Revenge.py")
for _ in range(13):
    conn.recvline()

pem = conn.recvuntil("1.")[:-2]
sk = ecdsa.SigningKey.generate()
vk = sk.get_verifying_key()
veri_key = vk.from_pem(pem)
n = veri_key.pubkey.order

payload = "{ __call = function(n) return '123456789'; end }"
cmd = "ls"

conn.recvuntil("choose:")
conn.sendline("1")
conn.recvuntil("cmd=")
conn.sendline(cmd)
conn.recvuntil("payload=")
conn.sendline(payload)
conn.recvuntil("sig=")
sig = conn.recvline().strip().decode()

r, s = ecdsa.util.sigdecode_string(bytes.fromhex(sig), order=n)
h = ecdsa.keys.sha1(cmd.encode("utf-8"))
z = ecdsa.util.string_to_number(h.digest())
k = 123456789
r_inv = inverse(r, n)
da = ((s*k - z) * r_inv) % n

cmd_attack = "cat flag"
sk_new = sk.from_secret_exponent(da)
sign_attack = sk_new.sign(cmd_attack.encode("utf-8"), k=k).hex()

conn.recvuntil("choose:")
conn.sendline("2")
conn.recvuntil("cmd=")
conn.sendline(cmd_attack)
conn.recvuntil("sig=")
conn.sendline(sign_attack)
flag = conn.recvline().decode().strip()
print(flag)
```

FLAG : **HZiXCTF{1337_bear_p0wns_cu5v3s}**
