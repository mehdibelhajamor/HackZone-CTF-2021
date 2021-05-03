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
1 - sign : sign a commande in ['cat s*', 'ls', 'whoami']
2 - exec : execute a commande given it's signature
3 - exit
```
First, i thought it's the usual **ECDSA** where we can exploit it and forge a signature for chosen command using 2 signatures. But then i realized that the secret ```k``` is generating everytime i sign, so that won't help at all.

We can see that ```k``` is generating as shown :
```python
k = randbelow(sk.curve.order, payload)
```

![2020-12-08 18_37_24-b00t2root-2020-CTF-Crypto-Challenges_README md at main · MehdiBHA_b00t2root-2020](https://user-images.githubusercontent.com/62826765/101520233-79641300-3984-11eb-888f-1ad5c2c6d68c.png)

**Analyzing the function :**
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
We can see that giving a payload it evaluate it with Lua language 


![2020-12-08 18_37_24-b00t2root-2020-CTF-Crypto-Challenges_README md at main · MehdiBHA_b00t2root-2020](https://user-images.githubusercontent.com/62826765/101520233-79641300-3984-11eb-888f-1ad5c2c6d68c.png)

**Full solver :**
```python
from lupa import LuaRuntime
import secrets
import ecdsa
from pwn import *
from Crypto.Util.number import inverse

conn = remote("52.236.0.242", 1337)
#conn = process("./task.py")
for _ in range(13):
    conn.recvline()

pem = conn.recvuntil("1.")[:-2]
sk = ecdsa.SigningKey.generate()
vk = sk.get_verifying_key()
veri_key = vk.from_pem(pem)
n = veri_key.pubkey.order

payload = "{ __call = function(table, key) local m = { name = key }; return '"+str(n-1)+"'; end }"
cmd = ["ls","whoami"]
sig = []
for i in range(2):
    conn.recvuntil("choose:")
    conn.sendline("1")
    conn.recvuntil("cmd=")
    conn.sendline(cmd[i])
    conn.recvuntil("payload=")
    conn.sendline(payload)
    conn.recvuntil("sig=")
    sig.append(conn.recvline().strip().decode())

c1 = cmd[0]
sig1 = sig[0]

r1, s1 = ecdsa.util.sigdecode_string(bytes.fromhex(sig1), order=n)
h1 = ecdsa.keys.sha1(c1.encode("utf-8"))
z1 = ecdsa.util.string_to_number(h1.digest())
k = n-1
r_inv = inverse(r1,n)
d_a = ((s1*k - z1) * r_inv) % n

cmd_attack = "cat flag"
sk_new = sk.from_secret_exponent(d_a)
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

FLAG : _**HZiXCTF{1337_bear_p0wns_cu5v3s}**_
