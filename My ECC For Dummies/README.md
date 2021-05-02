We were given a source code :

```python
from Crypto.Util.number import bytes_to_long as bl
from tinyec import registry
import secrets

FLAG = "HZiXCTF{redacted}"
flag_part1 = FLAG.split("_", 1)[0]
flag_part2 = FLAG.split("_", 1)[1]


def key_gen(P):
    secret = secrets.randbelow(P.x)
    Q = P * secret
    return Q, secret

def encrypt(plain1, plain2, P, Q):
    k = secrets.randbits(512)
    R = P * k
    S = Q * k
    c1 = S.x * plain1 % p
    c2 = S.y * plain2 % p
    return (R, c1, c2)

def decrypt(R, secret, c1, c2):
    T = R * secret
    m1 = pow(T.x, -1, p) * c1 % p
    m2 = pow(T.y, -1, p) * c2 % p
    return m1, m2


if __name__ == '__main__':

    curve = registry.get_curve('secp192r1')
    P = curve.g * secrets.randbits(512)
    p = P.p

    print(f"Public Parameters:\n[+] p = {p},\n[+] Curve = {curve},\n[+] P = ({P.x}, {P.y})")
    Q, n = key_gen(P)
    print(f"Public Key: ({Q.x}, {Q.y})")

    m1 = bl(flag_part1.encode())
    m2 = bl(flag_part2.encode())
    print(f"m2 {m2}")

    assert m1 < p
    assert m2 < p

    R, c1, c2 = encrypt(m1, m2, P, Q)
    ID = pow(m2, 1 << secrets.randbits(6)+1, p)
    print(f"Ciphertext [ID: {ID}]:\n(({R.x}, {R.y}), {c1}, {c2})")


"""
Public Parameters:
[+] p = 6277101735386680763835789423207666416083908700390324961279,
[+] Curve = "secp192r1" => y^2 = x^3 + 6277101735386680763835789423207666416083908700390324961276x + 2455155546008943817740293915197451784769108058161191238065 (mod 6277101735386680763835789423207666416083908700390324961279),
[+] P = (118726926238449146604166401674407291431073766182235957040, 103402990690546929415284676612346715211634004109234253773)
Public Key: (3791915955656218849242622894021365000925895935803336128820, 3329966616739715465745728730933058401053191194343496097662)
m2 19179670616298058934408348821305602258320084879756157
Ciphertext [ID: 3243154082094975110425161650374039692150707098951074985457]:
((4026862427689776673708719005534379325482880614935079628460, 4779183078484891486346057607813184593429180233415496627902), 273313854985749705692360311202040937037213239294441646642, 6076257418068540152032600239285650920642292327792130060609)
"""
```
