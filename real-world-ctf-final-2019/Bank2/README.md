
[Web version](https://x9453.github.io/2020/01/26/Real-World-CTF-Finals-2019-Bank2/)

# Challenge

* Type: Crypto
* Keywords: Schnorr signature algorithm
* [Source files & exploit](https://github.com/x9453/ctf-write-ups/tree/master/real-world-ctf-final-2019/Bank2/)

# Description

> Our bank has invested in a HUGE security upgrade. Now we are equipped with the latest interactive multi-signature protocol to keep your assets safe. Your satisfaction is our first priority.

# Solution

## Detailed Write-up

Similar to the challenge `Bank` in Real World CTF 2019 Quals ([Ref](https://ctftime.org/task/9225)), the server-side implements the Schnorr signature algorithm. The difference between these two implementations is the verifying function:

```python=
def cosi_verify(c, s, pk, m):
    if (not on_curve(pk)):
        print('Not on curve')
        return False
    cPrime = sha256(bytes_point(point_add(point_mul(G, s), point_mul(pk, n-c))) + m)
    if cPrime == c:
        return True
    return False
```
The main logic of the server's code is:

```python=
# generate server's public-private key pair
sk, pk = generate_keys()
print('sk, pk =', sk, pk)
...
if msg[0] == '0': # withdraw
    ...
    if cosi_verify(C, S, pk, 'WITHDRAW'):
        req.sendall("Here is your coin: %s\n" % FLAG)
if msg[0] == '1': # deposit
    r = p - Random.random.randint(5, p/2**16)
    req.sendall("%s\n" % repr((point_mul(G, r), pk)))
    ...
    c = sha256(bytes_point(T) + 'DEPOSIT')
    s = r + c * sk
    req.sendall("%s\n" % repr(s))
    ...
    if cosi_verify(C, S, PK, 'DEPOSIT'):
        balance += 100
        req.sendall('Coin Deposited')
```
In the deposit method, `T` and `PK` are provided by us. The bug happens at line 14, it should be `s = (r + c * sk) % n` instead (credit to [@fweasd](https://github.com/b04902036)). Notice that the `s` we received equals to `p - r' + c * sk`, where `r'` is around 240 bits. Since we know the value of `p, c`, we can calculate the value of `sk = (s - p)//c + 1`, which is the secret key of the server. Then, we sign the message `"WITHDRAW"` with the secret key and get the flag by the withdraw method.

Exploit:

```python=
G = ... # base point
n = ... # order of the group
p = ... # mod p

def sign(sk, msg):
    rn = 0x9453
    T = point_mul(G, rn)
    c = sha256(bytes_point(T) + msg)
    s = (rn + c * sk) % n
    return c, s, T

r = remote(host, port)
sk, pk = generate_keys()
c, s, T = sign(sk, 'DEPOSIT')
server_s = deposit(r, (T, pk), (c, s))

server_sk = (server_s - p) // c + 1
c, s, _ = sign(server_sk, 'WITHDRAW')
withdraw(r, (c, s))

# rwctf{2r0unD_Schn0Rr_1s_N07_5AfE._cHEck_tH3_0ak1aNDl9_p4p3r}
```
