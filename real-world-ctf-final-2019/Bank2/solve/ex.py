from pwn import *
from PoW import do_pow
from base64 import b64encode

from schnorr import *

#host, port = '127.0.0.1', 20014
host, port = '172.16.24.100', 20014

def pack(l):
    return b64encode(''.join(map(lambda x: to_bytes(x, 32, byteorder='big'), l)))

def withdraw(r, sig):
    r.sendlineafter('our first priority!', b64encode('0'))
    r.sendlineafter('Please send us a signature', pack(sig))

def deposit(r, commit, sig):
    r.sendlineafter('our first priority!', b64encode('1'))
    r.sendlineafter('Initiating Interative Protocol...\n', pack(commit[0] + commit[1]))
    r.recvline()
    server_s = eval(r.recvline().strip())
    r.sendlineafter('Please send us a signature', pack(sig))
    return server_s

def sign(sk, msg):
    rn = 0x9453
    T = point_mul(G, rn)
    c = sha256(bytes_point(T) + msg)
    s = (rn + c * sk) % n
    return c, s, T

def main():
    r = remote(host, port)
    s = r.recvline()[:-1]
    ans = do_pow(s)
    r.send(ans)

    sk, pk = generate_keys()
    c, s, T = sign(sk, 'DEPOSIT')
    server_s = deposit(r, (T, pk), (c, s))

    server_sk = (server_s - p) // c + 1
    c, s, _ = sign(server_sk, 'WITHDRAW')
    withdraw(r, (c, s))

    r.recvline()
    print(r.recvline())
    r.close()

main()

# rwctf{2r0unD_Schn0Rr_1s_N07_5AfE._cHEck_tH3_0ak1aNDl9_p4p3r}
