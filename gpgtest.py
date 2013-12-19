#!/usr/bin/python2
import struct
import hashlib
import base64
n = int('00E2FC646FF48AFC8C2A7DDF1B99CECD21A0AEC603DBAAA1A7ADF6836A6CED82BAE694AC5A4ACBD7FC1D36B2C677BE25E400330D295D044C9F6AFAEA45A8CF370F59E398F853FFCED03395D297CEED47C0E9EF2C358C05399E1F8A878E6E044F1AB7D82A162C77EE956B0A9B54C910000EF7122CC8BBB1746872968F05E7CFD563', 16)
e = 0x010001
t = 1387430955 #1387431060
f = '2373B1EFD2715F58527037221D798ADAACF24B9E'.lower()

d = 0x1588bf5895b927db7e5e81afa32868f2a3456178d53abb6a6689280f8d34fd3d910992ce602135a4effa93fc5b38d96c678e7055b7c2e4280da4af5c1b77493048565e969acbbe62f1a3992ca8f5a1e050cb01684c507ff5fdd69d76dc410a9421d6d5d92a404ecc915e884b33dd89cd33f826c301877f302f2cc59cefd6e2f1
p = 0xe41c31fcfd9b37c7c132ac42117b15ad881ea889bf6b488a3074bf500596de2ff6344a29e8e161defec8ad33baf6d0e3206b253ea66d72e5df9344e53a5948f3
q = 0xfebd02455f8f771d86e3e8aa8311dadf006cadf1c3f68d309970453a91da4aae01e4c7281b4258b6fe0d090c1c8a62b61708bf2619b11675d0e0f586dfa95dd1
u = 0xa52ac23b317f367896c85bab4986816e3548c8d8718671c04e115b24ce8f5a9af96e84bf788d4f3ca8939759bbd4b3055136d6a77aad45cc28bb77d313562739

#n = 137881935559731746576667096303241964801413801236929824996894552940643282784901454053626483776152779948787512052190598582040559117725190642218274926880418394549905718357236733728288866587089788445413420092484339301512746073773677942679902466995531985821488237542691684984194760039822183078939445119777889602523
#e = 0x10001

def chunks(l, n):
    """ Yield successive n-sized chunks from l. """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

def dump(n, leng=None): 
    s = '%x' % n
    if len(s) & 1:
        s = '0' + s
    out = s.decode('hex')
    if leng:
        if len(out) < leng:
            out = '\x00' * (leng - len(out)) + out
        elif len(out) > leng:
            raise Exception("Longer than expected!")
    return out


def mpi(n):
    by = dump(n)
    bl = len(bin(n)) - 2 # 0b1001010101
    if bl > 2**16:
        raise Exception("Length too big!")
    return struct.pack(">H", bl) + by

def octlen(msg):
    return struct.pack(">H", len(msg))

def rsa_pubkey_pkt(n, e, t):
    msg = ''
    msg += '\x04'  # version
    msg += dump(t, 4) # timestamp
    msg += '\x01'  # algorithm: RSA
    msg += mpi(n) + mpi(e) # key material
    return msg

def fingerprint_pkt(n, e, t):
    msg = rsa_pubkey_pkt(n, e, t)
    return '\x99' + octlen(msg) + msg

def rsa_privkey_pkt(n, e, t, d, p, q, u):
    asf = mpi(d) + mpi(p) + mpi(q) + mpi(u)
    chksum = sum([ord(c) for c in asf]) % 65536

    msg = ''
    msg += rsa_pubkey_pkt(n, e, t)
    msg += '\x00' # unencrypted
    msg += asf
    msg += dump(chksum, 2)

    return msg

def fingerprint(pkt):
    return hashlib.sha1(pkt).hexdigest()

def armor(byts, name = "PGP PRIVATE KEY BLOCK"):
    b64str = '\n'.join(chunks(base64.b64encode(byts), 78))

    s = ''
    s += '-'*5 + "BEGIN " + name.upper() + '-'*5 + '\n'
    s += 'Version: pyGPG v0.0.1\n'
    s += '\n'
    s += b64str + "\n"
    s += '-'*5 + "END " + name.upper() + '-'*5 + '\n'

    return s

def pktize(tag, byts):
    # data length
    leng = dump(len(byts))

    # length length type :)
    if len(leng) == 1:
        llt = 0
    elif len(leng) == 2:
        llt = 1
    elif len(leng) == 3:
        llt = 2
        leng = '\x00' + leng
    elif len(leng) == 4:
        llt = 2
    else:
        raise Exception("Invalid length length")

    pkt = ''
    struct.pack
    pkt += chr(0x80 | (tag << 2) | llt)
    pkt += leng
    pkt += byts

    return pkt

print armor(pktize(5, rsa_privkey_pkt(n,e,t,d,p,q,u)))


#pkt = rsapkt(n, e, t)
#ft = fingerprint(pkt)
#print ft == f
#print ft, f
#
#n4096 = int('F0' + '00' * 510 + '0A', 16)

#for exp in xrange(0x7F000001, 0xFFFFFFFF):
#    last = rsapkt(n4096, 0xDEADBEEF, 0)[512:]
#    print ord(last[8]), ord(last[9])
