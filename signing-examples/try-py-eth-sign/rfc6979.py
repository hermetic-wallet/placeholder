# taken from
# https://github.com/tlsfuzzer/python-ecdsa/blob/master/src/ecdsa/rfc6979.py

"""
RFC 6979:
    Deterministic Usage of the Digital Signature Algorithm (DSA) and
    Elliptic Curve Digital Signature Algorithm (ECDSA)
    http://tools.ietf.org/html/rfc6979
Many thanks to Coda Hale for his implementation in Go language:
    https://github.com/codahale/rfc6979
"""

import hmac
import binascii
from binascii import hexlify
#from .util import number_to_string, number_to_string_crop, bit_length

import hashlib

def orderlen(order):
    return (1 + len("%x" % order)) // 2  # bytes

ORDERLEN = 32

def number_to_string(num, order):
    #print ("order is ", order)
    #l = ORDERLEN#orderlen(order)
    #l = orderlen(order)
    #print ("l is ", l)
    l = ORDERLEN
    fmt_str = "%0" + str(2 * l) + "x"
    string = binascii.unhexlify((fmt_str % num).encode())
    assert len(string) == l, (len(string), l)
    return string

def number_to_string_crop(num, order):
    #l = orderlen(order)
    l = ORDERLEN
    fmt_str = "%0" + str(2 * l) + "x"
    string = binascii.unhexlify((fmt_str % num).encode())
    return string[:l]

def bit_length(x):
    return 256
    return x.bit_length() or 1

#from ._compat import hmac_compat

def hmac_compat(data):
    return data


# bit_length was defined in this module previously so keep it for backwards
# compatibility, will need to deprecate and remove it later
__all__ = ["bit_length", "bits2int", "bits2octets", "generate_k"]


def bits2int(data, qlen):
    x = int(hexlify(data), 16)
    l = len(data) * 8

    if l > qlen:
        return x >> (l - qlen)
    print ("bits2int(", data, qlen,")", x)
    return x


def bits2octets(data, order):
    z1 = bits2int(data, bit_length(order))
    z2 = z1 - order

    if z2 < 0:
        z2 = z1

    return number_to_string_crop(z2, order)


# https://tools.ietf.org/html/rfc6979#section-3.2
def generate_k(order, secexp, hash_func, data, retry_gen=0, extra_entropy=b""):
    """
    Generate the ``k`` value - the nonce for DSA.
    :param int order: order of the DSA generator used in the signature
    :param int secexp: secure exponent (private key) in numeric form
    :param hash_func: reference to the same hash function used for generating
        hash, like :py:class:`hashlib.sha1`
    :param bytes data: hash in binary form of the signing data
    :param int retry_gen: how many good 'k' values to skip before returning
    :param bytes extra_entropy: additional added data in binary form as per
        section-3.6 of rfc6979
    :rtype: int
    """


    qlen = bit_length(order)
    holen = hash_func().digest_size
    rolen = (qlen + 7) // 8
    bx = (
        hmac_compat(number_to_string(secexp, order)),
        hmac_compat(bits2octets(data, order)),
        hmac_compat(extra_entropy),
    )

    # Step B
    v = b"\x01" * holen

    # Step C
    k = b"\x00" * holen

    # Step D

    k = hmac.new(k, digestmod=hash_func)
    k.update(v + b"\x00")
    for i in bx:
        k.update(i)
    k = k.digest()

    # Step E
    v = hmac.new(k, v, hash_func).digest()

    # Step F
    k = hmac.new(k, digestmod=hash_func)
    k.update(v + b"\x01")
    for i in bx:
        k.update(i)
    k = k.digest()

    # Step G
    v = hmac.new(k, v, hash_func).digest()

    # Step H
    while True:
        # Step H1
        t = b""

        # Step H2
        while len(t) < rolen:
            v = hmac.new(k, v, hash_func).digest()
            t += v

        # Step H3
        secret = bits2int(t, qlen)

        if 1 <= secret < order:
            if retry_gen <= 0:
                return secret
            retry_gen -= 1

        k = hmac.new(k, v + b"\x00", hash_func).digest()
        v = hmac.new(k, v, hash_func).digest()

# expecting k = 15d0e55777f4273726bbb347f77b09ad0af372b6e82d5d66b2b6c683cef55c42
# 
# when m  = 52fbb559a867af2f7613fd01b0a59e1363d3403830551c22f65622ccf93e7db3
#      pk = 0100000000000000000000000000000000000000000000000000000000000000

msg_data = [ 0x52, 0xfb, 0xb5, 0x59, 0xa8, 0x67, 0xaf, 0x2f, 0x76, 0x13, 0xfd, 0x1, 0xb0, 0xa5, 0x9e,
          0x13, 0x63, 0xd3, 0x40, 0x38, 0x30, 0x55, 0x1c, 0x22, 0xf6, 0x56, 0x22, 0xcc, 0xf9, 0x3e,
          0x7d, 0xb3 ]

msg_data = binascii.unhexlify("52fbb559a867af2f7613fd01b0a59e1363d3403830551c22f65622ccf93e7db3")

ORDER = 115792089237316195423570985008687907852837564279074904382605163141518161494337

k = generate_k(ORDER, 0x0100000000000000000000000000000000000000000000000000000000000000, hashlib.sha256, msg_data)
assert k == 0x15d0e55777f4273726bbb347f77b09ad0af372b6e82d5d66b2b6c683cef55c42
print (hex(k))
