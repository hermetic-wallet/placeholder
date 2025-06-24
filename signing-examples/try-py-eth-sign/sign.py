from ecdsa import SigningKey, SECP256k1
import base64
import sys
import binascii
from sha3 import keccak_256
from hashlib import sha256

#private_key = binascii.unhexlify(b"0100000000000000000000000000000000000000000000000000000000000000")
private_key = binascii.unhexlify(b"0000000000000000000000000000000000000000000000000000000000000002")
sk = SigningKey.from_string(private_key, curve=SECP256k1)
vk = sk.get_verifying_key()

msg = binascii.unhexlify(b"52fbb559a867af2f7613fd01b0a59e1363d3403830551c22f65622ccf93e7db3")
print("Secret key:\t",binascii.hexlify(sk.to_string()))
print("Public key:\t",binascii.hexlify(vk.to_string()))
print("   Message:\t",binascii.hexlify(msg))

pk = binascii.hexlify(sk.to_string())
pk_hash = keccak_256()
pk_hash.update(vk.to_string())
print ("    Wallet:\t 0x{}".format(pk_hash.hexdigest()[24:]))

print()

# python generated sig

signature = sk.sign_digest_deterministic(msg, hashfunc=sha256)
print(" Signature:\t",binascii.hexlify(signature))
print("     Valid:\t", vk.verify_digest(signature, msg))

# web3.js / go-ethereum / k256 sig

print("=========================")
signature = binascii.unhexlify(b"71f498f5d9a05e83599a65e31febd4fb07451127031cf069c05c55ce586f248b0247be206cff797fe03223673560c431cf2f94a02ebbb09fda8e4a7b03c2f353")
print(" Signature:\t",binascii.hexlify(signature))
print("     Valid:\t", vk.verify_digest(signature, msg))

# k256 sign_digest @ 0.12.0

print("=========================")
signature = binascii.unhexlify(b"E5DDAF165DBC7FF272EA9869B186228CF2FBC461A8A140B266AD82F41BDC14C868AB5B9FAD8032F0363F3D24CA03FCEAFF73E402CB15C82C5D9FCCAB440588B4")
print(" Signature:\t",binascii.hexlify(signature))
print("     Valid:\t", vk.verify_digest(signature, msg))

# compiled uECC .elf

print("=========================")
signature = binascii.unhexlify(b"8dff4e41b6c2ff7c3c2b57ae5dac242a33592b936338dd7200b7640de74fa2e45998385164a0b163a686e262a21bfc6b898b2dc4aadaabe3c56567dc21363158")
print(" Signature:\t",binascii.hexlify(signature))
print("     Valid:\t", vk.verify_digest(signature, msg))

# uECC (latest-with-rfc6979)

print("=========================")
signature = binascii.unhexlify(b"0b8ed244c3db416320affcc88867fe3bbf30637a4dff3c9e19b067fef5b2d04ed850f7d3796a474d0ff4d20b187e202ff720c51a1defab58be52c9a470175e19")
print(" Signature:\t",binascii.hexlify(signature))
print("     Valid:\t", vk.verify_digest(signature, msg))

# uECC (latest-with-rfc6979, sign-with-k from trezor)

print("=========================")
signature = binascii.unhexlify(b"57eae071cc7c91561da7e4a21d500fbe65649ac0ba30c698ac91f75ff36a345b6609d69391c85aec85eeeca8aa46d3bb83b423ac4863bb1ec38ef112b0c1dca9")
print(" Signature:\t",binascii.hexlify(signature))
print("     Valid:\t", vk.verify_digest(signature, msg))

# noble

print("=========================")
signature = binascii.unhexlify(b"71f498f5d9a05e83599a65e31febd4fb07451127031cf069c05c55ce586f248b0247be206cff797fe03223673560c431cf2f94a02ebbb09fda8e4a7b03c2f353")
print(" Signature:\t",binascii.hexlify(signature))
print("     Valid:\t", vk.verify_digest(signature, msg))

# uECC (latest-with-rfc6979, sign-with-k from noble)

print("=========================")
signature = binascii.unhexlify(b"71f498f5d9a05e83599a65e31febd4fb07451127031cf069c05c55ce586f248bfdb841df930086801fcddc98ca9f3bcceb7f4846808cef9be5441411cc734dee")
print(" Signature:\t",binascii.hexlify(signature))
print("     Valid:\t", vk.verify_digest(signature, msg))

# noble-secp256k1-rs

print("=========================")
signature = binascii.unhexlify(b"71f498f5d9a05e83599a65e31febd4fb07451127031cf069c05c55ce586f248bfdb841df930086801fcddc98ca9f3bcceb7f4846808cef9be5441411cc734dee")
print(" Signature:\t",binascii.hexlify(signature))
print("     Valid:\t", vk.verify_digest(signature, msg))
