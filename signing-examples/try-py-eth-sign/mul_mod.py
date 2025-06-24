P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

MAX_BITS = 257
"""
    mul_mod can take two 256-bit nums (32-byte)
    an alloc 4 (+1 for buf) x 257-bit (33-byte, total of 132 bytes)

    or take in two 257-bit num and allocate another
    num, for total alloc of 33-byte

    comparison:
        height of stack has > 22 allocs, so even if you use 256-bit
        you would only save 1 num, whereas you'd have to allocate 4 extra

    NOTE: since you're working in 32-byte or 33-byte space, `mod`
            can be replaced with `minus` operation.
"""
def mul_mod(A, B):
    res = 0 # alloc, but could use A
    M = A % P # alloc

    while B > 0:
        #print("B =", B)
        if B & 1:
            assert M + res < 2 ** MAX_BITS
            if res + M > P:
                assert res + M - P < P
            res = (res + M) % P
            assert M < 2 ** MAX_BITS
            assert res < 2 ** MAX_BITS
            #print("res =", res)

        B >>= 1
        #print("B =", B)
        M <<= 1
        assert  M < 2 ** MAX_BITS
        #print("M =", M)
        if M > P:
            assert M - P < P
        M %= P
        #print()

    return res


#print(mul_mod(2,4))
#print(mul_mod(P+1,P-2))

x = 0x79be667e_f9dcbbac_55a06295_ce870b07_029bfcdb_2dce28d9_59f2815b_16f81798

print(mul_mod(x,x))
