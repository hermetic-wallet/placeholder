x = 0x79be667e_f9dcbbac_55a06295_ce870b07_029bfcdb_2dce28d9_59f2815b_16f81798
y = 0x483ada77_26a3c465_5da4fbfc_0e1108a8_fd17b448_a6855419_9c47d08f_fb10d4b8
p = 0xffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_fffffffe_fffffc2f

def mod_inverse(num, mod = p):
    return pow(num, -1, mod=p)

int0 = x * x % p
print("int0", hex(int0))

int1 = 3 * int0 % p
print("int1", hex(int1))

inv = mod_inverse(2 * y, p)
print("inv ", hex(inv))

lam = int1 * inv % p
print("lam ", hex(lam))

lam2 = lam * lam % p
print("lam2", hex(lam2))

lam3 = lam2 - x
print("lam3", hex(lam3))

lam4 = lam2 - x - x
print("lam4", hex(lam4))
