from itertools import product, permutations, combinations_with_replacement, combinations

digits = 4
pairs = []
pair_format = "{0:0" + str(digits) + "b}"
for i in range(0, 2 ** digits):
    pairs.append(pair_format.format(i))

pairs = list(product(pairs, repeat=2))
print(pairs)

for pair in pairs:
    n1, n2 = pair

    zum = int(n1, base=2) + int(n2, base=2)

    form = "{0:0" + str(digits + 1) + "b}"
    true_sum = form.format(zum)
    print ("x{}".format(n1), "x{}".format(n2), form.format(zum), sep = '\n')

    pos = digits - 1
    carry = 0
    manual_sum = []
    while pos >= 0:
        p1 = int(n1[pos])
        p2 = int(n2[pos])

        next_digit = p1 ^ p2 ^ carry
        carry = (p1 & p2) | (p1 & carry) | (p2 & carry)
        pos = pos - 1
        manual_sum.append(str(next_digit))

    
    print('{}{}'.format(carry, ''.join(reversed(manual_sum))))
    manual_sum = '{}{}'.format(carry, ''.join(reversed(manual_sum)))
    if true_sum ==  manual_sum:
        print ('', sep='\n')
    else:
        print ("FAIL", '', sep='\n')
