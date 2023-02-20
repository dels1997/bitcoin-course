import operator
import functools
from bsgs import baby_step_giant_step

def chinese_remainder_theorem(a, m):
    sum = 0
    M = functools.reduce(operator.mul, m, 1)
    assert len(a) == len(m)
    for i in range(len(a)):
        p = M // m[i]
        sum += a[i] * pow(p, -1, m[i]) * p
    return sum % M

def factors(n):
    factorisation = []
    f = 2
    while f * f <= n:
        if n % f == 0:
            exp = 0
            while n % f == 0:
                exp = exp + 1
                n = n / f
            factorisation.append([f, exp])
        f = f + 1
    if n > 1:
        factorisation.append([n, 1])
    return factorisation

def pohlig_hellman(g, h, p, factors):
    x = []
    pe = []
    for i in range(len(factors)):
        pe.append(pow(factors[i][0], factors[i][1]))
        gtemp = pow(g, p // pe[i], p)
        htemp = pow(h, p // pe[i], p)
        x.append(baby_step_giant_step(gtemp, htemp, p) % pe[i])

    dl = chinese_remainder_theorem(x, pe)
    return dl


g = 6
h = 7531
p = 8101
print("x = " + str(pohlig_hellman(g, h, p, factors(p - 1))))
