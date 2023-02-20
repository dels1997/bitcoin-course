import math

def baby_step_giant_step(g, h, p):
    m = math.ceil(p ** 0.5)
    # Compute baby steps.
    baby_steps = {}
    baby_steps_inverse = {}
    x = 1
    for j in range(m):
        baby_steps[j] = x
        baby_steps_inverse[x] = j
        x = (x * g) % p

    # Compute giant steps.
    giant_step = pow(g, -m, p)
    y = h
    for i in range(m):
        if y in baby_steps.values():
            return i * m + baby_steps_inverse[y]
        y = (y * giant_step) % p

    raise ValueError("No solution found")

# Example use.
# g = 2
# h = 15
# p = 29
# x = baby_step_giant_step(g, h, p)
# print("x =", x)
# print("g^x =", pow(g, x, p)) # should be equal to h
