from random import randrange
from hashlib import sha1
from gmpy2 import xmpz, to_binary, invert, powmod, is_prime

def generate_p_q(L, N):
    """
    Генерація простих чисел p та q для DSA.
    :param L: Довжина ключа
    :param N: Мінімальний розмір групи
    :return: Кортеж (p, q)
    """
    g = N  # Мінімальний розмір групи
    n = (L - 1) // g
    b = (L - 1) % g
    while True:
        # Генерація q
        while True:
            s = xmpz(randrange(1, 2 ** (g)))
            a = sha1(to_binary(s)).hexdigest()
            zz = xmpz((s + 1) % (2 ** g))
            z = sha1(to_binary(zz)).hexdigest()
            U = int(a, 16) ^ int(z, 16)
            mask = 2 ** (N - 1) + 1
            q = U | mask
            if is_prime(q, 20):
                break
        # Генерація p
        i = 0  # лічильник
        j = 2  # зсув
        while i < 4096:
            V = []
            for k in range(n + 1):
                arg = xmpz((s + j + k) % (2 ** g))
                zzv = sha1(to_binary(arg)).hexdigest()
                V.append(int(zzv, 16))
            W = 0
            for qq in range(0, n):
                W += V[qq] * 2 ** (160 * qq)
            W += (V[n] % 2 ** b) * 2 ** (160 * n)
            X = W + 2 ** (L - 1)
            c = X % (2 * q)
            p = X - c + 1  # p = X - (c - 1)
            if p >= 2 ** (L - 1):
                if is_prime(p, 10):
                    return p, q
            i += 1
            j += n + 1

def generate_g(p, q):
    """
    Генерація генератора g для DSA.
    :param p: Просте число p
    :param q: Просте число q
    :return: Генератор g
    """
    while True:
        h = randrange(2, p - 1)
        exp = xmpz((p - 1) // q)
        g = powmod(h, exp, p)
        if g > 1:
            break
    return g

def generate_keys(g, p, q):
    """
    Генерація ключів x та y для DSA.
    :param g: Генератор g
    :param p: Просте число p
    :param q: Просте число q
    :return: Кортеж (x, y)
    """
    x = randrange(2, q)  # x < q
    y = powmod(g, x, p)
    return x, y

def generate_params(L, N):
    """
    Генерація параметрів для DSA.
    :param L: Довжина ключа
    :param N: Мінімальний розмір групи
    :return: Кортеж (p, q, g)
    """
    p, q = generate_p_q(L, N)
    g = generate_g(p, q)
    return p, q, g

def sign(M, p, q, g, x):
    """
    Підписання повідомлення для DSA.
    :param M: Повідомлення для підпису
    :param p: Просте число p
    :param q: Просте число q
    :param g: Генератор g
    :param x: Приватний ключ x
    :return: Підпис (r, s)
    """
    if not validate_params(p, q, g):
        raise Exception("Invalid params")
    while True:
        k = randrange(2, q)  # k < q
        r = powmod(g, k, p) % q
        m = int(sha1(M).hexdigest(), 16)
        try:
            s = (invert(k, q) * (m + x * r)) % q
            return r, s
        except ZeroDivisionError:
            pass

def verify(M, r, s, p, q, g, y):
    """
    Перевірка підпису для DSA.
    :param M: Повідомлення
    :param r: Перший компонент підпису
    :param s: Другий компонент підпису
    :param p: Просте число p
    :param q: Просте число q
    :param g: Генератор g
    :param y: Публічний ключ y
    :return: True, якщо підпис вірний, False в іншому випадку
    """
    if not validate_params(p, q, g):
        raise Exception("Invalid params")
    if not validate_sign(r, s, q):
        return False
    try:
        w = invert(s, q)
    except ZeroDivisionError:
        return False
    m = int(sha1(M).hexdigest(), 16)
    u1 = (m * w) % q
    u2 = (r * w) % q
    v = (powmod(g, u1, p) * powmod(y, u2, p)) % p % q
    if v == r:
        return True
    return False

def validate_params(p, q, g):
    """
    Перевірка валідності параметрів DSA.
    :param p: Просте число p
    :param q: Просте число q
    :param g: Генератор g
    :return: True, якщо параметри валідні, False в іншому випадку
    """
    if is_prime(p) and is_prime(q):
        return True
    if powmod(g, q, p) == 1 and g > 1 and (p - 1) % q:
        return True
    return False

def validate_sign(r, s, q):
    """
    Перевірка валідності підпису DSA.
    :param r: Перший компонент підпису
    :param s: Другий компонент підпису
    :param q: Просте число q
    :return: True, якщо підпис валідний, False в іншому випадку
    """
    if r < 0 and r > q:
        return False
    if s < 0 and s > q:
        return False
    return True

if __name__ == "__main__":
    N = 160
    L = 1024
    p, q, g = generate_params(L, N)
    x, y = generate_keys(g, p, q)

    text = "Nikita"
    M = str.encode(text, "ascii")
    r, s = sign(M, p, q, g, x)
    if verify(M, r, s, p, q, g, y):
        print('All ok')
    print('Message:', M.decode('ascii'))
    print('Signature:', (r, s))
    print('p, q, g:', p, q, g)
    print('Public key (y):', y)
    print('Private key (x):', x)
