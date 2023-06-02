import random
import math


lowPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
   67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
   157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241,
   251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,317, 331, 337, 347, 349,
   353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449,
   457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569,
   571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
   673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
   797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907,
   911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]


def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b


def findModInverse(a, m):
    result = 0
    try:
        result = pow(a, -1, m)
    except:
        return 0
    return result


def rabinMiller(num):
    s = num - 1
    t = 0

    while s % 2 == 0:
        s = s // 2
        t += 1
    for trials in range(3):
        a = random.randint(2, num - 1)
        v = pow(a, s, num)
        if v != 1:
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
        return True


def isPrime(num):
    if num < 2:
        return False
    if num in lowPrimes:
        return True
    for prime in lowPrimes:
        if num % prime == 0:
            return False
    return rabinMiller(num)


def generatePrime(keysize):
    while True:
        num = random.randint(2 ** (keysize - 1), 2 ** keysize)
        if isPrime(num):
            return num


def generateRSAKey(keySize):

    p = generatePrime(keySize)
    q = generatePrime(keySize)
    n = p * q

    # e = (p-1)*(q-1).
    while True:
        e = random.randint(2 ** (keySize - 1), 2 ** keySize)
        if gcd(e, (p - 1) * (q - 1)) == 1:
            break

    # Oblicz d, czyli element odwrotny do e
    d = findModInverse(e, (p - 1) * (q - 1))
    publicKey = (n, e)
    privateKey = (n, d)

    return publicKey, privateKey


def generateElGamalKey(keySize):
    p = generatePrime(keySize)
    g = 2
    x = generatePrime(keySize)
    y = pow(g, x, p)
    el_public_key = (p, g, y)
    el_private_key = (p, g, x)
    return el_public_key, el_private_key


def rsa_sign(message, private_key):
    n, d = private_key
    signature = pow(int.from_bytes(message.encode(), 'big'), d, n)
    return signature


def rsa_verify(message, signature, public_key):
    n, e = public_key
    decrypted_signature = pow(signature, e, n)
    decrypted_message = decrypted_signature.to_bytes((decrypted_signature.bit_length() + 7) // 8, 'big').decode()
    return decrypted_message == message


def elgamal_sign(message, private_key):
    p, g, x = private_key
    k = random.randint(1, p - 1)
    r = pow(g, k, p)
    s = (findModInverse(k, p - 1) * (int.from_bytes(message.encode(), 'big') - x * r)) % (p - 1)
    return r, s


def elgamal_verify(message, signature, public_key):
    p, g, y = public_key
    r, s = signature
    m = int.from_bytes(message.encode(), 'big')

    w = findModInverse(s, p - 1)

    u1 = (pow(g, m, p) * pow(y, r, p)) % p
    u2 = r

    v = (pow(u1, w, p) * u2) % p

    return v == r


def save_key_to_file(key, filename):
    with open(filename, 'w') as file:
        file.write(','.join(map(str, key)))


def load_key_from_file(filename):
    with open(filename, 'r') as file:
        key_data = file.read().split(',')
    return int(key_data[0]), int(key_data[1])


def save_signature_to_file(signature, filename):
    with open(filename, 'w') as file:
        file.write(','.join(map(str, [signature])))


def load_signature_from_file(filename):
    with open(filename, 'r') as file:
        signature_data = file.read().split(',')
    return int(signature_data[0]), int(signature_data[1])


if __name__ == "__main__":
    rsa_public_key, rsa_private_key = generateRSAKey(1024)
    save_key_to_file(rsa_public_key, 'rsa_public_key.txt')
    save_key_to_file(rsa_private_key, 'rsa_private_key.txt')

    el_public_key, el_private_key = generateElGamalKey(1024)
    save_key_to_file(el_public_key, 'elgamal_public_key.txt')
    save_key_to_file(el_private_key, 'elgamal_private_key.txt')

    message = input("Enter the message to sign: ")
    signature = rsa_sign(message, rsa_private_key)
    save_signature_to_file(signature, 'signature.txt')

    is_valid = rsa_verify(message, signature, rsa_public_key)
    if is_valid:
        print("RSA Signature is valid.")
    else:
        print("RSA Signature is invalid.")

    signature = elgamal_sign(message, el_private_key)
    save_signature_to_file(signature, 'el_signature.txt')

    is_valid = elgamal_verify(message, signature, el_private_key)

    if is_valid:
        print("ElGamal Signature is valid.")
    else:
        print("ElGamal Signature is invalid.")
