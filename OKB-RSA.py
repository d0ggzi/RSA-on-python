import random
import math


class RSA:
    def __init__(self, p, q):
        self.private_key, self.public_key = self._rsa_generate_key(p, q)

    def _powermod(self, a, n, m):
        p = 1
        b = a
        k = n
        while k > 0:
            if k % 2 == 0:
                k //= 2
                b = b * b % m
            else:
                k -= 1
                p = p * b % m
        return p

    def _egcd(self, a, b):
        if a == 0:
            return b, 0, 1
        g, y, x = self._egcd(b % a, a)
        return g, x - (b // a) * y, y

    def _mod_inverse(self, a, m):
        g, x, y = self._egcd(a, m)
        if g != 1:
            raise Exception('No mod inverse')
        return x % m

    def _chinese_remainder_theorem(self, n1: int, r1: int, n2: int, r2: int) -> int:
        (_, x, y) = self._egcd(n1, n2)
        m = n1 * n2
        n = r2 * x * n1 + r1 * y * n2
        return (n % m + m) % m

    def _rsa_generate_key(self, p: int, q: int):
        """Return an RSA key pair generated using primes p and q."""
        n = p * q
        phi_n = (p - 1) * (q - 1)

        e = random.randint(10000, phi_n - 1)
        while math.gcd(e, phi_n) != 1:
            e = random.randint(1000, phi_n - 1)

        d = self._mod_inverse(e, phi_n)

        return (p, q, d), (n, e)

    def rsa_encrypt_text(self, plaintext: str) -> str:
        """Encrypt the given plaintext using the recipient's public key."""
        n, e = self.public_key

        encrypted = ''
        for letter in plaintext:
            encrypted = encrypted + chr(self._powermod(ord(letter), e, n))

        return encrypted

    def rsa_decrypt_text(self, ciphertext: str) -> str:
        """Decrypt the given ciphertext using the recipient's private key."""
        p, q, d = self.private_key

        decrypted = ''
        for letter in ciphertext:
            r1 = self._powermod(ord(letter), d, p)
            r2 = self._powermod(ord(letter), d, q)
            decrypted = decrypted + chr(self._chinese_remainder_theorem(p, r1, q, r2))

        return decrypted


if __name__ == '__main__':
    p, q = map(int, input("Enter prime numbers p, q (greater than 100): ").split())
    while p < 100 or q < 100:
        print("Input values are too small")
        p, q = map(int, input("Enter prime numbers p, q (greater than 100): ").split())
    text = input("Enter your text: ")
    rsa = RSA(p, q)
    cipher_text = rsa.rsa_encrypt_text(text)
    print("Your ciphertext is: " + cipher_text)
    decrypted_text = rsa.rsa_decrypt_text(cipher_text)
    print("Decrypted text is: " + decrypted_text)
