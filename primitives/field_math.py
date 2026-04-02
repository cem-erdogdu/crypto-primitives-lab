"""
Modular arithmetic helpers used across all cryptographic primitives.

These are the basic building blocks. Every elliptic curve operation,
every commitment, and every signature scheme ultimately reduces to
arithmetic in a finite field — integers modulo a large prime p.
"""


def mod_inverse(a: int, p: int) -> int:
    """
    Compute the modular inverse of a modulo p using Fermat's little theorem.
    
    By Fermat's theorem, a^(p-1) ≡ 1 (mod p) when p is prime,
    so a^(p-2) ≡ a^(-1) (mod p).
    
    This is used for elliptic curve point doubling and addition
    wherever we need to divide in the finite field.
    """
    if a % p == 0:
        raise ValueError("No inverse exists: a is divisible by p")
    return pow(a, p - 2, p)


def mod_sqrt(a: int, p: int) -> int:
    """
    Compute the square root of a modulo p (Tonelli-Shanks algorithm).
    
    Used when recovering a point on the curve from only its x-coordinate,
    which is how compressed public keys work in Bitcoin and Monero.
    
    Assumes p ≡ 3 (mod 4) for the simple case (true for secp256k1).
    """
    if p % 4 != 3:
        raise NotImplementedError("Only implemented for p ≡ 3 mod 4")
    return pow(a, (p + 1) // 4, p)


def is_quadratic_residue(a: int, p: int) -> bool:
    """
    Check if a has a square root modulo p (Euler's criterion).
    
    a is a quadratic residue mod p if a^((p-1)/2) ≡ 1 (mod p).
    Used to determine which of the two possible y-values is valid
    when decompressing a curve point.
    """
    return pow(a, (p - 1) // 2, p) == 1
