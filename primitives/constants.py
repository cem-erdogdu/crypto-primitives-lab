"""
Curve parameters for secp256k1 — the elliptic curve used by Bitcoin,
Monero (via ed25519 for some components), and many other systems.

The curve equation is: y^2 = x^3 + ax + b  (mod p)
For secp256k1: a=0, b=7, so y^2 = x^3 + 7  (mod p)

These constants are standardized — you cannot choose them freely.
The security of the whole system depends on p and n being large primes
and G being chosen such that the discrete logarithm is hard.
"""

# The prime that defines the finite field
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# Curve coefficients (secp256k1 has a=0, b=7)
A = 0
B = 7

# The order of the curve (number of points on the curve)
# This is the modulus for scalar arithmetic (private keys live in Z_n)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# The generator point G = (Gx, Gy)
# This is the "base point" — all public keys are multiples of G
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
