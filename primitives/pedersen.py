"""
Pedersen commitments for cryptographic commitment schemes.

A commitment scheme allows a party to commit to a value while keeping it hidden,
with the ability to later reveal (or "open") the value. Pedersen commitments are
widely used in blockchain protocols (e.g., Monero's range proofs), zero-knowledge
proofs, and secure multiparty computation.

This module provides:
- A commit function: creates a commitment C = v*G + r*H
- A verify function: checks if a commitment opens correctly
- An add function: combines commitments, demonstrating the homomorphic property

The core idea:
--------------
A Pedersen commitment to a value v with blinding factor r is:

    C = v * G + r * H

where G is the standard generator point for secp256k1 and H is a second generator
point chosen so that the discrete logarithm relationship between G and H is unknown.

Why this construction works:
----------------------------
- HIDING: Given only C, an observer cannot determine v without knowing r. Since r
  is chosen uniformly at random from a large range, there are many possible (v, r)
  pairs that produce the same C, making it information-theoretically hiding under
  the assumption that the discrete log between G and H is unknown.
- BINDING: Once you have committed to (v, r) producing C, it is computationally
  infeasible to find a different (v', r') with v' != v such that C = v'*G + r'*H.
  Doing so would require finding the discrete log of H with respect to G, which is
  assumed to be hard (ECDLP).

The homomorphic property:
-------------------------
Pedersen commitments are additively homomorphic:

    commit(v1, r1) + commit(v2, r2) = commit(v1 + v2, r1 + r2)

This follows directly from the linearity of scalar multiplication:

    (v1*G + r1*H) + (v2*G + r2*H) = (v1 + v2)*G + (r1 + r2)*H

This property is essential for applications like confidential transactions,
where you want to prove that inputs equal outputs without revealing individual values.
"""

import hashlib
from typing import Tuple

from primitives.constants import P, N
from primitives.elliptic_curve import Point
from primitives.field_math import mod_sqrt, is_quadratic_residue


# -----------------------------------------------------------------------------
# DERIVING THE SECOND GENERATOR H
# -----------------------------------------------------------------------------
#
# We need a second generator point H on secp256k1 such that nobody knows the
# discrete logarithm h where H = h * G. If someone knew h, they could break
# the binding property of Pedersen commitments by finding alternate openings.
#
# We use the "nothing-up-my-sleeve" technique:
#   1. Hash a well-known constant string (like "Pedersen H" or a protocol name)
#   2. Interpret the hash output as a candidate x-coordinate
#   3. Try to find a valid y such that (x, y) lies on the curve
#   4. If no such y exists (x is not a quadratic residue for x^3 + 7), we
#      increment and try again
#
# Because the hash is a one-way function and G was chosen by the secp256k1
# standard (not by us), there is no way for anyone to know the relationship
# between G and H unless they can either:
#   - Break the preimage resistance of SHA-256, or
#   - Solve the ECDLP (find h such that H = h * G)
#
# This is the standard approach used in Monero, Bulletproofs, and many other
# cryptographic protocols.
# -----------------------------------------------------------------------------


def _derive_generator_h() -> Point:
    """
    Derive a second generator point H on secp256k1.

    H is derived deterministically by hashing a constant string and finding
    the first valid curve point. Because this process is public and based on
    a standard hash function, nobody can know the discrete log of H with
    respect to G — unless they can break the ECDLP or SHA-256 preimage resistance.

    The derivation process:
    1. Start with a seed string and hash it with SHA-256.
    2. Interpret the hash as a candidate x-coordinate (take it modulo p).
    3. Check if x^3 + 7 has a square root modulo p (i.e., is a quadratic residue).
    4. If yes, compute y = sqrt(x^3 + 7) mod p and return the point (x, y).
    5. If no, hash the current x again and repeat until a valid point is found.

    Returns:
        A point H on the secp256k1 curve such that the discrete log of H
        with respect to G is unknown.
    """
    # The seed string is arbitrary but fixed — changing it would give a different H.
    # Using a descriptive string makes the origin transparent and auditable.
    seed = b"Pedersen commitment second generator H for secp256k1"

    # Counter ensures we can keep trying if a hash doesn't yield a valid x-coordinate.
    counter = 0

    while True:
        # Hash the seed concatenated with the counter to get a candidate x value.
        # We use SHA-256 which produces 256 bits — exactly the size of field elements.
        candidate_bytes = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()

        # Interpret the hash as an integer and reduce modulo p to get a valid x.
        x_candidate = int.from_bytes(candidate_bytes, "big") % P

        # For (x, y) to lie on secp256k1, we need y^2 = x^3 + 7 (mod p).
        # First, compute y_squared = x^3 + 7 mod p.
        y_squared = (pow(x_candidate, 3, P) + 7) % P

        # Check if y_squared is a quadratic residue — i.e., has a square root mod p.
        # If not, this x cannot be on the curve, so we try again with a new hash.
        if is_quadratic_residue(y_squared, P):
            # Compute one of the two square roots. For secp256k1 (p ≡ 3 mod 4),
            # we can use the simple formula: y = y_squared^((p+1)/4) mod p.
            y = mod_sqrt(y_squared, P)

            # We pick the even y value by convention (this is arbitrary but standard).
            # This ensures H is uniquely defined given the seed.
            if y % 2 != 0:
                y = P - y

            # Construct and return the point. The constructor verifies it lies on the curve.
            return Point(x_candidate, y)

        # This x didn't work — try the next counter value.
        counter += 1


# Derive H once at module load time. This is deterministic and public.
H = _derive_generator_h()


def commit(value: int, blinding_factor: int) -> Point:
    """
    Create a Pedersen commitment to a value.

    The commitment is computed as:

        C = value * G + blinding_factor * H

    where G is the standard secp256k1 generator and H is our independently
    derived second generator (see module docstring for why H is constructed this way).

    Args:
        value: The value being committed to (e.g., an amount in a transaction).
               This can be any integer; it will be reduced modulo N (the curve order).
        blinding_factor: A random secret value r that "hides" the commitment.
                         This must be kept secret until you want to open the commitment.
                         It will be reduced modulo N.

    Returns:
        A point C on the curve representing the commitment.

    Cryptographic properties:
    -------------------------
    - HIDING: Given only C, an adversary cannot determine 'value' without knowing
      'blinding_factor'. There are approximately N possible blinding factors for
      each possible value, and each produces a different C. Without r, all values
      are equally plausible openings from the adversary's perspective.
    - BINDING: Once you publish C, you are effectively "locked in" to one value.
      Finding a different (value', r') that opens to the same C would require
      computing the discrete log of H with respect to G, which is believed to be
      computationally infeasible.
    """
    # Reduce both inputs modulo N (the order of the curve group).
    # This ensures the scalar multiplication is well-defined and consistent.
    v = value % N
    r = blinding_factor % N

    # Compute the commitment: C = v*G + r*H
    # This uses the Point class's __mul__ (scalar multiplication) and __add__ (point addition).
    C = v * Point.generator() + r * H

    return C


def verify(commitment: Point, value: int, blinding_factor: int) -> bool:
    """
    Verify that a commitment opens correctly to the claimed value and blinding factor.

    This checks whether the equation:

        commitment == value * G + blinding_factor * H

    holds. If it does, the prover has successfully demonstrated knowledge of a valid
    opening (value, blinding_factor) for the commitment.

    Args:
        commitment: The Pedersen commitment point C to verify.
        value: The claimed committed value v.
        blinding_factor: The claimed blinding factor r.

    Returns:
        True if the commitment opens correctly to the given value and blinding factor,
        False otherwise.

    Why this works:
    ---------------
    By the binding property, there is (computationally) only one valid opening for
    any given commitment C. If verify returns True, the prover has either:
    - Revealed the original (v, r) used to create C, or
    - Found a collision (v', r') ≠ (v, r) such that C = v'*G + r'*H — which would
      require solving the ECDLP, believed to be infeasible.

    Therefore, a successful verification gives confidence that the committed value
    really is what the prover claims.
    """
    # Recompute what the commitment should be if the claimed opening is correct.
    expected = commit(value, blinding_factor)

    # Check if it matches the provided commitment.
    return commitment == expected


def add_commitments(c1: Point, c2: Point) -> Point:
    """
    Add two Pedersen commitments together.

    This demonstrates the additive homomorphic property of Pedersen commitments:

        commit(v1, r1) + commit(v2, r2) == commit(v1 + v2, r1 + r2)

    The mathematical justification is straightforward:

        C1 + C2 = (v1*G + r1*H) + (v2*G + r2*H)
                = (v1 + v2)*G + (r1 + r2)*H
                = commit(v1 + v2, r1 + r2)

    This property is extremely useful in practice. For example, in confidential
    transactions, you might want to prove that the sum of input amounts equals
    the sum of output amounts without revealing any individual amount. By adding
    commitments, you can verify such balance equations in the commitment space.

    Args:
        c1: The first commitment (e.g., commit(v1, r1)).
        c2: The second commitment (e.g., commit(v2, r2)).

    Returns:
        A new commitment representing the sum: commit(v1 + v2, r1 + r2).

    Note:
        The result is only a valid Pedersen commitment if the caller also tracks
        the combined blinding factor (r1 + r2) for potential later verification.
        In many protocols, this is done by the party who controls both factors.
    """
    # Point addition is already defined on the Point class via __add__.
    # Adding two commitments directly gives us the homomorphic sum.
    return c1 + c2
