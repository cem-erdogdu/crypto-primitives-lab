"""
Tests for elliptic curve point arithmetic in primitives/elliptic_curve.py

These tests verify the core operations of secp256k1 point arithmetic:
- Point addition and doubling
- Scalar multiplication via the double-and-add algorithm
- Proper handling of the point at infinity
- Public key derivation (private key * G)
"""

import pytest
from primitives.elliptic_curve import Point
from primitives.constants import N


class TestPointCreation:
    """Tests for creating points on the curve and the point at infinity."""

    def test_generator_point_is_on_curve(self):
        # The generator G is a well-known point that must satisfy the curve equation.
        G = Point.generator()
        assert G.is_on_curve()

    def test_infinity_is_valid(self):
        # The point at infinity is always considered valid.
        inf = Point.infinity()
        assert inf.is_on_curve()
        assert inf.is_infinity

    def test_invalid_point_raises(self):
        # A random point (1, 2) almost certainly does not lie on secp256k1.
        with pytest.raises(ValueError):
            Point(1, 2)


class TestPointAddition:
    """Tests for the elliptic curve group operation (point addition)."""

    def test_addition_with_infinity_is_identity(self):
        # P + infinity = P for any point P (identity element property).
        G = Point.generator()
        inf = Point.infinity()
        assert G + inf == G
        assert inf + G == G

    def test_double_equals_scalar_multiply_by_two(self):
        """
        Verify that adding G to itself produces the same result as 2 * G.

        This is a fundamental sanity check: the scalar multiplication algorithm
        must be consistent with repeated addition. If G + G != 2 * G, then
        our double-and-add implementation is broken.

        Mathematics:
            - G + G uses the point doubling formula (tangent slope).
            - 2 * G uses the double-and-add algorithm, which for k=2 performs:
                result = infinity, then doubles to infinity, then adds G
                since bit 1 of binary "10" is set.
              This gives G + G as well, so both must match.
        """
        G = Point.generator()

        # Compute G + G using point addition (which internally uses doubling).
        doubled_by_add = G + G

        # Compute 2 * G using scalar multiplication.
        doubled_by_scalar = 2 * G

        # They must be identical.
        assert doubled_by_add == doubled_by_scalar
        assert doubled_by_add.is_on_curve()


class TestScalarMultiplication:
    """Tests for scalar multiplication k * P."""

    def test_multiplying_by_order_gives_infinity(self):
        """
        Verify that N * G = infinity, where N is the order of the curve.

        The order N of secp256k1 is defined as the smallest positive integer
        such that N * G = infinity. This is a fundamental property of cyclic
        groups: every element P satisfies |P| * P = identity.

        Mathematics:
            - The curve has exactly N points (including infinity), forming a
              cyclic group of order N under point addition.
            - By Lagrange's theorem, for any point P in the group, the order
              of P divides N. For the generator G, the order is exactly N.
            - Therefore, adding G to itself N times cycles back to the start:
              N * G = infinity (the identity element).

        This test is critical because if it fails, signatures and key derivation
        would produce incorrect results (modular reduction by N would be wrong).
        """
        G = Point.generator()
        result = N * G
        assert result.is_infinity

    def test_scalar_zero_gives_infinity(self):
        # 0 * P = infinity for any point P (by definition / convention).
        G = Point.generator()
        assert 0 * G == Point.infinity()

    def test_scalar_one_gives_same_point(self):
        # 1 * P = P for any point P.
        G = Point.generator()
        assert 1 * G == G


class TestPublicKeyDerivation:
    """Tests for deriving a public key from a private key."""

    def test_private_key_times_g_yields_valid_point(self):
        """
        Verify that multiplying any valid private key by G yields a valid curve point.

        In elliptic curve cryptography, a private key is simply a random integer
        k in the range [1, N-1], and the corresponding public key is:

            PublicKey = k * G

        This test picks a sample private key and checks that:
        1. The resulting point lies on the curve.
        2. The point is not the point at infinity (which would be invalid).

        Mathematics:
            - Since k is in [1, N-1] and G has order N, k * G can never be
              infinity (that would require k ≡ 0 (mod N), which is excluded).
            - Every scalar multiple of G is a valid point on the curve by
              closure of the group operation.
        """
        # A sample private key (in practice this would be generated randomly
        # and kept secret). Using a fixed value here for reproducibility.
        private_key = 12345678901234567890

        # Derive the public key: PublicKey = private_key * G
        public_key = private_key * Point.generator()

        # The public key must be a valid point on the curve.
        assert public_key.is_on_curve()

        # The public key must not be the point at infinity.
        # This would only happen if private_key ≡ 0 (mod N), which we avoid.
        assert not public_key.is_infinity

    def test_different_private_keys_give_different_public_keys(self):
        # Different private keys should (with overwhelming probability) yield
        # different public keys. This is the basis of address uniqueness.
        pk1 = 1
        pk2 = 2

        pub1 = pk1 * Point.generator()
        pub2 = pk2 * Point.generator()

        assert pub1 != pub2
        assert pub1.is_on_curve()
        assert pub2.is_on_curve()
