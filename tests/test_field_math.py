"""
Tests for modular arithmetic helpers in primitives/field_math.py

These tests verify the mathematical properties that ALL other modules
depend on. If mod_inverse is wrong, everything breaks silently.
"""
import pytest
from primitives.field_math import mod_inverse, mod_sqrt, is_quadratic_residue
from primitives.constants import P


class TestModInverse:
    def test_basic_inverse(self):
        # 3 * 4 = 12 ≡ 1 (mod 11), so inverse of 3 mod 11 is 4
        assert mod_inverse(3, 11) == 4

    def test_inverse_times_original_equals_one(self):
        # The defining property: a * a^(-1) ≡ 1 (mod p)
        a = 123456789
        inv = mod_inverse(a, P)
        assert (a * inv) % P == 1

    def test_zero_raises(self):
        with pytest.raises(ValueError):
            mod_inverse(0, 11)

    def test_inverse_of_one_is_one(self):
        assert mod_inverse(1, P) == 1


class TestModSqrt:
    def test_sqrt_squared_equals_original(self):
        # If s = sqrt(a) mod p, then s^2 ≡ a (mod p)
        a = 4
        p = 11  # 11 ≡ 3 mod 4, so the simple formula works
        s = mod_sqrt(a, p)
        assert (s * s) % p == a

    def test_non_residue_raises_or_wrong(self):
        # Not every number has a square root mod p
        # 2 is not a quadratic residue mod 11
        assert not is_quadratic_residue(2, 11)


class TestQuadraticResidue:
    def test_perfect_squares_are_residues(self):
        p = 11
        # 4 = 2^2 is always a residue
        assert is_quadratic_residue(4, p)

    def test_known_non_residue(self):
        # 2 has no square root mod 11
        assert not is_quadratic_residue(2, 11)
