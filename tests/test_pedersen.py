"""
Tests for Pedersen commitments in primitives/pedersen.py

These tests verify the core cryptographic properties of Pedersen commitments:
- HIDING: Commitments do not reveal the committed value without the blinding factor
- BINDING: Once committed, you cannot open to a different value
- HOMOMORPHISM: Commitments can be added to produce commitments of sums

The tests include inline comments explaining what each property means and
why the Pedersen construction achieves it.
"""

import pytest
from primitives.pedersen import commit, verify, add_commitments, H
from primitives.elliptic_curve import Point
from primitives.constants import N


class TestCommitmentCreation:
    """Tests for basic commitment creation and the hiding property."""

    def test_commitment_is_a_valid_point_on_curve(self):
        # A commitment must always be a valid point on the curve.
        C = commit(100, 42)
        assert isinstance(C, Point)
        assert C.is_on_curve()

    def test_commitment_to_same_value_with_different_randomness_differs(self):
        """
        Verify that committing to the same value twice with different blinding
        factors produces different commitments.

        This is a direct consequence of the HIDING property. If the same value
        always produced the same commitment regardless of randomness, then an
        observer could build a lookup table (rainbow table) of all possible
        values and their commitments, completely breaking privacy.

        The mathematical reason:
            commit(v, r1) = v*G + r1*H
            commit(v, r2) = v*G + r2*H

            These are equal only if (r1 - r2)*H = 0, which (for r1 != r2 and H
            having order N) only happens if r1 ≡ r2 (mod N). Since we pick r
            from a huge range and use different values, the commitments differ.

        This test verifies that the blinding factor actually "blinds" the value.
        """
        value = 12345

        # Commit to the same value using two different random blinding factors.
        r1 = 11111111111111111111
        r2 = 22222222222222222222

        C1 = commit(value, r1)
        C2 = commit(value, r2)

        # The commitments must be different — otherwise the scheme is not hiding.
        assert C1 != C2

        # But both should still be valid points on the curve.
        assert C1.is_on_curve()
        assert C2.is_on_curve()

    def test_commitment_with_zero_blinding_is_still_valid_but_not_hiding(self):
        # Using a zero blinding factor is technically valid but provides no
        # hiding — anyone could compute v*G and compare. This is just a sanity
        # check that the code handles the edge case.
        C = commit(42, 0)
        assert C.is_on_curve()
        # C == 42*G in this case, which is deterministic and not hiding at all.
        assert C == 42 * Point.generator()


class TestCommitmentVerification:
    """Tests for the verify function and the binding property."""

    def test_verify_succeeds_with_correct_opening(self):
        # If you reveal the exact (value, blinding_factor) used to create a
        # commitment, verification must succeed.
        v = 999
        r = 123456789

        C = commit(v, r)
        assert verify(C, v, r) is True

    def test_verify_fails_with_wrong_value(self):
        """
        Verify that you cannot open a commitment to a different value.

        This is the BINDING property in action. Once you have published a
        commitment C = v*G + r*H, finding a different value v' and some r'
        such that C = v'*G + r'*H is computationally infeasible — it would
        require solving the Elliptic Curve Discrete Logarithm Problem.

        Suppose an adversary wants to cheat: they committed to v=100 but now
        want to pretend they committed to v'=50. They would need to find r'
        such that:

            100*G + r*H = 50*G + r'*H
            50*G = (r' - r)*H
            (r' - r) = 50 * (discrete log of G with respect to H)

        Since nobody knows the discrete log of G with respect to H (or vice versa),
        this is believed to be computationally impossible.

        This test demonstrates that a wrong value causes verification to fail.
        """
        original_value = 100
        original_blinding = 777777777

        C = commit(original_value, original_blinding)

        # Attempt to verify with a different value but the original blinding.
        # This should fail because the commitment was not made to this value.
        wrong_value = 200
        assert verify(C, wrong_value, original_blinding) is False

        # Also try a different blinding with the correct value — also fails.
        wrong_blinding = 888888888
        assert verify(C, original_value, wrong_blinding) is False

    def test_verify_fails_with_completely_wrong_opening(self):
        # A completely fabricated opening should obviously fail.
        C = commit(123, 456)
        assert verify(C, 999, 999) is False


class TestHomomorphicAddition:
    """Tests for the additive homomorphic property of Pedersen commitments."""

    def test_commitment_addition_equals_commitment_of_sum(self):
        """
        Verify the homomorphic property:

            commit(v1, r1) + commit(v2, r2) == commit(v1 + v2, r1 + r2)

        This is the defining algebraic property of Pedersen commitments and is
        essential for applications like confidential transactions.

        The mathematical explanation:
        ----------------------------
        A Pedersen commitment is a linear combination of two generator points:

            C1 = v1*G + r1*H
            C2 = v2*G + r2*H

        Adding these points (which is well-defined on an elliptic curve group):

            C1 + C2 = (v1*G + r1*H) + (v2*G + r2*H)
                    = (v1 + v2)*G + (r1 + r2)*H
                    = commit(v1 + v2, r1 + r2)

        This follows from:
        - The associativity and commutativity of point addition
        - The distributivity of scalar multiplication over point addition:
          (a + b)*P = a*P + b*P

        Why this matters in practice:
        ---------------------------
        Imagine a confidential transaction with inputs I1, I2 and outputs O1, O2.
        You want to prove that inputs equal outputs without revealing amounts.
        If you publish commitments to each amount, you can add them:

            C_inputs  = commit(I1, r1) + commit(I2, r2)
            C_outputs = commit(O1, s1) + commit(O2, s2)

        If the sums match and the blinding factors are managed correctly, you
        can prove balance (I1 + I2 = O1 + O2) in the commitment space without
        ever revealing the individual values.
        """
        # Choose two values and their blinding factors.
        v1 = 100
        r1 = 11111111111111111111

        v2 = 250
        r2 = 22222222222222222222

        # Create individual commitments.
        C1 = commit(v1, r1)
        C2 = commit(v2, r2)

        # Add the commitments together using the homomorphic add function.
        C_sum = add_commitments(C1, C2)

        # Compute what the commitment to the sum should be directly.
        C_expected = commit(v1 + v2, r1 + r2)

        # By the homomorphic property, these must be equal.
        assert C_sum == C_expected

        # The sum commitment should also be a valid curve point.
        assert C_sum.is_on_curve()

    def test_homomorphic_addition_with_negative_values(self):
        # The homomorphic property also works with modular arithmetic.
        # Since we work modulo N, "negative" values wrap around.
        # This is a quick sanity check that the modular reduction doesn't break things.
        v1 = 50
        r1 = 100

        v2 = N - 30  # This is -30 mod N, a "negative" value in modular terms.
        r2 = 200

        C1 = commit(v1, r1)
        C2 = commit(v2, r2)

        C_sum = add_commitments(C1, C2)

        # The expected value is (50 + (N - 30)) mod N = 20.
        expected_value = (v1 + v2) % N
        expected_r = (r1 + r2) % N
        C_expected = commit(expected_value, expected_r)

        assert C_sum == C_expected

    def test_adding_commitments_preserves_individual_validity(self):
        # Adding two valid commitments should produce another valid commitment.
        C1 = commit(10, 20)
        C2 = commit(30, 40)

        C_sum = add_commitments(C1, C2)

        assert C_sum.is_on_curve()


class TestGeneratorIndependence:
    """Tests related to the independence of G and H."""

    def test_h_is_a_valid_point_on_curve(self):
        # H must be a valid point on secp256k1 (this is verified during derivation).
        assert H.is_on_curve()
        assert not H.is_infinity

    def test_h_differs_from_g(self):
        # H must not equal G — otherwise the Pedersen scheme would collapse to
        # a single-generator scheme which has different security properties.
        G = Point.generator()
        assert H != G

    def test_h_is_not_a_known_multiple_of_g(self):
        """
        Verify that H is not an obvious small multiple of G.

        While we cannot prove computationally that nobody knows the discrete
        log of H with respect to G (that would require solving ECDLP), we can
        at least check that H is not a trivially small multiple like 1*G, 2*G,
        etc. Our derivation via hashing makes this astronomically unlikely.
        """
        G = Point.generator()

        # Check H is not any of the first 100 multiples of G.
        # This is a sanity check; the hashing derivation already ensures this.
        for i in range(1, 101):
            assert H != i * G
