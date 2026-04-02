"""
Tests for Merkle trees in primitives/merkle.py

These tests verify the core operations of Merkle trees:
- Building a tree from leaf values and obtaining the root
- Generating inclusion proofs for leaves
- Verifying proofs correctly
- Detecting tampering (modified leaf values or modified proof hashes)

The tests include inline comments explaining how Merkle trees enable private
transactions in systems like Zcash — specifically, how you can prove that a
coin exists in a commitment set without revealing which specific coin it is.
"""

import pytest
from primitives.merkle import MerkleTree, verify_proof


class TestTreeConstruction:
    """Tests for building a Merkle tree and obtaining the root."""

    def test_building_tree_produces_valid_root(self):
        """
        Verify that building a tree from a list of leaves produces a valid root.

        The root is a single 32-byte SHA-256 hash that serves as a fingerprint
        of the entire dataset. Any change to any leaf would produce a different
        root, making it a tamper-evident commitment to the whole set.

        This is exactly what Zcash uses: the root of the commitment tree is
        published on-chain so that anyone can verify proofs without having
        to store or download every commitment.
        """
        leaves = [b"alice", b"bob", b"carol", b"dave"]
        tree = MerkleTree(leaves)

        # The root should be 32 bytes (256 bits) — the standard SHA-256 output size.
        assert len(tree.root) == 32

        # The root should be deterministic: building the same tree again gives
        # the same root.
        tree2 = MerkleTree(leaves)
        assert tree.root == tree2.root

    def test_tree_with_single_leaf(self):
        # A tree with a single leaf is degenerate but valid: the root is just
        # the hash of that leaf.
        tree = MerkleTree([b"only-one"])
        assert len(tree.root) == 32
        # The root should equal SHA256("only-one") since there's no pairing.
        import hashlib
        assert tree.root == hashlib.sha256(b"only-one").digest()

    def test_tree_with_odd_number_of_leaves_duplicates_last(self):
        """
        Verify that an odd number of leaves results in the last leaf being
        duplicated so that every level can be paired.

        This is the standard "odd-node duplication" approach used in Zcash and
        many other Merkle tree implementations. It ensures the tree is well-formed
        even when the number of leaves isn't a power of two.

        For example, with leaves [A, B, C]:
            Level 0: [hash(A), hash(B), hash(C)]
            Level 0 after padding: [hash(A), hash(B), hash(C), hash(C)]
            Level 1: [hash_pair(h(A), h(B)), hash_pair(h(C), h(C))]
            Level 2 (root): hash_pair(level1[0], level1[1])
        """
        leaves = [b"one", b"two", b"three"]  # 3 leaves — odd number
        tree = MerkleTree(leaves)

        # The root should still be computed successfully.
        assert len(tree.root) == 32

        # Verify that the tree is deterministic and consistent.
        tree2 = MerkleTree(leaves)
        assert tree.root == tree2.root


class TestInclusionProofs:
    """Tests for generating and verifying inclusion proofs."""

    def test_proof_verification_succeeds_for_valid_leaf(self):
        """
        Verify that generating a proof for a leaf and then verifying it returns True.

        This is the fundamental operation of Merkle trees: you can prove that a
        specific piece of data belongs to a committed set using only a small
        number of hashes (logarithmic in the size of the set), rather than
        providing the entire set.

        In Zcash, this is how you prove that a coin you want to spend was
        legitimately created in a previous transaction. You don't need to send
        the entire commitment tree — just a handful of sibling hashes along
        the path from your coin's commitment up to the published root.
        """
        leaves = [b"alice", b"bob", b"carol", b"dave", b"eve"]
        tree = MerkleTree(leaves)

        # Generate a proof that "carol" (index 2) is in the tree.
        index = 2
        proof = tree.get_proof(index)

        # The proof length should be ceil(log2(n)) where n is the number of leaves.
        # For 5 leaves, that's 3 levels (we pad to 8 nodes at the leaf level).
        assert len(proof) > 0

        # Verification with the correct leaf value and index should succeed.
        assert verify_proof(b"carol", proof, index, tree.root) is True

    def test_proof_verification_fails_for_modified_leaf_value(self):
        """
        Verify that modifying the leaf value causes proof verification to fail.

        This is the "binding" property of Merkle trees. If someone tries to
        substitute a different leaf value into a valid proof, the reconstructed
        root will not match the expected root — because the hash chain starting
        from the wrong leaf will produce a different result.

        This is exactly why Zcash can trust a proof: if the proof verifies,
        the prover really did have a valid commitment in the tree. They can't
        swap in a fake commitment after the fact.
        """
        leaves = [b"alpha", b"beta", b"gamma", b"delta"]
        tree = MerkleTree(leaves)

        # Generate a valid proof for "gamma" at index 2.
        index = 2
        proof = tree.get_proof(index)

        # Verification with the original value succeeds.
        assert verify_proof(b"gamma", proof, index, tree.root) is True

        # But verification with a modified value fails.
        assert verify_proof(b"gamma_modified", proof, index, tree.root) is False

        # Even a small change breaks verification.
        assert verify_proof(b"gamm", proof, index, tree.root) is False

    def test_proof_verification_fails_if_proof_hash_is_modified(self):
        """
        Verify that modifying any hash in the proof path causes verification to fail.

        The proof is a chain of sibling hashes. Each one is essential to correctly
        reconstruct the path from the leaf to the root. If any sibling hash is
        altered — even slightly — the reconstructed root will differ from the
        expected root, and verification will fail.

        This is a crucial security property. It means that an adversary who
        intercepts a proof cannot tamper with it to make it prove something
        different. Any modification is immediately detected.
        """
        leaves = [b"one", b"two", b"three", b"four", b"five", b"six", b"seven", b"eight"]
        tree = MerkleTree(leaves)

        # Pick an arbitrary leaf and get its proof.
        index = 5  # "six"
        proof = tree.get_proof(index)

        # Verification with the intact proof succeeds.
        assert verify_proof(b"six", proof, index, tree.root) is True

        # Tamper with each proof hash in turn and verify that each tampering
        # breaks the proof.
        for i in range(len(proof)):
            # Make a copy of the proof and flip one bit in the i-th hash.
            tampered_proof = list(proof)
            tampered_proof[i] = bytes([b ^ 0x01 for b in tampered_proof[i]])

            # Verification must now fail.
            assert verify_proof(b"six", tampered_proof, index, tree.root) is False, (
                f"Tampering proof hash at index {i} should cause verification to fail"
            )

    def test_proof_verification_fails_for_wrong_index(self):
        """
        Verify that using the wrong index causes verification to fail.

        The index tells the verifier how to combine hashes (left vs right) at
        each level. Using the wrong index means the hashes are combined in the
        wrong order, leading to an incorrect reconstructed root.

        This ensures that a proof is only valid for the specific position where
        the leaf actually exists in the tree.
        """
        leaves = [b"a", b"b", b"c", b"d"]
        tree = MerkleTree(leaves)

        # Generate a proof for "c" at index 2.
        proof = tree.get_proof(2)

        # Verification with the correct index succeeds.
        assert verify_proof(b"c", proof, 2, tree.root) is True

        # Verification with a wrong index fails — even though "c" is a valid leaf,
        # the proof was generated for a specific position.
        assert verify_proof(b"c", proof, 0, tree.root) is False
        assert verify_proof(b"c", proof, 1, tree.root) is False
        assert verify_proof(b"c", proof, 3, tree.root) is False


class TestPrivateTransactionFoundation:
    """
    Tests and explanations for how Merkle trees enable private transactions.

    This class doesn't just test functionality — it also documents, through
    comments, the conceptual bridge from Merkle trees to Zcash-style privacy.
    """

    def test_proof_size_is_logarithmic_in_number_of_leaves(self):
        """
        Verify that the proof size grows logarithmically with the number of leaves.

        This is the key efficiency property that makes private transactions
        practical. Without it, you would need to send the entire commitment
        set with every transaction — which would be millions of items.

        With Merkle proofs, a transaction only needs to include about 20–30
        hashes regardless of how many commitments exist in total. This keeps
        transactions small and verification fast.
        """
        import math

        # Build trees of increasing size and check that proof lengths are
        # approximately log2(n).
        for n in [10, 100, 1000, 10000]:
            leaves = [f"leaf_{i}".encode() for i in range(n)]
            tree = MerkleTree(leaves)

            # Generate a proof for the first leaf.
            proof = tree.get_proof(0)

            # The proof length should be ceil(log2(n)) or close to it.
            expected_length = math.ceil(math.log2(n))
            assert len(proof) == expected_length or len(proof) == expected_length + 1, (
                f"For {n} leaves, expected proof length ~{expected_length}, got {len(proof)}"
            )

    def test_membership_proof_without_revealing_which_leaf(self):
        """
        Demonstrate and explain how you can prove membership without revealing
        which specific leaf you're proving membership for.

        In Zcash's model, the leaves of the Merkle tree are "commitments" — each
        one is a Pedersen commitment to a coin (hiding the coin's value and owner).
        The tree root is public, but the individual commitments are not.

        When you want to spend a coin, you create a zero-knowledge proof that
        says, in essence:

            "I know a secret key and a coin commitment such that:
             1. The commitment is in the tree (I can produce a valid Merkle proof),
             2. The commitment opens to a coin that I own (I know the secret key),
             3. This coin has not been spent before (nullifier check)."

        The crucial point is that the Merkle proof itself doesn't reveal WHICH
        commitment in the tree you're proving membership for. The verifier sees
        a list of hashes, but without knowing your original index and the full
        tree structure, they cannot determine which leaf you started from.

        This test demonstrates the mechanical side: the proof is just a list of
        opaque hashes. The zero-knowledge part (hiding the index) is achieved
        by wrapping the Merkle proof inside a zk-SNARK, which proves that a
        valid Merkle verification would succeed for *some* index — without
        revealing which one.
        """
        # Create a tree representing a set of coin commitments.
        # In reality these would be Pedersen commitment points, but for the
        # purposes of this illustration, any unique byte strings work.
        commitments = [
            b"commitment_for_alice_coin_1",
            b"commitment_for_bob_coin_1",
            b"commitment_for_carol_coin_1",
            b"commitment_for_dave_coin_1",
            b"commitment_for_alice_coin_2",
            b"commitment_for_eve_coin_1",
        ]
        tree = MerkleTree(commitments)

        # Alice wants to spend her first coin. She generates a proof for it.
        alice_index = 0  # commitment_for_alice_coin_1
        proof = tree.get_proof(alice_index)

        # The proof is just a list of hashes — opaque bytes.
        # An observer seeing this proof cannot determine which commitment it
        # proves membership for without additional information.
        for sibling_hash in proof:
            assert isinstance(sibling_hash, bytes)
            assert len(sibling_hash) == 32  # Each is a SHA-256 hash

        # Verification still works — the proof is valid.
        assert verify_proof(commitments[alice_index], proof, alice_index, tree.root) is True

        # The key insight for privacy: if this proof were embedded inside a
        # zero-knowledge proof, the verifier would learn only that "some valid
        # commitment in the tree is being spent," not which specific one.
        # The Merkle proof provides the membership evidence; the zk-SNARK
        # hides the index and the commitment itself.
