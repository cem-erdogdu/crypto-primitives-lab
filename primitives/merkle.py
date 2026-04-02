r"""
Merkle trees for efficient and secure membership proofs.

A Merkle tree is a binary tree of hashes. It lets you prove that a particular
piece of data is part of a larger set without revealing or transmitting the
entire set. This is the foundation of many blockchain protocols, including
Bitcoin's block headers and Zcash's private transaction system.

The core idea:
--------------
Start with a list of data items (the "leaves"). Hash each one to get the leaf
hashes. Then, pair up adjacent hashes and hash each pair together to form the
next level. Repeat until only one hash remains — the "root." The root serves as
a compact fingerprint of the entire dataset.

Why this matters:
-----------------
- **Compact commitment**: A dataset of millions of items can be summarized by a
  single 32-byte hash (the root). Anyone who knows the root can verify claims
  about the data without downloading everything.
- **Efficient proofs**: To prove that a particular leaf belongs to the tree, you
  only need to provide log₂(n) sibling hashes — one per level of the tree. For a
  tree with a million leaves, that's about 20 hashes, not a million.
- **Tamper detection**: If any leaf changes, the root changes. This means a
  verifier can detect unauthorized modifications.

How the tree is built:
----------------------
Given leaves [L0, L1, L2, L3, L4], we build the tree as follows:

        Level 2 (root):          R
                                / \
        Level 1:              H01  H234
                             / \    / \
        Level 0 (leaves):   L0 L1  L2 L3 L4*
                                          ^
                                          |
                              Duplicated to make a pair

At each level, if there's an odd number of nodes, we duplicate the last one
so that every node has a sibling to hash with. This is sometimes called a
"balanced" or "complete" tree construction and is the standard approach used
in Zcash's Sprout and Sapling protocols.

Each internal node is computed as:

    parent = SHA256(left_child_bytes || right_child_bytes)

The concatenation order matters. Here we always put the left child first.

Why Zcash uses Merkle trees:
----------------------------
Zcash is a cryptocurrency focused on privacy. Unlike Bitcoin, where every
transaction reveals the sender, receiver, and amount, Zcash transactions can
be fully shielded — nobody can see who sent money to whom or how much.

A central challenge in private cryptocurrencies is the "double spend" problem.
In Bitcoin, you prevent double spending by checking that a coin hasn't already
been spent in a public ledger. But if transactions are private, how do you know
a coin is valid without revealing which coin it is?

Zcash solves this with a Merkle tree of "commitments." Every time a shielded
coin (called a "note") is created, its commitment is added to a global Merkle
tree. The root of this tree is published on-chain. When you want to spend a
coin, you provide a cryptographic proof (a "zero-knowledge proof") that:

1. You know the secret key that corresponds to that coin.
2. The coin's commitment exists somewhere in the Merkle tree (i.e., it was
   created in a valid previous transaction).

The proof is constructed so that it reveals *nothing* about which commitment
you're proving membership for — only that *some* valid commitment exists and
you have the authority to spend it. This is called a "membership proof" or
"set membership proof."

Without Merkle trees, you would have to either:
- Reveal the exact commitment you're spending (breaking privacy), or
- Have every verifier download and store every commitment ever created (impractical).

With Merkle trees, the proof is tiny (logarithmic in the number of commitments),
and verification is fast.

This is the foundation for private transactions: you prove membership in the
commitment set without linking to a specific coin. The verifier learns only
that a valid, unspent coin is being spent — not which one.
"""

import hashlib
from typing import List, Tuple


def _sha256(data: bytes) -> bytes:
    """
    Hash arbitrary bytes with SHA-256.

    SHA-256 produces a fixed 32-byte (256-bit) output regardless of input size.
    It is collision-resistant: it is computationally infeasible to find two
    different inputs that produce the same output. This property is essential
    for Merkle trees — if collisions were easy to find, you could create a fake
    leaf that hashes to the same value as a real one, breaking the security of
    membership proofs.

    Args:
        data: The bytes to hash.

    Returns:
        A 32-byte SHA-256 digest.
    """
    return hashlib.sha256(data).digest()


def _hash_pair(left: bytes, right: bytes) -> bytes:
    """
    Hash two sibling nodes together to produce their parent node.

    The parent hash is computed as SHA256(left || right), where || denotes
    concatenation. The order matters: hash_pair(a, b) is not the same as
    hash_pair(b, a). This is why inclusion proofs must track whether each
    sibling was on the left or right side of its parent.

    Args:
        left: The left child's hash (32 bytes).
        right: The right child's hash (32 bytes).

    Returns:
        The parent node's hash (32 bytes).
    """
    return _sha256(left + right)


class MerkleTree:
    """
    A Merkle tree built from a list of leaf values.

    The tree is constructed bottom-up. Each leaf value is first hashed to
    produce a leaf node. Then, pairs of nodes are hashed together to form
    parent nodes, repeating until a single root hash remains.

    If a level has an odd number of nodes, the last node is duplicated so
    that every node has a partner to hash with. This ensures the tree is
    a complete binary tree (every level except possibly the last is full).

    Attributes:
        leaves: The list of leaf hashes (each is a 32-byte SHA-256 digest).
        root: The root hash of the tree, summarizing all the leaves.
    """

    def __init__(self, leaf_values: List[bytes]):
        """
        Build a Merkle tree from a list of raw leaf values.

        Each value in the input list is hashed with SHA-256 to produce a leaf
        node. The tree is then constructed level by level by pairing and hashing
        adjacent nodes until only the root remains.

        Args:
            leaf_values: A list of byte strings representing the data items.
                         Each item is hashed to produce one leaf node.

        Raises:
            ValueError: If the input list is empty.
        """
        if not leaf_values:
            raise ValueError("Cannot build a Merkle tree from an empty list")

        # -------------------------------------------------------
        # STEP 1: HASH EACH LEAF VALUE TO GET THE LEAF NODES
        # -------------------------------------------------------
        # The raw data items are not stored directly in the tree.
        # Instead, we store their hashes. This is important for two reasons:
        #   1. Hashes are fixed-size (32 bytes), making the tree structure uniform.
        #   2. The hash function acts as a commitment — you can't reverse it to
        #      recover the original data from a leaf hash alone.
        # -------------------------------------------------------
        self.leaves: List[bytes] = [_sha256(value) for value in leaf_values]

        # -------------------------------------------------------
        # STEP 2: BUILD THE TREE LEVEL BY LEVEL
        # -------------------------------------------------------
        # We keep track of the current level and repeatedly combine pairs of
        # nodes to form the next level up. The process continues until we have
        # exactly one node — the root.
        #
        # At each level, if there is an odd number of nodes, we duplicate the
        # last one. This is the standard approach used in Zcash and many other
        # Merkle tree implementations. It ensures that every node (except the
        # root) has a sibling to pair with.
        # -------------------------------------------------------
        level = self.leaves[:]

        while len(level) > 1:
            # If there's an odd number of nodes at this level, duplicate the last one.
            # For example, [A, B, C] becomes [A, B, C, C] so we can pair C with itself.
            if len(level) % 2 == 1:
                level.append(level[-1])

            # Combine adjacent pairs into parent nodes for the next level.
            next_level: List[bytes] = []
            for i in range(0, len(level), 2):
                left_child = level[i]
                right_child = level[i + 1]
                parent = _hash_pair(left_child, right_child)
                next_level.append(parent)

            level = next_level

        # After the loop, 'level' contains exactly one element: the root hash.
        self.root: bytes = level[0]

    @property
    def root_hex(self) -> str:
        """Return the root hash as a hexadecimal string for easy display."""
        return self.root.hex()

    def get_proof(self, index: int) -> List[bytes]:
        """
        Generate a Merkle inclusion proof for the leaf at the given index.

        An inclusion proof demonstrates that a particular leaf belongs to the tree
        without requiring the verifier to have the entire tree. The proof consists
        of the sibling hashes encountered on the path from the leaf up to the root.

        At each level of the tree, the leaf's ancestor has a sibling. We collect
        those siblings as we walk up the tree. The verifier can then reconstruct
        the root by repeatedly hashing the current node with its sibling, using
        the index to determine which side each sibling was on.

        Args:
            index: The zero-based index of the leaf to prove membership for.

        Returns:
            A list of sibling hashes, one for each level of the tree (from leaf
            level up to just below the root). The length of the proof is
            ceil(log₂(n)) where n is the number of leaves.

        Raises:
            IndexError: If the index is out of range for the leaf list.
        """
        if index < 0 or index >= len(self.leaves):
            raise IndexError(f"Leaf index {index} out of range (0..{len(self.leaves) - 1})")

        proof: List[bytes] = []
        current_index = index

        # -------------------------------------------------------
        # WALK UP THE TREE, COLLECTING SIBLING HASHES
        # -------------------------------------------------------
        # We start at the leaf level and work our way up. At each level:
        #   - If our current node is at an even index, its sibling is to the right.
        #   - If our current node is at an odd index, its sibling is to the left.
        #
        # The sibling hash is appended to the proof list. The verifier will use
        # the original index (and its bit pattern) to know how to combine hashes.
        # -------------------------------------------------------
        level = self.leaves[:]

        while len(level) > 1:
            # Handle odd-length levels by duplicating the last node (same as tree construction).
            if len(level) % 2 == 1:
                level.append(level[-1])

            # Determine the sibling index based on whether we're on the left or right.
            if current_index % 2 == 0:
                # Current node is left child; sibling is on the right.
                sibling_index = current_index + 1
            else:
                # Current node is right child; sibling is on the left.
                sibling_index = current_index - 1

            proof.append(level[sibling_index])

            # Move to the parent level: combine pairs and update our index.
            next_level: List[bytes] = []
            for i in range(0, len(level), 2):
                parent = _hash_pair(level[i], level[i + 1])
                next_level.append(parent)

            # The new index at the parent level is half the current index.
            current_index = current_index // 2
            level = next_level

        return proof


def verify_proof(leaf_value: bytes, proof: List[bytes], index: int, root: bytes) -> bool:
    """
    Verify that a leaf value is included in a Merkle tree with the given root.

    This function reconstructs the path from the leaf up to the root using the
    provided proof (the list of sibling hashes). If the reconstructed root
    matches the expected root, the proof is valid — the leaf is indeed part of
    the tree at the claimed index.

    Args:
        leaf_value: The raw leaf data (not its hash — we hash it here).
        proof: The list of sibling hashes from get_proof().
        index: The claimed index of the leaf in the original leaf list.
        root: The expected root hash of the tree.

    Returns:
        True if the proof is valid (the leaf belongs to the tree at the given
        index), False otherwise.

    How verification works:
    -----------------------
    We start with the hash of the leaf value. Then, for each sibling hash in
    the proof, we combine it with our current hash — placing them on the correct
    left/right sides based on the bits of the index. After processing all
    siblings, we should arrive at the root hash if the proof is valid.

    The index acts as a "path descriptor": reading its binary representation
    from least significant bit to most significant bit tells us whether we were
    the left or right child at each level of the tree.
    """
    # -------------------------------------------------------
    # STEP 1: HASH THE LEAF VALUE TO GET THE STARTING NODE
    # -------------------------------------------------------
    # The proof was generated from leaf hashes, not raw values, so we must
    # hash the provided value first to match what the tree contains.
    current_hash = _sha256(leaf_value)

    # -------------------------------------------------------
    # STEP 2: REPLAY THE PATH FROM LEAF TO ROOT
    # -------------------------------------------------------
    # We walk up the tree by repeatedly hashing with each sibling from the proof.
    # The index tells us whether the sibling was on the left or right at each step.
    #
    # We consume bits of the index from LSB to MSB. A 0 bit means we are the
    # left child (sibling goes on the right); a 1 bit means we are the right
    # child (sibling goes on the left).
    # -------------------------------------------------------
    current_index = index

    for sibling in proof:
        if current_index % 2 == 0:
            # We are the left child; sibling is on the right.
            current_hash = _hash_pair(current_hash, sibling)
        else:
            # We are the right child; sibling is on the left.
            current_hash = _hash_pair(sibling, current_hash)

        # Move up one level in the tree.
        current_index = current_index // 2

    # -------------------------------------------------------
    # STEP 3: CHECK WHETHER WE ARRIVED AT THE EXPECTED ROOT
    # -------------------------------------------------------
    # If the reconstructed hash matches the provided root, the proof is valid.
    return current_hash == root
