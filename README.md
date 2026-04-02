# crypto-primitives-lab

A Python library implementing cryptographic primitives used in privacy coins
(Monero, Zcash) from scratch. Built for learning — each module corresponds
to one layer of a real privacy-preserving transaction system.

## Structure

- `primitives/` — Core cryptographic modules
- `tests/` — pytest test suite

## Modules (planned)

- `field_math.py` — Modular arithmetic helpers (included)
- `elliptic_curve.py` — Elliptic curve point operations (TODO)
- `pedersen.py` — Pedersen commitments (TODO)
- `merkle.py` — Merkle tree and inclusion proofs (TODO)
- `ring_signature.py` — Ring signature scheme (TODO)
- `stealth_address.py` — ECDH-based one-time addresses (TODO)

## Running tests
```bash
pip install -r requirements.txt
pytest tests/ -v
```
```

**`requirements.txt`**
```
pytest>=7.0
hashlib
```

Actually hashlib is stdlib. Keep it simple:
```
pytest>=7.0
