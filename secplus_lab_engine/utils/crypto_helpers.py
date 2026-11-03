"""
Cryptographic helpers used across the labs.

Security+ SY0-701 mapping
-------------------------
* 1.4  Cryptographic solutions: hashing, salting, HMAC, key stretching.
* 4.9  Data sources for investigations: log integrity / chain of custody.

Everything here uses only the Python standard library (``hashlib``, ``hmac``,
``secrets``) so the engine runs fully offline.

Key ideas
---------
* A **hash** (SHA-256) proves integrity: any change to the input changes the
  digest. It does NOT prove *who* produced the data.
* A **salt** is random, non-secret data mixed into the hash so identical inputs
  produce different digests (defeats rainbow tables / precomputation).
* An **HMAC** mixes in a *secret key*. Only a key holder can produce a valid
  tag, so it proves integrity **and** authenticity.
* A **hash chain** links each record's digest to the previous one. Deleting,
  inserting or editing any record breaks every link after it, which is how
  tamper-evident (append-only) audit logs work.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from pathlib import Path
from typing import Any, Iterable

GENESIS_HASH = "0" * 64  # previous-hash value for the first link in a chain


# --------------------------------------------------------------------------- #
# Basic hashing
# --------------------------------------------------------------------------- #
def _to_bytes(data: str | bytes) -> bytes:
    return data if isinstance(data, bytes) else data.encode("utf-8")


def sha256_hex(data: str | bytes) -> str:
    """Return the hex SHA-256 digest of ``data``."""
    return hashlib.sha256(_to_bytes(data)).hexdigest()


def generate_salt(n_bytes: int = 16) -> str:
    """Return a cryptographically random salt as hex (default 128 bits)."""
    return secrets.token_hex(n_bytes)


def salted_sha256(data: str | bytes, salt: str) -> str:
    """Hash ``salt || data``. Same data + different salt => different digest."""
    return sha256_hex(_to_bytes(salt) + _to_bytes(data))


def stretch_password(password: str, salt: str, iterations: int = 100_000) -> str:
    """PBKDF2-HMAC-SHA256 key stretching (how passwords *should* be stored)."""
    dk = hashlib.pbkdf2_hmac("sha256", _to_bytes(password), _to_bytes(salt), iterations)
    return dk.hex()


def file_sha256(path: str | Path, chunk_size: int = 65536) -> str:
    """Stream a file from disk and return its SHA-256 digest."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    """Compare digests without leaking timing information."""
    return hmac.compare_digest(_to_bytes(a), _to_bytes(b))


# --------------------------------------------------------------------------- #
# HMAC
# --------------------------------------------------------------------------- #
def hmac_sign(key: str | bytes, data: str | bytes) -> str:
    """Return a hex HMAC-SHA256 tag for ``data`` under ``key``."""
    return hmac.new(_to_bytes(key), _to_bytes(data), hashlib.sha256).hexdigest()


def hmac_verify(key: str | bytes, data: str | bytes, tag: str) -> bool:
    """Verify an HMAC tag in constant time."""
    return constant_time_equals(hmac_sign(key, data), tag)


# --------------------------------------------------------------------------- #
# Canonical serialisation + hash chains
# --------------------------------------------------------------------------- #
def canonical_json(obj: Any) -> str:
    """Deterministic JSON (sorted keys, no whitespace) so hashes are stable."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def build_hash_chain(records: Iterable[Any], salt: str) -> list[str]:
    """
    Build a salted hash chain over ``records``.

    ``link[i] = SHA256(salt || link[i-1] || canonical_json(record[i]))``
    """
    chain: list[str] = []
    prev = GENESIS_HASH
    for rec in records:
        prev = salted_sha256(prev + canonical_json(rec), salt)
        chain.append(prev)
    return chain


def verify_hash_chain(records: list[Any], chain: list[str], salt: str) -> dict:
    """
    Recompute the chain and compare it to a trusted manifest.

    Returns a dict with ``valid`` (bool), ``first_broken_index`` (int | None),
    and ``length_delta`` (records added (+) or removed (-) vs the manifest).
    """
    recomputed = build_hash_chain(records, salt)
    first_broken = None
    for i, (got, expected) in enumerate(zip(recomputed, chain)):
        if not constant_time_equals(got, expected):
            first_broken = i
            break
    length_delta = len(records) - len(chain)
    if first_broken is None and length_delta != 0:
        first_broken = min(len(records), len(chain))
    return {
        "valid": first_broken is None,
        "first_broken_index": first_broken,
        "length_delta": length_delta,
    }
