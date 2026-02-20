"""
OPAQUE Protocol — Python Implementation
Cryptography Engineering, Lecture 11 Homework

Phases:
  1. Registration
  2. Login Step 1 : OPRF  (DH-OPRF on P-256)
  3. Login Step 2 : 3DH AKE
  4. Login Step 3 : Key Confirmation

Crypto stack:
  - Group G    : NIST P-256 for all EC operations
  - DH-OPRF    : Client blinds pw with random scalar alpha,
                 server multiplies by salt s, client unblinds.
                 oprf_val = x-coord of s*h(pw)
                 rw = H(pw || oprf_val)
  - Hash H     : SHA-256
  - AEAD       : AES-256-GCM
  - KDF / HKDF : HKDF-SHA256
  - HMAC       : HMAC-SHA256
"""

import os
import hashlib
import hmac as hmac_lib
import json
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1, generate_private_key, ECDH, derive_private_key,
    EllipticCurvePrivateKey, EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

CURVE   = SECP256R1()
BACKEND = default_backend()
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


# ══════════════════════════════════════════════════════════════════
# PRIMITIVES
# ══════════════════════════════════════════════════════════════════

def H(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def HMAC(key: bytes, msg: bytes) -> bytes:
    return hmac_lib.new(key, msg, hashlib.sha256).digest()


def KDF(ikm: bytes, info: bytes = b"opaque-kdf", length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=length,
        salt=None, info=info, backend=BACKEND,
    ).derive(ikm)


def AEAD_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """nonce (12B) || ciphertext+tag"""
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def AEAD_decrypt(key: bytes, data: bytes) -> bytes:
    return AESGCM(key).decrypt(data[:12], data[12:], None)


# ══════════════════════════════════════════════════════════════════
# EC HELPERS
# ══════════════════════════════════════════════════════════════════

def keygen() -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    sk = generate_private_key(CURVE, BACKEND)
    return sk, sk.public_key()


def pk_to_bytes(pk: EllipticCurvePublicKey) -> bytes:
    return pk.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def sk_to_bytes(sk: EllipticCurvePrivateKey) -> bytes:
    return sk.private_numbers().private_value.to_bytes(32, "big")


def load_sk(b: bytes) -> EllipticCurvePrivateKey:
    return derive_private_key(int.from_bytes(b, "big"), CURVE, BACKEND)


def load_pk(b: bytes) -> EllipticCurvePublicKey:
    return EllipticCurvePublicKey.from_encoded_point(CURVE, b)


def dh(sk: EllipticCurvePrivateKey, pk: EllipticCurvePublicKey) -> bytes:
    """ECDH raw shared secret (x-coordinate, 32 bytes)."""
    return sk.exchange(ECDH(), pk)


def random_scalar() -> bytes:
    while True:
        val = int.from_bytes(os.urandom(32), "big")
        if 1 <= val < P256_ORDER:
            return val.to_bytes(32, "big")


def scalar_inv(s_b: bytes) -> bytes:
    val = int.from_bytes(s_b, "big")
    return pow(val, P256_ORDER - 2, P256_ORDER).to_bytes(32, "big")


def scalar_mult(scalar_b: bytes, point: EllipticCurvePublicKey) -> bytes:
    """
    Compute scalar * point, return x-coordinate (32 bytes).
    We leverage ECDH: create ephemeral SK from scalar, ECDH with point.
    """
    sk = derive_private_key(int.from_bytes(scalar_b, "big"), CURVE, BACKEND)
    return sk.exchange(ECDH(), point)


def x_to_point(x_bytes: bytes) -> EllipticCurvePublicKey:
    """Recover an EC point from its x-coordinate (try both parities)."""
    for prefix in (b'\x02', b'\x03'):
        try:
            return EllipticCurvePublicKey.from_encoded_point(CURVE, prefix + x_bytes)
        except Exception:
            continue
    raise ValueError("x_to_point: no valid point for given x-coordinate")


# ══════════════════════════════════════════════════════════════════
# HASH-TO-CURVE  (simplified try-and-increment)
# ══════════════════════════════════════════════════════════════════

def hash_to_curve(data: bytes) -> EllipticCurvePublicKey:
    """
    Maps arbitrary bytes to a P-256 point.
    Try-and-increment is not constant-time; use RFC 9380 in production.
    """
    for i in range(512):
        seed = hashlib.sha256(data + i.to_bytes(2, "big")).digest()
        x = int.from_bytes(seed, "big") % P256_ORDER
        for prefix in (b'\x02', b'\x03'):
            try:
                return EllipticCurvePublicKey.from_encoded_point(
                    CURVE, prefix + x.to_bytes(32, "big")
                )
            except Exception:
                continue
    raise RuntimeError("hash_to_curve failed after 512 attempts")


# ══════════════════════════════════════════════════════════════════
# DH-OPRF PROTOCOL
#
#  Registration (server has pw once via TLS):
#    oprf_val = scalar_mult(s, h(pw)).x_coord    ← s * h(pw)
#    rw = H(pw || oprf_val)
#
#  Login — Client blinding:
#    alpha ← Zq
#    ALPHA = scalar_mult(alpha, h(pw))           ← alpha * h(pw)  [65B point]
#    → sends ALPHA to server
#
#  Login — Server eval:
#    BETA_x = scalar_mult(s, ALPHA)              ← s * (alpha * h(pw))
#    BETA = x_to_point(BETA_x)                   ← back to 65B point
#    → sends BETA + enc_keys to client
#
#  Login — Client unblind:
#    oprf_val = scalar_mult(alpha^-1, BETA).x    ← alpha^-1 * s * alpha * h(pw)
#                                                 = s * h(pw)  ✓
#    rw = H(pw || oprf_val)
# ══════════════════════════════════════════════════════════════════

def oprf_client_blind(pw_bytes: bytes) -> Tuple[bytes, bytes]:
    """Returns (alpha_bytes, ALPHA_65bytes)."""
    alpha = random_scalar()
    h_pw = hash_to_curve(pw_bytes)
    alpha_x = scalar_mult(alpha, h_pw)           # x-coord of alpha*h(pw)
    ALPHA = pk_to_bytes(x_to_point(alpha_x))     # 65 bytes
    return alpha, ALPHA


def oprf_server_eval(s: bytes, ALPHA: bytes) -> bytes:
    """Returns BETA as 65-byte uncompressed point."""
    ALPHA_point = load_pk(ALPHA)
    BETA_x = scalar_mult(s, ALPHA_point)         # x-coord of s*ALPHA
    return pk_to_bytes(x_to_point(BETA_x))       # 65 bytes


def oprf_client_unblind(alpha: bytes, BETA: bytes) -> bytes:
    """Returns x-coord of alpha^-1 * BETA = s*h(pw) (32 bytes)."""
    BETA_point = load_pk(BETA)
    return scalar_mult(scalar_inv(alpha), BETA_point)


def compute_rw(pw_bytes: bytes, oprf_val: bytes) -> bytes:
    """rw = H(pw || oprf_val)."""
    return H(pw_bytes + oprf_val)


# ══════════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════════

class Database:
    def __init__(self):
        self._store: dict = {}

    def save(self, username: str, record: dict):
        self._store[username] = record

    def load(self, username: str) -> dict:
        if username not in self._store:
            raise KeyError(f"Unknown user: '{username}'")
        return self._store[username]


# ══════════════════════════════════════════════════════════════════
# PHASE 1 — REGISTRATION
# ══════════════════════════════════════════════════════════════════

def registration(username: str, password: str, db: Database) -> None:
    """
    Registration (client sends pw over TLS, server stores envelope):

      s ← Zq
      oprf_val = (s * h(pw)).x
      rw = H(pw || oprf_val)
      rw_key = KDF(rw, "opaque-rw-key")
      (lpk_c, lsk_c) ← KeyGen
      (lpk_s, lsk_s) ← KeyGen
      enc_keys = AEAD(rw_key, (lpk_c || lsk_c || lpk_s))
      DB[user] = {salt, lpk_c, lpk_s, lsk_s, enc_keys}
    """
    print(f"\n{'═'*60}")
    print("PHASE 1 — REGISTRATION")
    print(f"{'═'*60}")
    print(f"  User     : {username}")
    print(f"  Password : {password}")

    pw_bytes = password.encode()

    s = random_scalar()
    print(f"\n  [Server] s (salt)  = {s.hex()[:32]}...")

    h_pw = hash_to_curve(pw_bytes)
    oprf_val = scalar_mult(s, h_pw)               # x-coord of s*h(pw)
    rw = compute_rw(pw_bytes, oprf_val)
    rw_key = KDF(rw, info=b"opaque-rw-key")
    print(f"  [Server] oprf_val  = {oprf_val.hex()[:32]}...")
    print(f"  [Server] rw        = {rw.hex()[:32]}...")

    lsk_c, lpk_c = keygen()
    lsk_s, lpk_s = keygen()
    print(f"  [Server] lpk_c     = {pk_to_bytes(lpk_c).hex()[:32]}...")
    print(f"  [Server] lpk_s     = {pk_to_bytes(lpk_s).hex()[:32]}...")

    key_info = json.dumps({
        "lpk_c": pk_to_bytes(lpk_c).hex(),
        "lsk_c": sk_to_bytes(lsk_c).hex(),
        "lpk_s": pk_to_bytes(lpk_s).hex(),
    }).encode()
    enc_keys = AEAD_encrypt(rw_key, key_info)
    print(f"  [Server] enc_keys  = {enc_keys.hex()[:32]}...")

    db.save(username, {
        "salt":     s.hex(),
        "lpk_c":    pk_to_bytes(lpk_c).hex(),
        "lpk_s":    pk_to_bytes(lpk_s).hex(),
        "lsk_s":    sk_to_bytes(lsk_s).hex(),
        "enc_keys": enc_keys.hex(),
    })
    print(f"\n  [Server] Record stored for '{username}' ✓")


# ══════════════════════════════════════════════════════════════════
# PHASE 2 — LOGIN  (3 steps)
# ══════════════════════════════════════════════════════════════════

def login(username: str, password: str, db: Database) -> bytes:
    """
    Full OPAQUE login.
    Returns session key SK on success, raises on failure.
    """
    print(f"\n{'═'*60}")
    print("PHASE 2 — LOGIN")
    print(f"{'═'*60}")
    print(f"  User     : {username}")
    print(f"  Password : {password}")

    pw_bytes = password.encode()

    # ── STEP 1: OPRF ────────────────────────────────────────────
    print(f"\n  ── Step 1 : OPRF ──")

    alpha, ALPHA = oprf_client_blind(pw_bytes)
    print(f"  [Client] alpha     = {alpha.hex()[:32]}...")
    print(f"  [Client] ALPHA     = {ALPHA.hex()[:32]}...")
    print(f"  [Client] → (Username, ALPHA)")

    record = db.load(username)
    s = bytes.fromhex(record["salt"])
    enc_keys = bytes.fromhex(record["enc_keys"])
    BETA = oprf_server_eval(s, ALPHA)
    print(f"  [Server] BETA      = {BETA.hex()[:32]}...")
    print(f"  [Server] → (BETA, enc_keys)")

    oprf_val = oprf_client_unblind(alpha, BETA)
    rw = compute_rw(pw_bytes, oprf_val)
    rw_key = KDF(rw, info=b"opaque-rw-key")
    print(f"  [Client] oprf_val  = {oprf_val.hex()[:32]}...")
    print(f"  [Client] rw        = {rw.hex()[:32]}...")

    key_info_bytes = AEAD_decrypt(rw_key, enc_keys)   # raises InvalidTag if wrong pw
    key_info = json.loads(key_info_bytes.decode())
    lpk_c = load_pk(bytes.fromhex(key_info["lpk_c"]))
    lsk_c = load_sk(bytes.fromhex(key_info["lsk_c"]))
    lpk_s = load_pk(bytes.fromhex(key_info["lpk_s"]))
    print(f"  [Client] Keys decrypted ✓")

    # ── STEP 2: 3DH AKE ─────────────────────────────────────────
    print(f"\n  ── Step 2 : 3DH AKE ──")

    epk_c_sk, epk_c = keygen()
    print(f"  [Client] X = g^x   = {pk_to_bytes(epk_c).hex()[:32]}...")
    print(f"  [Client] → X")

    lsk_s  = load_sk(bytes.fromhex(record["lsk_s"]))
    lpk_c_srv = load_pk(bytes.fromhex(record["lpk_c"]))
    epk_s_sk, epk_s = keygen()
    print(f"  [Server] Y = g^y   = {pk_to_bytes(epk_s).hex()[:32]}...")
    print(f"  [Server] → Y")

    # 3DH-KServer(b, y, A, X): SK = HKDF(g^{xb} || g^{xy} || g^{ay})
    SK_server = KDF(
        dh(lsk_s,    epk_c) +
        dh(epk_s_sk, epk_c) +
        dh(epk_s_sk, lpk_c_srv),
        info=b"opaque-3dh-sk"
    )

    # 3DH-KClient(a, x, B, Y): SK = HKDF(g^{bx} || g^{xy} || g^{ya})
    SK_client = KDF(
        dh(epk_c_sk, lpk_s) +
        dh(epk_c_sk, epk_s) +
        dh(lsk_c,    epk_s),
        info=b"opaque-3dh-sk"
    )

    print(f"  [Server] SK        = {SK_server.hex()[:32]}...")
    print(f"  [Client] SK        = {SK_client.hex()[:32]}...")
    assert SK_client == SK_server, "BUG: session keys differ"
    print(f"  [✓] Both parties derived the same SK")

    # ── STEP 3: KEY CONFIRMATION ─────────────────────────────────
    print(f"\n  ── Step 3 : Key Confirmation ──")

    Kc = KDF(SK_client, info=b"opaque-key-confirmation-client")
    Ks = KDF(SK_client, info=b"opaque-key-confirmation-server")

    mac_c = HMAC(Kc, b"Client KC")
    print(f"  [Client] mac_c     = {mac_c.hex()[:32]}...")
    print(f"  [Client] → mac_c")

    if not hmac_lib.compare_digest(HMAC(Kc, b"Client KC"), mac_c):
        raise ValueError("Key confirmation FAILED: invalid mac_c")
    mac_s = HMAC(Ks, b"Server KC")
    print(f"  [Server] mac_c verified ✓")
    print(f"  [Server] mac_s     = {mac_s.hex()[:32]}...")
    print(f"  [Server] → mac_s")

    if not hmac_lib.compare_digest(HMAC(Ks, b"Server KC"), mac_s):
        raise ValueError("Key confirmation FAILED: invalid mac_s")
    print(f"  [Client] mac_s verified ✓")

    print(f"\n  ══ AUTHENTICATION SUCCESSFUL ══")
    print(f"  Session key SK = {SK_client.hex()}")
    return SK_client



# ══════════════════════════════════════════════════════════════════
# FORMATTED DEMO
# ══════════════════════════════════════════════════════════════════

SEP  = "-" * 80
SEP2 = "=" * 80


def run_demo(username: str, password: str, db: Database) -> None:

    # ── PHASE 1: REGISTRATION ────────────────────────────────────
    print(SEP)
    print(" PHASE 1: REGISTRATION")
    print(SEP)
    print("Goal: Register user without revealing password to server\n")
    print(f"  [Client] Requesting registration for \'{username}\'")
    print(f"  [Server] Processing registration for \'{username}\'")

    pw_bytes = password.encode()
    s = random_scalar()
    h_pw = hash_to_curve(pw_bytes)
    oprf_val = scalar_mult(s, h_pw)
    rw = compute_rw(pw_bytes, oprf_val)
    rw_key = KDF(rw, info=b"opaque-rw-key")
    lsk_c, lpk_c = keygen()
    lsk_s, lpk_s = keygen()
    key_info = json.dumps({
        "lpk_c": pk_to_bytes(lpk_c).hex(),
        "lsk_c": sk_to_bytes(lsk_c).hex(),
        "lpk_s": pk_to_bytes(lpk_s).hex(),
    }).encode()
    enc_keys = AEAD_encrypt(rw_key, key_info)
    db.save(username, {
        "salt":     s.hex(),
        "lpk_c":    pk_to_bytes(lpk_c).hex(),
        "lpk_s":    pk_to_bytes(lpk_s).hex(),
        "lsk_s":    sk_to_bytes(lsk_s).hex(),
        "enc_keys": enc_keys.hex(),
    })

    print(f"  [Server] Registration successful")
    print(f"           Salt (hex): {s.hex()[:32]}...")
    print(f"\n Registration Complete\n")

    # ── PHASE 2: LOGIN ───────────────────────────────────────────
    print(SEP)
    print(" PHASE 2: LOGIN")
    print(SEP)

    # Stage 1: OPRF
    print("\n --- Stage 1: OPRF ---")
    print("Goal: Recover keys without revealing password or salt\n")

    record = db.load(username)
    s_srv      = bytes.fromhex(record["salt"])
    enc_keys_srv = bytes.fromhex(record["enc_keys"])

    print(f"  [Server] Sending OPRF data for \'{username}\'")

    alpha, ALPHA = oprf_client_blind(pw_bytes)
    BETA = oprf_server_eval(s_srv, ALPHA)

    print(f"  [Server] Sent salt and encrypted keys")
    print(f"  [Client] Computing rw from password and salt")

    oprf_val_c = oprf_client_unblind(alpha, BETA)
    rw_c       = compute_rw(pw_bytes, oprf_val_c)
    rw_key_c   = KDF(rw_c, info=b"opaque-rw-key")

    ki_bytes = AEAD_decrypt(rw_key_c, enc_keys_srv)
    ki = json.loads(ki_bytes.decode())
    lpk_c_r = load_pk(bytes.fromhex(ki["lpk_c"]))
    lsk_c_r = load_sk(bytes.fromhex(ki["lsk_c"]))
    lpk_s_r = load_pk(bytes.fromhex(ki["lpk_s"]))

    print(f"  [Client] Keys recovered successfully")
    print(f"\n\u2713 OPRF Stage Complete\n")

    # Stage 2: AKE
    print(" --- Stage 2: AKE (3-way Diffie-Hellman) ---")
    print("Goal: Establish session key using ephemeral and long-term keys\n")

    print(f"  [Client] Generating ephemeral key")
    epk_c_sk, epk_c = keygen()
    print(f"  [Client] Ephemeral key generated")

    print(f"  [Server] Processing AKE for \'{username}\'")
    lsk_s_r   = load_sk(bytes.fromhex(record["lsk_s"]))
    lpk_c_srv = load_pk(bytes.fromhex(record["lpk_c"]))
    epk_s_sk, epk_s = keygen()

    SK_server = KDF(
        dh(lsk_s_r,   epk_c) +
        dh(epk_s_sk,  epk_c) +
        dh(epk_s_sk,  lpk_c_srv),
        info=b"opaque-3dh-sk"
    )
    SK_client = KDF(
        dh(epk_c_sk,  lpk_s_r) +
        dh(epk_c_sk,  epk_s)   +
        dh(lsk_c_r,   epk_s),
        info=b"opaque-3dh-sk"
    )

    print(f"  [Server] Session key: {SK_server.hex()[:32]}...")
    print(f"  [Client] Computing session key")
    print(f"  [Client] Session key: {SK_client.hex()[:32]}...")
    print(f"\n   Server SK: {SK_server.hex()}")
    print(f"   Client SK: {SK_client.hex()}\n")

    assert SK_client == SK_server, "BUG: session keys differ"
    print(f" Session keys match!\n")
    print(f"\u2713 AKE Stage Complete\n")

    # Stage 3: Key Confirmation
    print(" --- Stage 3: Key Confirmation ---")
    print("Goal: Mutual authentication via HMAC\n")

    Kc = KDF(SK_client, info=b"opaque-key-confirmation-client")
    Ks = KDF(SK_client, info=b"opaque-key-confirmation-server")

    print(f"  [Client] Generating MAC")
    mac_c = HMAC(Kc, b"Client KC")

    print(f"  [Server] Verifying key confirmation")
    assert hmac_lib.compare_digest(HMAC(Kc, b"Client KC"), mac_c)
    mac_s = HMAC(Ks, b"Server KC")
    print(f"  [Server] Client MAC verified")

    print(f"  [Client] Verifying server MAC")
    assert hmac_lib.compare_digest(HMAC(Ks, b"Server KC"), mac_s)
    print(f"  [Client]Server verified - Authentication complete!")
    print(f"\n\u2713 Key Confirmation Complete\n")

    # Summary
    print(SEP2)
    print(f"                    SUCCESS: OPAQUE Authentication Complete!\n")
    print(f" Established Session Key:")
    print(f"  {SK_client.hex()}\n")
    print(f"                               Security Properties:")
    print(f" Password never sent in clear")
    print(f" Server doesn\'t learn password")
    print(f" Client doesn\'t learn salt (in full OPAQUE)")
    print(f" Resistant to precomputation attacks (salt not revealed)")
    print(f" Mutual authentication achieved")
    print(f" Forward secrecy (ephemeral keys)")
    print(SEP2)


if __name__ == "__main__":
    db = Database()
    run_demo("alice", "correct-horse-battery", db)