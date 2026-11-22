import csv
import os
import sys
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    AESGCMSIV,
    ChaCha20Poly1305,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

RUNS = 101  # run 0 is the warm-up
RSA_KEYGEN_RUNS = 21  # RSA keygen is slow, so the brief uses 21 runs instead of 101
HEADER = ["part", "algorithm", "operation", "message_bytes", "run", "nanoseconds"]


def time_runs(func, runs):
    """Call func() `runs` times, timing each call on its own.

    Returns a list of nanosecond durations, in order. Index 0 is the warm-up.
    """
    times = []
    for _ in range(runs):
        start = time.perf_counter_ns()
        func()
        end = time.perf_counter_ns()
        times.append(end - start)
    return times


def time_runs_with_inputs(func, inputs):
    """Like time_runs, but call func(item) once for each item in `inputs`.

    The items are prepared before this function is called, so preparing them
    (e.g. generating nonces) is not part of the timing.
    """
    times = []
    for item in inputs:
        start = time.perf_counter_ns()
        func(item)
        end = time.perf_counter_ns()
        times.append(end - start)
    return times


def record(writer, part, algorithm, operation, message_bytes, times):
    """Write one CSV row per timed run, warm-up (run 0) included."""
    for run, ns in enumerate(times):
        writer.writerow([part, algorithm, operation, message_bytes, run, ns])


# ---------------------------------------------------------------------------
# Key establishment (part = "kem")
# ---------------------------------------------------------------------------

RSA_OAEP_PARAMS = [
    ("RSA-OAEP-3072", 3072),
    ("RSA-OAEP-7680", 7680),
]


def bench_rsa_oaep(writer):
    for name, key_size in RSA_OAEP_PARAMS:
        # Setup, not timed: one key pair, the padding, and one ciphertext
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = key.public_key()
        oaep = padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
        ciphertext = public_key.encrypt(os.urandom(32), oaep)

        # keygen: 21 runs, public exponent 65537
        times = time_runs(
            lambda: rsa.generate_private_key(public_exponent=65537, key_size=key_size),
            RSA_KEYGEN_RUNS,
        )
        record(writer, "kem", name, "keygen", 0, times)

        # encapsulate: the 32 B of random data is generated inside the timing
        times = time_runs(lambda: public_key.encrypt(os.urandom(32), oaep), RUNS)
        record(writer, "kem", name, "encapsulate", 0, times)

        # decapsulate: same ciphertext every run
        times = time_runs(lambda: key.decrypt(ciphertext, oaep), RUNS)
        record(writer, "kem", name, "decapsulate", 0, times)


ECDH_PARAMS = [
    ("ECDH-P-256", ec.SECP256R1()),
    ("ECDH-P-384", ec.SECP384R1()),
    ("ECDH-P-521", ec.SECP521R1()),
]


def ecdh_encapsulate(public_key):
    """Ephemeral key pair + key exchange; the ciphertext is the ephemeral public point."""
    ephemeral = ec.generate_private_key(public_key.curve)
    shared_secret = ephemeral.exchange(ec.ECDH(), public_key)
    ciphertext = ephemeral.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    )
    return shared_secret, ciphertext


def ecdh_decapsulate(key, curve, ciphertext):
    """Load the ephemeral public key from its bytes, then do the key exchange."""
    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(curve, ciphertext)
    return key.exchange(ec.ECDH(), ephemeral_public)


def bench_ecdh(writer):
    for name, curve in ECDH_PARAMS:
        # Setup, not timed: one key pair, and one ciphertext for decapsulate
        key = ec.generate_private_key(curve)
        public_key = key.public_key()
        _, ciphertext = ecdh_encapsulate(public_key)

        times = time_runs(lambda: ec.generate_private_key(curve), RUNS)
        record(writer, "kem", name, "keygen", 0, times)

        times = time_runs(lambda: ecdh_encapsulate(public_key), RUNS)
        record(writer, "kem", name, "encapsulate", 0, times)

        times = time_runs(lambda: ecdh_decapsulate(key, curve, ciphertext), RUNS)
        record(writer, "kem", name, "decapsulate", 0, times)


def x25519_encapsulate(public_key):
    """Ephemeral key pair + key exchange; the ciphertext is the raw ephemeral public key."""
    ephemeral = X25519PrivateKey.generate()
    shared_secret = ephemeral.exchange(public_key)
    ciphertext = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return shared_secret, ciphertext


def x25519_decapsulate(key, ciphertext):
    ephemeral_public = X25519PublicKey.from_public_bytes(ciphertext)
    return key.exchange(ephemeral_public)


def bench_x25519(writer):
    key = X25519PrivateKey.generate()
    public_key = key.public_key()
    _, ciphertext = x25519_encapsulate(public_key)

    times = time_runs(lambda: X25519PrivateKey.generate(), RUNS)
    record(writer, "kem", "X25519", "keygen", 0, times)

    times = time_runs(lambda: x25519_encapsulate(public_key), RUNS)
    record(writer, "kem", "X25519", "encapsulate", 0, times)

    times = time_runs(lambda: x25519_decapsulate(key, ciphertext), RUNS)
    record(writer, "kem", "X25519", "decapsulate", 0, times)


MLKEM_PARAMS = [
    ("ML-KEM-768", mlkem.MLKEM768PrivateKey),
    ("ML-KEM-1024", mlkem.MLKEM1024PrivateKey),
]


def bench_mlkem(writer):
    for name, key_class in MLKEM_PARAMS:
        # Setup, not timed: one key pair, and one ciphertext for decapsulate.
        # NOTE: check the docs for the order encapsulate() returns its pair in.
        key = key_class.generate()
        public_key = key.public_key()
        shared_secret, ciphertext = public_key.encapsulate()

        times = time_runs(lambda: key_class.generate(), RUNS)
        record(writer, "kem", name, "keygen", 0, times)

        times = time_runs(lambda: public_key.encapsulate(), RUNS)
        record(writer, "kem", name, "encapsulate", 0, times)

        times = time_runs(lambda: key.decapsulate(ciphertext), RUNS)
        record(writer, "kem", name, "decapsulate", 0, times)


# ---------------------------------------------------------------------------
# Digital signatures (part = "signature")
# ---------------------------------------------------------------------------

def bench_ed25519(writer, message):
    # Setup, not timed: one key pair, reused for sign and verify
    key = Ed25519PrivateKey.generate()
    public_key = key.public_key()
    signature = key.sign(message)  # the signature that verify will check

    # keygen: generating the key is the operation being timed
    times = time_runs(lambda: Ed25519PrivateKey.generate(), RUNS)
    record(writer, "signature", "Ed25519", "keygen", 0, times)

    # sign: the message is passed directly to Ed25519
    times = time_runs(lambda: key.sign(message), RUNS)
    record(writer, "signature", "Ed25519", "sign", 0, times)

    # verify: same signature every run
    times = time_runs(lambda: public_key.verify(signature, message), RUNS)
    record(writer, "signature", "Ed25519", "verify", 0, times)


ECDSA_PARAMS = [
    ("ECDSA-P-256", ec.SECP256R1(), hashes.SHA256()),
    ("ECDSA-P-384", ec.SECP384R1(), hashes.SHA384()),
    ("ECDSA-P-521", ec.SECP521R1(), hashes.SHA512()),
]


def bench_ecdsa(writer, message):
    for name, curve, hash_alg in ECDSA_PARAMS:
        # Setup, not timed: one key pair, and one signature for verify
        key = ec.generate_private_key(curve)
        public_key = key.public_key()
        algorithm = ec.ECDSA(hash_alg)
        signature = key.sign(message, algorithm)

        times = time_runs(lambda: ec.generate_private_key(curve), RUNS)
        record(writer, "signature", name, "keygen", 0, times)

        times = time_runs(lambda: key.sign(message, algorithm), RUNS)
        record(writer, "signature", name, "sign", 0, times)

        times = time_runs(lambda: public_key.verify(signature, message, algorithm), RUNS)
        record(writer, "signature", name, "verify", 0, times)


RSA_PSS_PARAMS = [
    ("RSA-PSS-3072", 3072),
    ("RSA-PSS-7680", 7680),
]


def bench_rsa_pss(writer, message):
    for name, key_size in RSA_PSS_PARAMS:
        # Setup, not timed: one key pair, the padding, and one signature for verify
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = key.public_key()
        hash_alg = hashes.SHA256()
        pss = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hash_alg.digest_size,  # salt the length of the digest (32 B)
        )
        signature = key.sign(message, pss, hash_alg)

        # keygen: 21 runs, public exponent 65537
        times = time_runs(
            lambda: rsa.generate_private_key(public_exponent=65537, key_size=key_size),
            RSA_KEYGEN_RUNS,
        )
        record(writer, "signature", name, "keygen", 0, times)

        times = time_runs(lambda: key.sign(message, pss, hash_alg), RUNS)
        record(writer, "signature", name, "sign", 0, times)

        times = time_runs(lambda: public_key.verify(signature, message, pss, hash_alg), RUNS)
        record(writer, "signature", name, "verify", 0, times)


MLDSA_PARAMS = [
    ("ML-DSA-44", mldsa.MLDSA44PrivateKey),
    ("ML-DSA-65", mldsa.MLDSA65PrivateKey),
    ("ML-DSA-87", mldsa.MLDSA87PrivateKey),
]


def bench_mldsa(writer, message):
    for name, key_class in MLDSA_PARAMS:
        # Setup, not timed: one key pair, and one signature for verify
        key = key_class.generate()
        public_key = key.public_key()
        signature = key.sign(message)

        times = time_runs(lambda: key_class.generate(), RUNS)
        record(writer, "signature", name, "keygen", 0, times)

        # the message is passed directly, with no hash or context
        times = time_runs(lambda: key.sign(message), RUNS)
        record(writer, "signature", name, "sign", 0, times)

        times = time_runs(lambda: public_key.verify(signature, message), RUNS)
        record(writer, "signature", name, "verify", 0, times)


# ---------------------------------------------------------------------------
# Authenticated encryption (part = "aead")
# ---------------------------------------------------------------------------

AEAD_PARAMS = [
    # (name, class, key length in bytes)
    ("AES-128-GCM", AESGCM, 16),
    ("AES-256-GCM", AESGCM, 32),
    ("ChaCha20-Poly1305", ChaCha20Poly1305, 32),
    ("AES-256-GCM-SIV", AESGCMSIV, 32),
]
AEAD_MESSAGE_LENGTHS = [64, 1024, 16384, 1048576]


def bench_aead(writer):
    for name, cipher_class, key_len in AEAD_PARAMS:
        for length in AEAD_MESSAGE_LENGTHS:
            # Setup, not timed: random key and message, the cipher object,
            # and one ciphertext (with its nonce) for decrypt
            cipher = cipher_class(os.urandom(key_len))
            message = os.urandom(length)
            decrypt_nonce = os.urandom(12)
            ciphertext = cipher.encrypt(decrypt_nonce, message, None)

            # encrypt: a fresh random 12 B nonce every run, generated before
            # the clock starts, no associated data
            nonces = [os.urandom(12) for _ in range(RUNS)]
            times = time_runs_with_inputs(
                lambda nonce: cipher.encrypt(nonce, message, None), nonces
            )
            record(writer, "aead", name, "encrypt", length, times)

            # decrypt: same nonce and ciphertext every run
            times = time_runs(lambda: cipher.decrypt(decrypt_nonce, ciphertext, None), RUNS)
            record(writer, "aead", name, "decrypt", length, times)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: python my_project.py <output-directory>")
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)

    # One random 1 KiB message, shared by every signature algorithm
    message = os.urandom(1024)

    with open(os.path.join(out_dir, "raw.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)

        # Key establishment
        bench_rsa_oaep(writer)
        bench_ecdh(writer)
        bench_x25519(writer)
        bench_mlkem(writer)

        # Digital signatures
        bench_ed25519(writer, message)
        bench_ecdsa(writer, message)
        bench_rsa_pss(writer, message)
        bench_mldsa(writer, message)

        # Authenticated encryption
        bench_aead(writer)


if __name__ == "__main__":
    main()