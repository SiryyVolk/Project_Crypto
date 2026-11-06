import csv
import os
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric import mldsa

RUNS = 101  # run 0 is the warm-up; RSA keygen will use 21 instead
RSA_KEYGEN_RUNS = 3  # RSA keygen is slow, so the brief uses 21 runs instead of 101
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


def record(writer, part, algorithm, operation, message_bytes, times):
    """Write one CSV row per timed run, warm-up (run 0) included."""
    for run, ns in enumerate(times):
        writer.writerow([part, algorithm, operation, message_bytes, run, ns])


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
        bench_ed25519(writer, message)
        bench_ecdsa(writer, message)
        bench_rsa_pss(writer, message)
        bench_mldsa(writer, message)

if __name__ == "__main__":
    main()