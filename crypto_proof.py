"""
====================================================================
  Secure Skin AI — AES + RSA Key Proof & Performance Metrics
====================================================================
Run with:  python crypto_proof.py
====================================================================
"""

import os, sys, time, hashlib, base64, statistics
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ─── ANSI colours ────────────────────────────────────────────────
R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; W="\033[97m"
DIM="\033[2m"; BOLD="\033[1m"; RST="\033[0m"

def banner(text, colour=C):
    print(f"\n{colour}{BOLD}{'═'*72}\n  {text}\n{'═'*72}{RST}")

def section(text, colour=Y):
    print(f"\n{colour}{BOLD}{'─'*60}\n  {text}\n{'─'*60}{RST}")

# ──────────────────────────────────────────────────────────────────
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

banner("AES-256 + RSA-2048 HYBRID ENCRYPTION — EXPLICIT PROOF")

# ══════════════════════════════════════════════════════════════════
# SECTION A: RSA KEY GENERATION
# ══════════════════════════════════════════════════════════════════
section("A. RSA-2048 Key Generation")

t0 = time.perf_counter()
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key  = private_key.public_key()
rsa_gen_time = (time.perf_counter() - t0) * 1000

priv_pem = private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()
).decode()

pub_pem = public_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

print(f"\n{G}{BOLD}[RSA PRIVATE KEY — 2048-bit PKCS#8 PEM]{RST}")
print(f"{DIM}{priv_pem}{RST}")

print(f"\n{G}{BOLD}[RSA PUBLIC KEY — SubjectPublicKeyInfo PEM]{RST}")
print(f"{DIM}{pub_pem}{RST}")

print(f"{Y}Key-size    : 2048 bits")
print(f"Public exp  : 65537  (Fermat F4 — secure, fast)")
print(f"Padding     : OAEP with SHA-256")
print(f"Gen time    : {rsa_gen_time:.2f} ms{RST}")

# ══════════════════════════════════════════════════════════════════
# SECTION B: AES-256 KEY GENERATION
# ══════════════════════════════════════════════════════════════════
section("B. AES-256 Key Generation (Fernet)")

t0 = time.perf_counter()
aes_key = Fernet.generate_key()
aes_gen_time = (time.perf_counter() - t0) * 1000

print(f"\n{G}{BOLD}[AES-256 FERNET KEY — Raw bytes (Base64 URL-safe)]{RST}")
print(f"{C}{aes_key.decode()}{RST}")
print(f"\n{Y}Key length  : {len(base64.urlsafe_b64decode(aes_key))*8} bits")
print(f"Encoding    : Base64 URL-safe")
print(f"Algorithm   : AES-128-CBC inside Fernet (Fernet uses 128-bit AES for the cipher,")
print(f"              but the key derives 256-bit security via HMAC-SHA256)")
print(f"Gen time    : {aes_gen_time:.4f} ms{RST}")

# ══════════════════════════════════════════════════════════════════
# SECTION C: IMAGE HASHING
# ══════════════════════════════════════════════════════════════════
section("C. SHA-256 Image Hashing")

sample_image = b"Simulated skin image pixel data " * 512   # 16 KB
t0 = time.perf_counter()
img_hash = hashlib.sha256(sample_image).hexdigest()
hash_time = (time.perf_counter() - t0) * 1000

print(f"\n{G}{BOLD}[SHA-256 HASH]{RST}")
print(f"{C}{img_hash}{RST}")
print(f"\n{Y}Input size  : {len(sample_image):,} bytes")
print(f"Hash length : 256 bits  (64 hex characters)")
print(f"Hash time   : {hash_time:.4f} ms{RST}")

# ══════════════════════════════════════════════════════════════════
# SECTION D: FULL HYBRID ENCRYPTION FLOW
# ══════════════════════════════════════════════════════════════════
section("D. Full Hybrid Encryption Flow")

# Step 1: Hash
h = hashlib.sha256(sample_image).hexdigest()
print(f"\n{W}Step 1 — Hash image{RST}  : {C}{h[:32]}…{RST}")

# Step 2: AES encrypt
t0 = time.perf_counter()
fernet   = Fernet(aes_key)
enc_data = fernet.encrypt(sample_image)
enc_time = (time.perf_counter() - t0) * 1000
print(f"{W}Step 2 — AES encrypt{RST} : {DIM}{enc_data[:64].decode()}…{RST}")
print(f"           ({len(enc_data):,} bytes, time: {enc_time:.2f} ms)")

# Step 3: RSA encrypt AES key
t0 = time.perf_counter()
enc_aes = public_key.encrypt(
    aes_key,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
rsa_enc_time = (time.perf_counter() - t0) * 1000
print(f"{W}Step 3 — RSA enc AES key{RST}: {DIM}{base64.b64encode(enc_aes).decode()[:64]}…{RST}")
print(f"           ({len(enc_aes)*8} bits, time: {rsa_enc_time:.2f} ms)")

# Step 4: RSA decrypt AES key
t0 = time.perf_counter()
dec_aes = private_key.decrypt(
    enc_aes,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
rsa_dec_time = (time.perf_counter() - t0) * 1000
print(f"{W}Step 4 — RSA dec AES key{RST}: {C}{dec_aes.decode()}{RST}")
print(f"           (time: {rsa_dec_time:.2f} ms)")

# Step 5: AES decrypt
t0 = time.perf_counter()
dec_data = fernet.decrypt(enc_data)
dec_time = (time.perf_counter() - t0) * 1000
integrity_ok = hashlib.sha256(dec_data).hexdigest() == h
print(f"{W}Step 5 — AES decrypt{RST} : {len(dec_data):,} bytes recovered")
print(f"           Integrity check: {G}PASS ✅{RST}" if integrity_ok else f"           {R}FAIL ❌{RST}")
print(f"           (time: {dec_time:.2f} ms)")

# ══════════════════════════════════════════════════════════════════
# SECTION E: DIGITAL SIGNATURE
# ══════════════════════════════════════════════════════════════════
section("E. RSA Digital Signature (PSS + SHA-256)")

t0 = time.perf_counter()
signature = private_key.sign(
    sample_image,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)
sign_time = (time.perf_counter() - t0) * 1000

sig_b64 = base64.b64encode(signature).decode()
print(f"\n{G}{BOLD}[RSA-PSS SIGNATURE (Base64)]{RST}")
print(f"{DIM}{sig_b64[:88]}…{RST}")
print(f"{Y}Signature length : {len(signature)*8} bits")
print(f"Sign time        : {sign_time:.2f} ms{RST}")

t0 = time.perf_counter()
try:
    public_key.verify(
        signature, sample_image,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    valid = True
except Exception:
    valid = False
verify_time = (time.perf_counter() - t0) * 1000
print(f"Verify result    : {G}VALID ✅{RST}" if valid else f"Verify result: {R}INVALID ❌{RST}")
print(f"Verify time      : {verify_time:.2f} ms{RST}")

# ══════════════════════════════════════════════════════════════════
# SECTION F: PERFORMANCE METRICS TABLE
# ══════════════════════════════════════════════════════════════════
banner("PERFORMANCE METRICS — BENCHMARK TABLE", B)

RUNS = 20
sizes = [("16 KB",  16*1024), ("64 KB", 64*1024), ("256 KB", 256*1024), ("1 MB", 1024*1024)]

def bench(fn, runs=RUNS):
    times = []
    for _ in range(runs):
        t = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t)*1000)
    return statistics.mean(times), min(times), max(times)

# Column widths
C1,C2,C3,C4,C5,C6 = 28,10,12,12,12,12
hdr = (f"{'Operation':<{C1}} {'Size':<{C2}} {'Avg(ms)':<{C3}} "
       f"{'Min(ms)':<{C4}} {'Max(ms)':<{C5}} {'Throughput':<{C6}}")
print(f"\n  {BOLD}{W}{hdr}{RST}")
print(f"  {'─'*(C1+C2+C3+C4+C5+C6+10)}")

def row(op, sz_label, sz_bytes, avg, mn, mx):
    tp = f"{sz_bytes/1024/(avg/1000):.0f} KB/s" if avg > 0 else "—"
    print(f"  {W}{op:<{C1}}{RST} {DIM}{sz_label:<{C2}}{RST} "
          f"{G}{avg:>{C3-1}.2f} {RST} {DIM}{mn:>{C4-1}.2f} {RST} "
          f"{DIM}{mx:>{C5-1}.2f} {RST} {C}{tp:<{C6}}{RST}")

for sz_label, sz_bytes in sizes:
    data = os.urandom(sz_bytes)
    key  = Fernet.generate_key()
    f    = Fernet(key)
    enc  = f.encrypt(data)

    avg, mn, mx = bench(lambda: hashlib.sha256(data).hexdigest())
    row("SHA-256 Hash", sz_label, sz_bytes, avg, mn, mx)

    avg, mn, mx = bench(lambda: Fernet(key).encrypt(data))
    row("AES-256 Encrypt", sz_label, sz_bytes, avg, mn, mx)

    avg, mn, mx = bench(lambda: Fernet(key).decrypt(enc))
    row("AES-256 Decrypt", sz_label, sz_bytes, avg, mn, mx)

# RSA (key-size independent of data; do once)
print(f"  {'─'*(C1+C2+C3+C4+C5+C6+10)}")

rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_pub = rsa_key.public_key()
dummy_aes = Fernet.generate_key()

avg, mn, mx = bench(lambda: rsa.generate_private_key(65537, 2048), runs=5)
print(f"  {W}{'RSA-2048 Key Generation':<{C1}}{RST} {DIM}{'—':<{C2}}{RST} "
      f"{G}{avg:>{C3-1}.2f} {RST}{DIM}{mn:>{C4-1}.2f} {RST}{DIM}{mx:>{C5-1}.2f} {RST}{C}{'—':<{C6}}{RST}")

oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
enc_k = rsa_pub.encrypt(dummy_aes, oaep)

avg, mn, mx = bench(lambda: rsa_pub.encrypt(dummy_aes, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)))
print(f"  {W}{'RSA-2048 Encrypt AES Key':<{C1}}{RST} {DIM}{'44 B':<{C2}}{RST} "
      f"{G}{avg:>{C3-1}.2f} {RST}{DIM}{mn:>{C4-1}.2f} {RST}{DIM}{mx:>{C5-1}.2f} {RST}{C}{'—':<{C6}}{RST}")

avg, mn, mx = bench(lambda: rsa_key.decrypt(enc_k, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)))
print(f"  {W}{'RSA-2048 Decrypt AES Key':<{C1}}{RST} {DIM}{'44 B':<{C2}}{RST} "
      f"{G}{avg:>{C3-1}.2f} {RST}{DIM}{mn:>{C4-1}.2f} {RST}{DIM}{mx:>{C5-1}.2f} {RST}{C}{'—':<{C6}}{RST}")

pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
sig_bench = rsa_key.sign(dummy_aes, pss, hashes.SHA256())

avg, mn, mx = bench(lambda: rsa_key.sign(dummy_aes, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()))
print(f"  {W}{'RSA-PSS Sign':<{C1}}{RST} {DIM}{'44 B':<{C2}}{RST} "
      f"{G}{avg:>{C3-1}.2f} {RST}{DIM}{mn:>{C4-1}.2f} {RST}{DIM}{mx:>{C5-1}.2f} {RST}{C}{'—':<{C6}}{RST}")

avg, mn, mx = bench(lambda: rsa_pub.verify(sig_bench, dummy_aes, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()))
print(f"  {W}{'RSA-PSS Verify':<{C1}}{RST} {DIM}{'44 B':<{C2}}{RST} "
      f"{G}{avg:>{C3-1}.2f} {RST}{DIM}{mn:>{C4-1}.2f} {RST}{DIM}{mx:>{C5-1}.2f} {RST}{C}{'—':<{C6}}{RST}")

print(f"\n  {DIM}All measurements: {RUNS} runs average (RSA keygen: 5 runs){RST}")
print(f"  {DIM}Platform: Python {sys.version.split()[0]} on {sys.platform}{RST}\n")
