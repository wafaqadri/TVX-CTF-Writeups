# The Fourth Portal
Category: Cryptography

Tools Used: Python 3 (csv, itertools, json) and cryptography (HKDF, AESGCM)



---

## 1. Challenge Overview

We were provided with a zip archive named `the_fourth_portal.zip` containing Minecraft-themed lore files and cryptographic artifacts:

```text
the_fourth_portal/
├── overworld/
│   └── beacons.csv
├── nether/
│   └── beacons.csv
├── the_end/
│   └── beacons.csv
└── the_echo/
    ├── lectern.txt
    ├── core.hex
    └── vault.json
```

The challenge prompt gave us the narrative setup:

> *"An abandoned portal links the Overworld, the Nether, and the End. Then a fourth world answers: the Echo. Its vault is sealed, and someone has forged beacon readings in each of the old dimensions. Rebuild what the three worlds lost, bring the Echo's piece, and open the vault. The last cartographer left a book on the Echo's lectern."*

---

## 2. Recon & Lore Analysis

Opening `the_echo/lectern.txt`, we find precise mathematical instructions left behind by the "cartographer":

```text
THE CARTOGRAPHER'S LAST BOOK

Each old world left sixteen beacon readings (X, Z).
The portal reads both coordinates as residues modulo 257:
convert each signed coordinate to its least nonnegative residue.
Example: (-1, 258) is the point (256, 1).

In each old world, the honest readings follow the same rule for
that world: Z = c0 + c1*X + ... + c7*X^7, with all arithmetic
modulo 257. Up to four readings in each ledger were forged.
Each world has its own eight coefficients. Inscribe them as
eight bytes in order c0 through c7. Real coefficients fit in a
byte (0 to 255).

The Echo kept its own eight bytes intact in core.hex.

THE PORTAL FRAME
Read one byte from each world per row:
Overworld, Nether, The End, The Echo.
Start at the first byte of each world, then move to the next
byte in each. The first two rows are O0 N0 E0 H0 O1 N1 E1 H1.
The completed frame is 32 raw bytes, the input key material
for the vault's key derivation.
```

And checking `the_echo/vault.json`:

```json
{
  "kdf": "HKDF-SHA256",
  "salt_hex": "4a06df8e10e1cb1e5c5fd2373f125dda",
  "info_ascii": "TVX:fourth-portal:v1",
  "key_length_bytes": 32,
  "cipher": "AES-256-GCM",
  "nonce_hex": "59cea0d35d9d3b98d04739da",
  "aad_ascii": "echo-vault-v1",
  "ciphertext_hex": "b3a00bcaf2a3fedce9ea0320bcfa8ecb384879b29a4907ba981fe881ed6c5ef043dff8",
  "tag_hex": "0dec614c7ff044e0d3cf011e949a93e7"
}
```

Finally, `the_echo/core.hex` had the 8 bytes for Echo:

```text
6e 11 c3 61 9f ee 00 c4
```

---

## 3. Mathematical Strategy: Polynomial Reconstruction over F_257

Breaking down the constraints:

1. **Field**: Arithmetic is modulo p = 257, which is prime (F_257).
2. **Degree**: The secret polynomial in each dimension has degree up to 7:

   **Z ≡ c₀ + c₁X + c₂X² + ... + c₇X⁷ (mod 257)**

   which is defined by 8 coefficients (c₀, ..., c₇).

3. **Data Points**: We are given 16 points (X, Z) in each world's `beacons.csv`.
4. **Forged Points (Errors)**: At most 4 points are forged, meaning **at least 12 points are guaranteed honest**.

Because p = 257 is prime and 8 points uniquely determine a degree-7 polynomial, we can treat this as an error-correcting code problem (specifically Reed-Solomon decoding).

Given that C(16, 8) = 12,870, the search space is tiny! A simple combination/RANSAC search over subsets of 8 points:

- Pick 8 distinct points from the 16 given points.
- Compute the interpolating polynomial using **Lagrange interpolation modulo 257**.
- Evaluate the polynomial on all 16 points.
- If it evaluates correctly on ≥ 12 points, we have found the true honest polynomial.

### Lagrange Interpolation Modulo 257

For 8 points (x₀, z₀), ..., (x₇, z₇):

**P(x) = Σ(k=0 to 7) [zₖ × Π(j ≠ k) ((x - xⱼ) / (xₖ - xⱼ))] mod 257**

Modular inversion `1/d mod 257` is computed via Fermat's Little Theorem:

**d²⁵⁵ mod 257**

---

## 4. Solving the Polynomials

Running the interpolation across all three files:

- **Overworld**:
  - Found 12/16 matching points.
  - Coefficients: `[142, 244, 194, 72, 92, 128, 2, 138]`
  - Bytes (O): `8e f4 c2 48 5c 80 02 8a`

- **Nether**:
  - Found 12/16 matching points.
  - Coefficients: `[147, 108, 179, 81, 164, 6, 234, 230]`
  - Bytes (N): `93 6c b3 51 a4 06 ea e6`

- **The End**:
  - Found 12/16 matching points.
  - Coefficients: `[201, 58, 11, 177, 171, 157, 123, 10]`
  - Bytes (E): `c9 3a 0b b1 ab 9d 7b 0a`

- **The Echo** (from `core.hex`):
  - Bytes (H): `6e 11 c3 61 9f ee 00 c4`

---

## 5. Portal Frame & Key Material Assembly

Per the cartographer's instructions, we interleave the bytes row by row:

**O₀, N₀, E₀, H₀, O₁, N₁, E₁, H₁, ..., O₇, N₇, E₇, H₇**

This produces the 32-byte raw Input Key Material (IKM):

```text
8e93c96ef46c3a11c2b30bc34851b1615ca4ab9f80069dee02ea7b008ae60ac4
```

---

## 6. Decrypting the Vault

Using `HKDF-SHA256` as specified in `vault.json`:

- **IKM**: The 32 assembled bytes
- **Salt**: `bytes.fromhex("4a06df8e10e1cb1e5c5fd2373f125dda")`
- **Info**: `"TVX:fourth-portal:v1"`
- **Derived AES Key**: `60b8aa7c2ae2c7ed213a58dcc13768a5a9903db9c1af0955acd80efb2a35282d`

Then decrypting with **AES-256-GCM**:

- **Nonce**: `bytes.fromhex("59cea0d35d9d3b98d04739da")`
- **AAD**: `"echo-vault-v1"`
- **Ciphertext + Tag**: From `vault.json`

The GCM authentication tag verifies, yielding the flag!

---

## 7. Full Exploit Script

```python
import csv
import itertools
import json
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

P = 257

def inv(n):
    return pow(n % P, P - 2, P)

def poly_eval(coeffs, x):
    res = 0
    xp = 1
    for c in coeffs:
        res = (res + c * xp) % P
        xp = (xp * x) % P
    return res

def lagrange(points):
    deg = len(points)
    total_coeffs = [0] * deg
    for k in range(deg):
        xk, zk = points[k]
        denom = 1
        poly = [1]
        for j in range(deg):
            if j == k:
                continue
            xj, _ = points[j]
            denom = (denom * (xk - xj)) % P
            new_poly = [0] * (len(poly) + 1)
            for deg_idx, c in enumerate(poly):
                new_poly[deg_idx] = (new_poly[deg_idx] + c * (-xj)) % P
                new_poly[deg_idx + 1] = (new_poly[deg_idx + 1] + c) % P
            poly = new_poly
        
        factor = (zk * inv(denom)) % P
        for deg_idx in range(deg):
            total_coeffs[deg_idx] = (total_coeffs[deg_idx] + poly[deg_idx] * factor) % P
            
    return total_coeffs

def solve_world(filepath):
    points = []
    with open(filepath, 'r') as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            if not row or not row[0].strip():
                continue
            points.append((int(row[0]) % P, int(row[1]) % P))
            
    for subset in itertools.combinations(points, 8):
        xs = [pt[0] for pt in subset]
        if len(set(xs)) < 8:
            continue
        coeffs = lagrange(subset)
        
        matches = sum(1 for x, z in points if poly_eval(coeffs, x) == z)
        if matches >= 12:
            return bytes(coeffs)
            
    raise RuntimeError(f"Could not solve {filepath}")

def main():
    # 1. Recover polynomial coefficients
    o = solve_world('overworld/beacons.csv')
    n = solve_world('nether/beacons.csv')
    e = solve_world('the_end/beacons.csv')
    
    with open('the_echo/core.hex') as f:
        core_hex = f.read().strip().replace(' ', '')
    h = bytes.fromhex(core_hex)
    
    # 2. Interleave into 32-byte frame
    frame = bytearray()
    for i in range(8):
        frame.extend([o[i], n[i], e[i], h[i]])
    print("[+] Recovered Key Material (IKM):", frame.hex())
    
    # 3. HKDF-SHA256 Derivation
    with open("the_echo/vault.json") as f:
        vault = json.load(f)
        
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=vault["key_length_bytes"],
        salt=bytes.fromhex(vault["salt_hex"]),
        info=vault["info_ascii"].encode("utf-8"),
    )
    derived_key = hkdf.derive(bytes(frame))
    print("[+] Derived AES Key:", derived_key.hex())
    
    # 4. AES-256-GCM Decryption
    aesgcm = AESGCM(derived_key)
    nonce = bytes.fromhex(vault["nonce_hex"])
    aad = vault["aad_ascii"].encode("utf-8")
    ct = bytes.fromhex(vault["ciphertext_hex"])
    tag = bytes.fromhex(vault["tag_hex"])
    
    plaintext = aesgcm.decrypt(nonce, ct + tag, aad)
    print("[+] Flag:", plaintext.decode("utf-8"))

if __name__ == '__main__':
    main()
```

---

## 8. Conclusion

- **Category**: Crypto Desert (Cryptography)
- **Tools Used**: Python 3 standard library (`csv`, `itertools`, `json`) + `cryptography` package (`HKDF`, `hashes`, `AESGCM`).
- **Core Concept**: Finite field polynomial interpolation (modulo 257) with noisy/forged data points, followed by standard cryptographic key derivation (HKDF) and authenticated decryption (AES-GCM).
- **Flag**:

  ```text
  TVX{th3_3ch0_b1nds_th3_f0ur_w0rlds}
  ```
