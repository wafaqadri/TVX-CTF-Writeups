## Ender Chest (100 PTS)
Category: Cryptography.

Tools Used: Python 3, PARI/GP (gp) / SageMath.

### Challenge Overview

The challenge archive contained an encryption script `chall.py` and its output `output.txt`.

The challenge description read:

> "You found a world seed nobody could guess and used it as the key to his chests. Elliptic curves are unbreakable, so the curve the server admin picked must be fine, right?... RIGHT???"

In `chall.py`, we see standard Elliptic Curve Cryptography (ECC) over a finite prime field `F_p`:

- Curve equation: `y² ≡ x³ + ax + b (mod p)`
- Base point: `G`
- Public key point: `Q = d · G` (where `d` is the secret world seed)

The script encrypted two payloads with AES-256-CBC:

1. `shulker_box` → Encrypted using the x-coordinate of public point `Q` (`Q[0]`).
2. `ender_chest` → Encrypted using the private seed `d`.

---

### The Trap

Since `output.txt` already gave us `Q[0]`, decrypting `shulker_box` was effortless:

```python
# Decrypting shulker_box gives:

TVX{tNt_g035_B00m_C0ngr4t5}
```

Submitting this to the platform failed. Looking at the challenge title ("Ender Chest") and the fake flag message, it was obvious: `shulker_box` was a honeypot decoy. The **real** flag was locked inside `ender_chest`, meaning we actually had to recover the private key `d`.

---

###  The Vulnerability (Pohlig-Hellman on Smooth Curve)

Recovering `d` from `Q = d · G` is the Elliptic Curve Discrete Logarithm Problem (ECDLP). On secure curves like `secp256k1`, this is computationally impossible.

However, an elliptic curve is only as strong as the prime factors of its **group order** `N = #E(F_p)`.

We checked the number of points on this custom curve:

```text
N = #E(F_p) = 4724861355973759917094976238449899
```

When factored, this number reveals its critical flaw:

```text
N = 11 × 367 × 13399 × 58453 × 484079 × 40128631 × 76927309
```

Every single prime factor is tiny (the largest is around `7.69 × 10^7`). When a group order factors into small primes, the group is called **smooth**.

This makes the curve completely vulnerable to the **Pohlig-Hellman Algorithm**:

1. Solve the discrete logarithm modulo each small prime power factor individually (using Baby-step Giant-step or Pollard's rho).
2. Combine the small results back together using the **Chinese Remainder Theorem (CRT)** to find the full `d`.

---

###  Solution Walkthrough

#### Step 1: Solving the Discrete Logarithm

Using **PARI/GP** or **SageMath**, the `elllog` function solves Pohlig-Hellman in under a second:

```gp
/* PARI/GP snippet */

p = 4724861355973759862466485852137759;

a = 927566916496059264792326746507264;

b = 4715968330470840770745781630703560;

E = ellinit([a, b], p);

G = [3675942204092047283238136253093045, 3544727085494657603430718404172845];

Q = [3869418175838450319054504785525959, 1429060253338888234770668216689896];

d = elllog(E, Q, G);

print("Private seed d = ", d);
```

This output the private key:

```text
d = 2327569722739447708246377569803395
```

---

#### Step 2: Decrypting the Real Flag (`solve_ender.py`)

Now that we have the world seed `d`, we derive the AES key and decrypt `ender_chest`:

```python
import hashlib

from Crypto.Cipher import AES

from Crypto.Util.Padding import unpad

# Recovered secret seed d

d = 2327569722739447708246377569803395

# Encrypted ender_chest from output.txt

ender_chest_hex = "46e14511e959705d1fe179ab3a4c2c40f5db5273f61faa0e319096122ccc59f812a0f0591c193aab914bda09c9f609413398a9c3e8c8e602fc356ff3ea5a7583"

raw_data = bytes.fromhex(ender_chest_hex)

# Deriving AES key and IV

key = hashlib.sha256(str(d).encode()).digest()

iv = raw_data[:16]

ciphertext = raw_data[16:]

# Decrypt

cipher = AES.new(key, AES.MODE_CBC, iv)

flag = unpad(cipher.decrypt(ciphertext), 16).decode()

print(f"[+] Real Flag: {flag}")
```

Running the script gives:

```text
[+] Real Flag: TVX{D1dn5_F4lL_4_7h3_7r4p_7h15_t1me}
```

---

### Key Takeaways

1. **Never reuse primes in RSA:** Sharing a prime factor across different moduli completely breaks key confidentiality with a single GCD computation.
2. **Never pick custom curves blindly:** Elliptic curves must be chosen such that the group order contains at least one large prime factor ≥ 2²⁵⁶. If the order is smooth, Pohlig-Hellman breaks it in seconds.
3. **Always read the challenge name:** The author specifically named the challenge *Ender Chest*, leaving *Shulker Box* as an intentional trap to catch players who didn't verify their targets.
