# Creeper's Shared Prime

* **Category:** Cryptography
* **Tools Used:** Python 3 (`math`, standard library)

---

### Challenge Description

> Both vaults were assembled by the same careless Creeper.

We were provided with two text files:

* `public_keys.txt` — contains public parameters for two separate vaults (`Vault A` and `Vault B`).
* `ciphertext.txt` — contains the encrypted flag belonging to Vault A.

---

### Initial Recon & The Flaw

Opening `public_keys.txt`, we found two RSA public keys sharing the standard public exponent `e = 65537`, but with two distinct moduli:

```text
=== Creeper Vault A ===
n = 1942668892225729070919461906823520455305416829490420089422957436437580309796491507761
e = 65537

=== Creeper Vault B ===
n = 1942668892225729070919461906823519371241578281403951004079222153957205455266330293941
e = 65537
```

And inside `ciphertext.txt`:

```text
c = 1574928985319013777436289945491687612751672976588545303342361399014858100334313795739

The ciphertext belongs to Vault A.
```

The title (*"Creeper's Shared Prime"*) and the note (*"same careless Creeper"*) pointed directly to one of the most classic textbook RSA vulnerabilities: **Common Factor / Shared Prime Attack**.

In standard RSA, a modulus `n` is the product of two random prime numbers:

**n = p × q**

If an implementation has poor entropy or reuses primes across key generations, two different public keys might share one prime factor:

**n_A = p × q_A**

**n_B = p × q_B**

Normally, factoring a large composite modulus `n` without knowing the factors is computationally infeasible. However, if two moduli share a common factor `p`, we don't need to factor them at all. We can extract `p` directly in microseconds using the Euclidean algorithm to find the greatest common divisor:

**p = gcd(n_A, n_B)**

---

### Solution Walkthrough

Once `p` is recovered:

1. Divide `n_A` by `p` to get the second factor `q_A = n_A / p`.
2. Compute Euler's totient function for Vault A:

   **φ(n_A) = (p - 1)(q_A - 1)**

3. Compute the private decryption exponent `d_A` via the modular inverse:

   **d_A ≡ e⁻¹ (mod φ(n_A))**

4. Decrypt the ciphertext:

   **m ≡ cᵈᴬ (mod n_A)**

5. Convert the integer `m` back into ASCII text.

We wrote a quick Python solver script (`solve.py`):

```python
import math

# Public key parameters
n_A = 1942668892225729070919461906823520455305416829490420089422957436437580309796491507761
n_B = 1942668892225729070919461906823519371241578281403951004079222153957205455266330293941
e = 65537

# Ciphertext for Vault A
c = 1574928985319013777436289945491687612751672976588545303342361399014858100334313795739

# 1. Recover the shared prime factor p
p = math.gcd(n_A, n_B)
assert p > 1, "No common factor found!"

# 2. Find q for Vault A
q = n_A // p

# 3. Compute phi and private exponent d
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

# 4. Decrypt ciphertext
m = pow(c, d, n_A)

# 5. Decode integer to ASCII bytes
flag = bytes.fromhex(hex(m)[2:]).decode()
print("[+] Decrypted Flag:", flag)
```

Running the script gives:

```text
[+] Decrypted Flag: TVXCTF{the_creeper_reused_a_prime}
```

---

### Flag

```text
TVXCTF{the_creeper_reused_a_prime}
```
