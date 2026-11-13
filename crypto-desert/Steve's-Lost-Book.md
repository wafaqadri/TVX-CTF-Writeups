# Steve's Lost Book

- **Category:** Cryptography
- **Tools Used:** Linux Terminal (`cat`, `base64`), Python 3

---

### Challenge Description

> Steve found a page in a stronghold library, but an Enderman encoded its contents before teleporting away. Recover what the page says.
>
> The Endermen scrambled the letters into a travel-safe alphabet.
>
> *Both `TVXCTF{...}` and `TVX{...}` are accepted.*

We were provided with a single text file named `Steves_Lost_Book.txt`.

---

### Initial Recon & Thought Process

We started by checking the raw contents of `Steves_Lost_Book.txt`:

```bash
cat Steves_Lost_Book.txt
```

This dumped a single continuous string without spaces:

```text
VFZYQ1RGe3N0ZXZlX2ZvdW5kX3RoZV9oaWRkZW5fY2hlc3R9
```

A few things immediately stood out:

1. The character set consists strictly of uppercase letters, lowercase letters, and digits (`[A-Za-z0-9]`).
2. The prompt specifically dropped the phrase **"travel-safe alphabet"**. In computing and networking lore, Base64 was designed specifically to encode arbitrary binary/text data so that it survives safe transmission over channels that might otherwise mangle special characters (e.g., email or legacy protocols).
3. The string starts with `VFZY...`. Knowing that Base64 encodes 3 bytes into 4 ASCII characters:
   - `TVX` in ASCII is `0x54, 0x56, 0x58` → Base64 representation is `VFZY`. This aligned with the expected flag header.

---

### Solution Walkthrough

Since it was standard Base64, we could decode it directly using standard terminal utilities:

```bash
base64 -d Steves_Lost_Book.txt
```


This method returned the cleartext message:

```text
TVXCTF{steve_found_the_hidden_chest}
```

---

### Flag

```text
TVX{steve_found_the_hidden_chest}
```

