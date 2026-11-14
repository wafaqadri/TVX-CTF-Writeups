# WHAT A WASTE OF TOKENS... (3)

Category: Cryptography

Tools Used: Python 3, cyberchef(Used during initial triage to identify octal and float patterns)

---

## Challenge Overview

The challenge came with a 114 KB text file called `last.txt` and a simple description from the author:

> It's the last one, I promise

Looking at the file size and the title *WHAT A WASTE OF TOKENS*, it became clear that the challenge was an onion-like multi-stage puzzle designed to burn context tokens and test our ability to strip away nested encodings layer by layer.

---

## Peeling the Layers

Opening `last.txt` revealed a massive string of 38,312 space-separated numbers:

```text
60 60 61 61 60 61 61 60 40 60 60 61 60 61 61 61 60 40 ...
```

### Layer 1: Octal ASCII to Binary String

Looking at the numbers:

- `60` in octal is ASCII `'0'`.
- `61` in octal is ASCII `'1'`.
- `40` in octal is ASCII `' '` (space delimiter).

Decoding these octal codes turned the text into a sequence of binary bytes:

```text
00110110 00101110 00110111 00110001 00110000 00110010 ...
```

---

### Layer 2: Binary to Floating-Point Numbers

Converting each 8-bit binary segment into its ASCII character:

- `00110110` = `'6'`
- `00101110` = `'.'`
- `00110111` = `'7'`
- `00110001` = `'1'`

This yielded a string of **193 scientific notation floating-point numbers**:

```text
6.710209277116519e-7 5.96791437601496e-7 1.5348543061074567e-19 6.710208140248142e-7 ...
```

---

### Layer 3: Single-Precision (Float32) IEEE-754 Packing

Why floats? Because in single precision (IEEE-754 32-bit), each float represents exactly 4 bytes of raw data.

Unpacking each float using Python's `struct.pack('>f', x)`:

```python
struct.pack(">f", 6.710209277116519e-7) = b'54 5'
struct.pack(">f", 5.96791437601496e-7) = b'5 32'
```

Concatenating all 193 unpacked floats gave 772 bytes of text containing space-separated decimal ASCII numbers:

```text
54 55 32 54 54 32 50 48 32 54 55 32 54 56 32 50 48 ...
```

---

### Layer 4: Decimal to Hex String to 29 Tokens

Converting those decimal numbers back into ASCII characters:

- `54` = `'6'`, `55` = `'7'`, `32` = `' '` → `"67 "`
- `54` = `'6'`, `54` = `'6'`, `32` = `' '` → `"66 "`
- `50` = `'2'`, `48` = `'0'`, `32` = `' '` → `"20 "`

This spelled out space-separated hex bytes:

```text
67 66 20 67 68 20 67 6a 20 69 6e 20 67 69 20 68 6a 20 65 66 ...
```

Converting these hex bytes into text finally gave the true ciphertext: a sequence of **29 two-letter tokens**:

```text
gf gh gj in gi hj ef ei gv ef gv df ef ij ih ee hg hh ie ie gv hf ee ek hl ek ei hn it
```

---

## Cryptanalysis: The Hex Coordinate Cipher

We knew the flag format for the CTF is `TVX{...}` and ends with `}`.

Matching the known flag prefix and suffix against our 29 tokens:

- Token 0: `gf` → `'T'` (ASCII `84` / hex `0x54`)
- Token 1: `gh` → `'V'` (ASCII `86` / hex `0x56`)
- Token 2: `gj` → `'X'` (ASCII `88` / hex `0x58`)
- Token 3: `in` → `'{'` (ASCII `123` / hex `0x7B`)
- Token 28: `it` → `'}'` (ASCII `125` / hex `0x7D`)

### The "Aha!" Moment

Looking at the hex values of the known characters compared to their two-letter tokens:

| Character | Hex Code | High Nibble (d1) | Low Nibble (d2) | Token | First Letter | Second Letter |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **`T`** | `0x54` | `5` | `4` | `gf` | `g` (103) | `f` (102) |
| **`V`** | `0x56` | `5` | `6` | `gh` | `g` (103) | `h` (104) |
| **`X`** | `0x58` | `5` | `8` | `gj` | `g` (103) | `j` (106) |
| **`{`** | `0x7B` | `7` | `B` (11) | `in` | `i` (105) | `n` (110) |
| **`}`** | `0x7D` | `7` | `D` (13) | `it` | `i` (105) | `t` (116) |

Notice the pattern:

1. **First letter (High Nibble):**
   - `ord(r) - 98 = High Nibble`
   - `'e'` (101 - 98 = 3) → `0x3_`
   - `'g'` (103 - 98 = 5) → `0x5_`
   - `'h'` (104 - 98 = 6) → `0x6_`
   - `'i'` (105 - 98 = 7) → `0x7_`

2. **Second letter (Low Nibble):**
   - Digits `0-9` and `A-F` are mapped directly to letters shifted by `'b'` (98), with skipped letters for hex letters:
     - `e` → `3`, `f` → `4`, `g` → `5`, `h` → `6`, `i` → `7`, `j` → `8`, `k` → `9`, `l` → `A`
     - `n` → `B` (11), `t` → `D` (13), `v` → `F` (15)

This meant:

- `gv` = `0x5F` = `_` (Underscore!)
- `ef` = `0x34` = `4`
- `ei` = `0x37` = `7`
- `gi` = `0x57` = `W`
- `hj` = `0x68` = `h`
- `gi hj ef ei` = `Wh47` ("What")

Every token was simply the two nibbles of a character's hex representation!

---

## Complete Solve Script (`solve.py`)

Here is the full Python script that automates the entire unpacking pipeline and decodes the final flag:

```python
import struct

# Step 1: Read raw octal data
with open("last.txt", "r") as f:
    octal_data = f.read().strip().split()

# Step 2: Octal -> Binary String -> ASCII Floats
bin_str = "".join(chr(int(t, 8)) for t in octal_data)
ascii_floats = "".join(chr(int(b, 2)) for b in bin_str.split()).split()

# Step 3: Floats -> Float32 IEEE-754 bytes -> Decimal ASCII codes
packed_bytes = b"".join(struct.pack(">f", float(x)) for x in ascii_floats)
decimal_ascii = packed_bytes.decode("latin1").split()

# Step 4: Decimal codes -> Hex bytes -> 29 two-letter tokens
hex_text = "".join(chr(int(d)) for d in decimal_ascii)
tokens = bytes.fromhex(hex_text).decode("latin1").split()

# Step 5: Decode the 2-letter hex coordinate cipher
d1_map = {
    "d": 0x2,
    "e": 0x3,
    "g": 0x5,
    "h": 0x6,
    "i": 0x7,
}

d2_map = {
    "e": 0x3,
    "f": 0x4,
    "g": 0x5,
    "h": 0x6,
    "i": 0x7,
    "j": 0x8,
    "k": 0x9,
    "l": 0xA,
    "n": 0xB,
    "t": 0xD,
    "v": 0xF,
}

flag_bytes = []
for t in tokens:
    high_nibble = d1_map[t[0]]
    low_nibble = d2_map[t[1]]
    flag_bytes.append((high_nibble << 4) | low_nibble)

flag = bytes(flag_bytes).decode("latin1")
print(f"[+] Flag: {flag}")
```

Running the script outputs:

```text
[+] Flag: TVX{Wh47_4_$4xv3efss_d39j97k}
```

---

## Flag

```text
TVX{Wh47_4_$4xv3efss_d39j97k}
```



---
