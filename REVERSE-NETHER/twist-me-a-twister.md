# Twist Me a Twister: Reverse Engineering Writeup

| | |
|---|---|
| **Category** | Reverse Engineering |
| **Points** | 100 |
| **File** | `TwistMeATwister.exe` |
| **Flag** | `TVX{Fl4ggy_fl4g_fl4g_tw15ty_tw15t_tw15t}` |

## Overview

The challenge file is `TwistMeATwister.exe`, a .NET console program. The hint is "Ever heard of tongue twisters? programs can twist your tongue too!!". The program asks for a flag and prints `accepted` or `rejected`.

## 1. Triage

`file` shows a PE32 .NET assembly, and `strings` finds almost nothing useful. The `#US` (user strings) heap holds only the prompt and the `accepted` and `rejected` messages. There is no embedded base64 blob this time.

I had no decompiler available, so I parsed the .NET metadata by hand and disassembled the IL of each method.

## 2. Finding the hidden data

The program has a static byte array that is filled at startup from the PE's `FieldRVA` table. It is stored in the file as raw data:

| Item | Value |
|---|---|
| Size | 40 bytes |
| File offset | `816` (`0x330`) |

The program rebuilds the expected flag from these 40 bytes in a method called `Reveal()`. It compares your input to the result, so the flag is whatever `Reveal()` produces.

## 3. The `Reveal()` routine

For each output position `i` from 0 to 39, the method does the following:

1. It picks a source index with a "twist" that scrambles the order:

   ```
   idx = (i * 7 + 3) % 40
   ```

2. It reads `S[idx]` and rotates it right by `idx % 5 + 1` bits.
3. It XORs the result with `(55 + idx * 11) & 0xFF`.
4. It stores the result as output byte `i`.

The output bytes are decoded as ASCII to give the expected string.

## 4. Solve

I read the 40 bytes straight out of the executable and applied the same steps in Python:

```python
d = open('TwistMeATwister.exe', 'rb').read()
S = list(d[816:816 + 40])
n = 40

def ror(x, k):
    return ((x >> (k & 31)) | (x << ((8 - k) & 31))) & 255

out = []
for i in range(n):
    idx = (i * 7 + 3) % n
    b = ror(S[idx], idx % 5 + 1)
    b = (b ^ ((55 + idx * 11) & 255)) & 255
    out.append(b)

print(bytes(out).decode())
```

Output:

```
TVX{Fl4ggy_fl4g_fl4g_tw15ty_tw15t_tw15t}
```

## Takeaway

The flag is never stored as plain text. It sits in the binary as 40 scrambled bytes, and `Reveal()` unscrambles them at runtime. Because the routine needs no user input, you can recover the flag without running the program. Reading the byte array and repeating the arithmetic is enough. Alternatively, a debugger such as dnSpy would show the expected string at the comparison in `Main`.
