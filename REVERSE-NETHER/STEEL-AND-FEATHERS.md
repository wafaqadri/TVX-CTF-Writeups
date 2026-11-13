# Steel and Feathers: Reverse Engineering Writeup

| | |
|---|---|
| **Category** | Reverse Engineering |
| **Points** | 100 |
| **File** | `SteelAndFeathers.exe` |
| **Flag** | `TVX{Congratulations_You_Know_Some_ball}` |

## Overview

The challenge file is `SteelAndFeathers.exe`, a .NET console program. It prompts `flag> ` and prints `accepted` or `rejected`.

## 1. Triage

`file` shows a PE32 .NET assembly. The `#US` (user strings) heap has only four entries:

- `flag> `
- `rejected`
- `accepted`
- one long base64 string starting with `H4sI`, which is the base64 form of the gzip header

I had no decompiler, so I parsed the metadata and disassembled the IL by hand. There are four methods: `Ror`, `Unpack`, `Run` and `Main`.

## 2. Main

`Main` calls `Run()` to get an expected string and reads your input. It prints `accepted` only if the two match exactly. Your input is never used to compute anything, so the flag is whatever `Run()` returns.

## 3. Unpack

`Unpack` base64-decodes the blob, gunzips it, and decrypts each byte in place:

```
b[i] = ROR8(b[i], i % 7 + 1) ^ ((23 + i*41) & 0xFF)
```

The result is 1,288 bytes of bytecode for a custom stack VM.

## 4. The VM in Run

`Run` interprets the bytecode. It uses an integer stack, a 256-byte memory with `mem[250] = 45`, and an output list.

| Opcode | Operation |
|---|---|
| `0x10` | push the next byte |
| `0x20` | pop a, b; push `(a ^ b) & 255` |
| `0x30` | pop a, b; push `(a + b) & 255` |
| `0x40` | pop a; rotate left by the next byte; push |
| `0x51` | pop and discard |
| `0x60` | pop into `mem[next byte]` |
| `0x61` | push `mem[next byte]` |
| `0x70` | pop and append to the output |
| `0xFF` | halt |

After halting, the output bytes are decoded as ASCII to give the expected string. The VM takes no user input, so its output is the same every run.

## 5. Solve

I decrypted the bytecode and emulated the VM in Python:

```python
def ror(x, n):
    return ((x >> (n & 31)) | (x << ((8 - n) & 31))) & 255

for i in range(len(b)):
    b[i] = (ror(b[i], i % 7 + 1) ^ ((23 + i * 41) & 255)) & 255

mem = [0] * 256
mem[250] = 45
st, out, pc = [], [], 0

while True:
    op = b[pc]; pc += 1
    if op == 255:
        break
    if op == 16:
        st.append(b[pc]); pc += 1
    elif op == 32:
        st.append((st.pop() ^ st.pop()) & 255)
    elif op == 48:
        st.append((st.pop() + st.pop()) & 255)
    elif op == 64:
        a = st.pop(); n = b[pc]; pc += 1
        st.append(((a << (n & 31)) | (a >> ((8 - n) & 31))) & 255)
    elif op == 81:
        st.pop()
    elif op == 96:
        mem[b[pc]] = st.pop() & 255; pc += 1
    elif op == 97:
        st.append(mem[b[pc]]); pc += 1
    elif op == 112:
        out.append(st.pop() & 255)

print(bytes(out))
```

Output:

```
TVX{Congratulations_You_Know_Some_ball}
```

## Takeaway

The expected flag is computed at startup by an encrypted VM that takes no input. Decrypting the bytecode and emulating the VM recovers it. A debugger such as dnSpy would give the same result by breaking at the string comparison in `Main`.
