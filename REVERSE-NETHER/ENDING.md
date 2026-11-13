# TVX CTF – Ending (Reverse Engineering, 500 pts)

**Author:** NotSaad
**Description:** "What has beginnings, has endings, and what has code, has flags."
**File:** `Ending.exe`
**Flag:** `TVX{S0me_1nt2r2st1ng_t2xt_h2r2}`

## 1. Recon

```
$ file Ending.exe
PE32 executable (console) Intel 80386 Mono/.Net assembly
```

It is a tiny (10 KB) .NET assembly. The metadata shows a class `Program` with the methods `Unpack`, `ReadWord`, `Main` and a rotate helper. The `#US` heap holds three strings:

- `flag> `, `rejected` and `accepted`
- one long base64 string starting with `H4sI`, which is the gzip magic in base64

The program asks for a flag and prints accepted or rejected. The base64 blob looks like the checker's payload.

## 2. Reading the IL

There was no decompiler in my environment, so I wrote a small IL disassembler in Python and read the five method bodies.

**`Main`**
```
expected = Run();                 // byte[31] -> ASCII string
Console.Write("flag> ");
input = Console.ReadLine() ?? "";
Console.WriteLine(input == expected ? "accepted" : "rejected");
```

The expected flag is never stored as plaintext. It is generated at runtime by `Run()`, so I only needed to reproduce `Run()`.

**Stage 1 – `Unpack()`**
```
data = GunzipBase64(blob)                  // 958 bytes
for i in range(len(data)):
    data[i] = ror8(data[i], i % 5 + 1) ^ ((199 + i*91) & 0xFF)
```
`ror8(a, b)` is a rotate-right of a byte: `(a >> (b&31)) | (a << ((8-b)&31))`, truncated to a byte.

This gives a bytecode program for a custom virtual machine.

**Stage 2 – the VM (`Run`)**

The VM has 4 16-bit registers `r0..r3`, 128 16-bit words of memory and a 31-byte output buffer. `ReadWord` reads a little-endian 16-bit immediate.

| Opcode | Instruction | Effect |
|---|---|---|
| 0x10 | `mov r, imm16` | `r = imm` |
| 0x11 | `xor r, imm16` | `r ^= imm` |
| 0x12 | `add r, imm16` | `r += imm` |
| 0x13 | `rol r, n` | 16-bit rotate left |
| 0x14 | `ld r, m` | `r = mem[m]` |
| 0x15 | `st m, r` | `mem[m] = r` |
| 0x16 | `xorr a, b` | `ra ^= rb` |
| 0x17 | `addr a, b` | `ra += rb` |
| 0x18 | `subr a, b` | `ra -= rb` |
| 0x19 | `not r` | `r = ~r` |
| 0x1a | `ldx a, b` | `ra = mem[rb]` |
| 0x30 | `jnz r, off` | `if r != 0: pc += (sbyte)off`, relative to the byte after the offset |
| 0x31 | `jmp off` | `pc = addr_of_offset_byte + (sbyte)off` |
| 0x40 | `out r` | `output[n++] = (byte)r` |
| 0xFF | `halt` | stop the VM |

Any other opcode throws.

## 3. The VM program

The first part of the program fills `mem[]` with constants: 31 encrypted words at `mem[0..30]` and three lookup tables at `mem[0x20..]`, `mem[0x40..]` and `mem[0x60..]`. The last 90 bytes are the actual decode loop:

```
mov r0, 0          ; i = 0
mov r1, 0x4B       ; running key
loop:
  ldx r2, r0       ; r2 = mem[i]            (encrypted word)
  mov r3, 0x40 ; addr r3, r0 ; ldx r3, r3
  xorr r2, r3      ; r2 ^= mem[0x40+i]
  rol  r2, 5
  mov r3, 0x20 ; addr r3, r0 ; ldx r3, r3
  subr r2, r3      ; r2 -= mem[0x20+i]
  xorr r2, r1      ; r2 ^= key
  out  r2          ; flag[i] = (byte) r2
  mov r3, 0x60 ; addr r3, r0 ; ldx r3, r3
  xorr r1, r3      ; key ^= mem[0x60+i]
  rol  r1, 3       ; key = rol16(key, 3)
  add  r0, 1
  mov r3, 31 ; subr r3, r0
  jnz  r3, loop    ; repeat for i = 0..30
halt
```

No input is read anywhere in the VM, so the output is a constant. The "check" in `Main` is just a string comparison against that constant.

## 4. Solver

```python
import re, base64, gzip

d = open('Ending.exe', 'rb').read()
i = d.find('H4sI'.encode('utf-16le'))          # the string lives in the UTF-16 #US heap
j = i
while d[j+1] == 0 and 32 <= d[j] < 127:
    j += 2
blob = gzip.decompress(base64.b64decode(d[i:j].decode('utf-16le')))

ror8 = lambda a, b: ((a >> (b & 31)) | (a << ((8 - b) & 31))) & 255
prog = bytes((ror8(blob[k], k % 5 + 1) ^ ((199 + k*91) & 255)) & 255
             for k in range(len(blob)))

regs, mem, out, pc = [0]*4, [0]*128, [], 0
def rb():
    global pc; v = prog[pc]; pc += 1; return v
def rw():
    global pc; v = prog[pc] | prog[pc+1] << 8; pc += 2; return v
sb = lambda x: x - 256 if x > 127 else x

while (op := rb()) != 0xFF:
    if   op == 0x10: a = rb(); regs[a] = rw()
    elif op == 0x11: a = rb(); regs[a] ^= rw()
    elif op == 0x12: a = rb(); regs[a] = (regs[a] + rw()) & 0xFFFF
    elif op == 0x13:
        a = rb(); n = rb(); v = regs[a]
        regs[a] = ((v << (n & 31)) | (v >> ((16 - n) & 31))) & 0xFFFF
    elif op == 0x14: a = rb(); b = rb(); regs[a] = mem[b]
    elif op == 0x15: a = rb(); b = rb(); mem[a] = regs[b]
    elif op == 0x16: a = rb(); b = rb(); regs[a] ^= regs[b]
    elif op == 0x17: a = rb(); b = rb(); regs[a] = (regs[a] + regs[b]) & 0xFFFF
    elif op == 0x18: a = rb(); b = rb(); regs[a] = (regs[a] - regs[b]) & 0xFFFF
    elif op == 0x19: a = rb(); regs[a] = ~regs[a] & 0xFFFF
    elif op == 0x1a: a = rb(); b = rb(); regs[a] = mem[regs[b]]
    elif op == 0x30:
        a = rb(); off = sb(rb())
        if regs[a]: pc += off
    elif op == 0x31:
        base = pc; pc = base + sb(rb())
    elif op == 0x40: a = rb(); out.append(regs[a] & 255)
    else: raise Exception(hex(op))

print(bytes(out).decode())
```

Output (906 VM steps):

```
TVX{S0me_1nt2r2st1ng_t2xt_h2r2}
```

## 5. Notes

- The VM output starts with `TVX{` and ends with `}`, and the text in between is readable. That makes a transcription error in my emulator unlikely.
- I could not run the real `.exe` (no .NET runtime in my sandbox), so the flag was derived statically. If the platform rejects it, the first thing to try is swapping the `2`s for `3`s.
- The flag text reads like "Some interesting text here" with leetspeak applied.

## Flag

```
TVX{S0me_1nt2r2st1ng_t2xt_h2r2}
```
