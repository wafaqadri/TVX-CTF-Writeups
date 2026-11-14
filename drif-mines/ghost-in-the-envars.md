
# Ghost In the Envars
# CTF Memory Forensics Write-Up: `memory.raw`

## Challenge Overview
* **Category:** Digital Forensics (Memory Forensics)
* **Artifact:** `memory.raw` (Windows 10 x64 RAM dump)
* **Tools Used:** Volatility 3 (`v2.28.2`), `strings`, `grep`
* **Flag Format:** `VTX{...}`

---

## Step 1: Initial Triage & OS Identification
First, we verify that `memory.raw` is a volatile memory image rather than a bootable disk image, then identify the operating system profile using **Volatility 3**:

```bash
vol -f memory.raw windows.info
```

* **OS Version:** Windows 10 (Build `19041`, 64-bit)
* **Architecture:** x64 (`WindowsIntel32e`)
* **Capture Time:** `2026-11-11 20:03:24 UTC`

---

## Step 2: Process Enumeration
Next, we list active processes while filtering out noisy system `svchost.exe` instances to spot user-launched applications:

```bash
vol -f memory.raw windows.pslist | grep -v "svchost.exe"
```

### Key Findings
Near the end of the process timeline, several terminal sessions were spawned by `explorer.exe` (`PID 5072`):
* **`PID 6708`** — `powershell.exe` (Interactive parent PowerShell session)
* **`PID 7208`** — `powershell.exe` (Child process of `6708`)
* **`PID 7388`** — `powershell.exe` (Child process of `6708`)
* **`PID 8032`** — `cmd.exe` (Spawned at `19:51:53 UTC`)

---

## Step 3: Inspecting Command-Line Arguments & Console History
We inspect the command-line arguments passed to the PowerShell and Command Prompt instances:

```bash
vol -f memory.raw windows.cmdline --pid 6708 7208 7388 8032
```

### Decoy Flag Discovery
PIDs `7208` and `7388` executed a Base64-encoded UTF-16LE command:
```powershell
powershell.exe -WindowStyle Hidden -EncodedCommand UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAOAA2ADQAMAAwADsAIAAjACAAVABWAFgAewBkAG8AbgB0AF8AdQBzAGUAXwBhAGkAXwBmAG8AcgBfAHMAbwBsAHYAaQBuAGcAfQA=
```
Decoding this payload reveals a decoy comment placed by the challenge author:
```powershell
Start-Sleep -Seconds 86400; # TVX{dont_use_ai_for_solving}
```

### Console Command History (`cmdscan`)
Checking `cmdscan` reveals a registry modification executed inside `cmd.exe` (`PID 8032` / `conhost.exe` `PID 6428`):
```bash
vol -f memory.raw windows.cmdscan
```
```cmd
reg add "HKLM\SOFTWARE\Challenge" /v "AuthKey" /t REG_SZ /d "K3rn3l_Auth_K3y_99" /f
```

---

## Step 4: Dumping Interactive PowerShell Memory (`PID 6708`)
Because interactive PowerShell sessions manage command buffers via `PSReadLine` rather than `conhost.exe` command buckets, the session's variables and commands reside directly inside the `powershell.exe` (`PID 6708`) process memory.

1. **Dump the memory map of `PID 6708`:**
   ```bash
   mkdir -p ps6708
   vol -o ps6708 -f memory.raw windows.memmap --pid 6708 --dump
   ```

2. **Extract UTF-16LE (Windows Unicode) strings matching the flag pattern:**
   ```bash
   strings -e l ps6708/*.dmp | grep -oE "[A-Z]{2,5}\{[^}]+\}" | sort -u
   ```

---

## Conclusion
By isolating the interactive parent PowerShell process (`PID 6708`), dumping its virtual memory space with `windows.memmap`, and filtering for UTF-16LE strings (`strings -e l`), we bypassed the decoy `TVX{...}` processes and recovered the real `VTX{...}` flag directly from RAM.

# Flag
```
TVX{m3m0ry_4rt_n0t_pr0mpt_2026}
```
