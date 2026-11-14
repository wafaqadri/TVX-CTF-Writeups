# TraceVX CTF — Comprehensive Forensic Writeup

This document provides a detailed technical writeup and investigation walk-through for the **TraceVX** forensic CTF challenge. The investigation covers initial compromise vectors, payload extraction, persistence mechanisms, command-and-control (C2) infrastructure analysis, and telemetry-based exfiltration quantification.

---

## Challenge Overview & Final Answers

| Question | Objective | Answer |
| :--- | :--- | :--- |
| **Q1** | Compromised User Account | `Ahmed` |
| **Q2** | Phishing / Initial Delivery URL | `login-microsoftonline.secure-verify.cc` |
| **Q3** | Exact Compromise Timestamp | `2026-09-17T14:31:51Z` |
| **Q4** | Initial Execution Binary | `powershell.exe` |
| **Q5** | Staged Script / Path | `stage.cmdline` |
| **Q6** | Primary Dropped Malware Executable | `Navigator.exe` |
| **Q7** | SHA-256 Hash of Navigator.exe | `411ff3850c2ed96028e4f39184fed07c3fdacf56936e03581ce479c6ed7ab8cd` |
| **Q8** | Scheduled Task Persistence Name | `TraceTelemetry` |
| **Q9** | Attacker C2 Endpoint (IP:PORT) | `185.192.48.239:443` |
| **Q10** | Total Outbound Exfiltrated Bytes | `8388608` |

---

## Detailed Investigation Walkthrough

### Phase 1: Initial Access & Compromise Vector (Q1 – Q4)
1. **User Attribution (Q1):** 
   Reviewing user profile folders, registry hives, and NTFS Master File Table (`$MFT`) logs extracted from the container pointed directly to activity under the user profile belonging to **`Ahmed`**.
2. **Delivery Vector (Q2):** 
   PowerShell Script Block logs (Event ID 4104) captured a malicious `Invoke-WebRequest` (IWR) command downloading staging scripts from a lookalike domain: 
   `login-microsoftonline.secure-verify.cc`.
3. **Execution Timestamp & Binary (Q3 & Q4):** 
   Correlating the `$MFT` timeline entries with PowerShell process creation events showed that the execution sequence initiated on **`2026-09-17T14:31:51Z`** via **`powershell.exe`**.

### Phase 2: Staging & Malware Identification (Q5 – Q7)
1. **Staged Configuration (Q5):** 
   The initial PowerShell script created a temporary file used for staging execution parameters:
   `C:\Users\Ahmed\AppData\Local\Temp\k29x8\stage.cmdline`.
2. **Payload Extraction (Q6 & Q7):** 
   Subsequent staging actions dropped the primary backdoor into `C:\ProgramData\Microsoft\UpdateCache\` named **`Navigator.exe`**. Extracting its binary and running a cryptographic hash check yielded the SHA-256 sum:
   `411ff3850c2ed96028e4f39184fed07c3fdacf56936e03581ce479c6ed7ab8cd`.

### Phase 3: Persistence & Infrastructure Analysis (Q8 – Q9)
1. **Persistence Mechanism (Q8):** 
   Reviewing the PowerShell script block logs uncovered the explicit `schtasks` command executed by the attacker to maintain persistence:
   ```powershell
   schtasks /create /tn TraceTelemetry
   ```
   Thus, the scheduled task name is **`TraceTelemetry`**.
2. **C2 Infrastructure (Q9):** 
   Strings extraction from the carved PE binary (`Navigator.exe`) revealed hardcoded internal metadata pointing to the C2 endpoint operating over HTTPS:
   `185.192.48.239:443`.

### Phase 4: Exfiltration Quantification (Q10)
1. **Network Usage Telemetry Query:** 
   Querying the carved network telemetry database (`SRUDB.sqlite` -> `network_usage` table) for outbound connections to the C2 IP (`185.192.48.239`) associated with the malicious toolset (`Navigator.exe` and `AdaptConductor.exe`) returned the following records for user Ahmed:
   * **Navigator.exe** (Outbound): `5,242,880` bytes
   * **AdaptConductor.exe** (Outbound): `3,145,728` bytes
2. **Final Calculation:**
   $$\text{Total Exfiltrated Bytes} = 5,242,880 + 3,145,728 = \mathbf{8,388,608}$$
