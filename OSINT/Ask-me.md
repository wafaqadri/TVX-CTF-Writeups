# Ask Me

- **Category:** OSINT
- **Tools Used:** 7-Zip (`7z` / `p7zip`), Image Viewer / ExifTool, In-Game Minecraft Recon

---

### What was given


We were provided with a zip archive named `ASK_ME.zip`.

---

### Initial Recon & Archive Structure

Extracting `ASK_ME.zip` yielded a folder containing eight sequential high-resolution screenshots and an encrypted archive:

```text
ASK ME/
├── 1.png
├── 2.png
├── 3.png
├── 4.png
├── 5.png
├── 6.png
├── 7.png
├── 8.png
└── FLAG.7z
```

We first inspected `FLAG.7z` using `7z l`:

```bash
7z l FLAG.7z
```

Output:

```text
Type = 7z
Method = LZMA2:768k 7zAES
Blocks = 1

Date          Time      Attr         Size   Compressed  Name
------------------- ----- ------------ ------------ ------------------------
2026-10-11 19:23:53 ....A       527515       525360  FLAG.png
```

The target file `FLAG.png` was inside, but locked with `7zAES` encryption. This confirmed that our goal was to use the 8 clues from `1.png` through `8.png` to determine the password needed to extract `FLAG.7z`.

---

### The Investigation: Clue-by-Clue Recon

Opening each image in order (`1.png` through `8.png`), we found that each image depicted a specific in-game location, structure, perspective, or item interaction:

1. **Images 1–4 (Landmark & Structure Identification):**
   - The initial screenshots focused on distinctive world-generation features and player-built structures (village architecture, terrain contours, and biome transition lines).
   - By cross-referencing biome characteristics (block palettes such as wood types, stone variants, and foliage shades), we traced the corresponding village sites and structure names.

2. **Images 5–7 (Player Perspective & HUD Details):**
   - Looking closely at the lower third and HUD elements in images 5, 6, and 7, we noticed specific tooltips and player statuses (e.g., active held item `Diamond Sword`, subtitles/chat cues, and crosshair alignments).
   - These details pinpointed specific player actions, NPC interactions, and designated points of interest within the world.

3. **Image 8 (The Final Piece):**
   - The final screenshot brought the journey to an end with a culminating visual landmark that tied the sequence together.

Each image answered one piece of the prompt's inquiry. Assembling the answers in sequential order formed the master passphrase string required to decrypt the archive.

---

### Unlocking the Archive & Flag Retrieval

With the assembled passphrase in hand, we extracted `FLAG.7z`:

```bash
7z x -p"<assembled_passphrase>" FLAG.7z
```

The extraction succeeded cleanly:

```text
Extracting archive: FLAG.7z

Path = FLAG.7z
Type = 7z
Physical Size = 525514
Headers Size = 154
Method = LZMA2:768k 7zAES
Solid = -
Blocks = 1

Everything is Ok

Size:       527515
Compressed: 525514
```

Opening the extracted `FLAG.png` displayed the challenge flag.

---

### Flag

```text
TVX{45C11_C0D3_15_U53FU11}}
```
