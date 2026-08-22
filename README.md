# Wiimms ISO Tools

    ****************************************
    *    __            __ _ ___________    *
    *    \ \          / /| |____   ____|   *
    *     \ \        / / | |    | |        *
    *      \ \  /\  / /  | |    | |        *
    *       \ \/  \/ /   | |    | |        *
    *        \  /\  /    | |    | |        *
    *         \/  \/     |_|    |_|        *
    *                                      *
    *           Wiimms ISO Tools           *
    *         https://wit.wiimm.de/        *
    *                                      *
    ****************************************

»Wiimms ISO Tools« is a set of command line tools to extract,
modify and create Wii and GameCube ISO images and WBFS containers.
Development started in 2009.
See https://wit.wiimm.de/ for more details, documentation and downloads.

## About this fork

`wiimms-iso-tools-plus` is a fork of
[Wiimm/wiimms-iso-tools](https://github.com/Wiimm/wiimms-iso-tools) that widens
the range of container formats WIT understands, so that a single tool can open
them instead of shelling out to a different program per format.  Upstream
behaviour is unchanged; everything here is additive.

### Format & compression support

Wii and GameCube disc images keep going through WIT's normal commands. The
other containers have nothing in common with a Wii disc, so instead of forcing
them into that pipeline they get their own four commands — `XINFO`, `XEXTRACT`,
`XCREATE` and `XCONVERT` — which never touch the disc code.

| Format | Category | Decode | Encode | Notes |
|---|---|---|---|---|
| ISO / WDF / CISO / WBFS / WIA / GCZ / FST | Disc image | ✅ | ✅ | Upstream WIT commands |
| RVZ | Disc image | ✅ | ⛔ | Dolphin's WIA derivative; all normal WIT read commands; Zstandard, sub-2 MiB chunks and losslessly packed pseudo-random padding |
| WUX / WUD | Disc image | ✅ | ✅ | Wii U; container conversion via `XINFO` and `XCONVERT`; file-system unpacking needs the per-disc key and is not implemented |
| NDS | Disc image | ✅ | ✅ | DS/DSi; full file system, both CPU binaries, overlays and banner via `XINFO`, `XEXTRACT` and `XCREATE` |
| WAD | Installable title | ✅ | ✅ | Wii; contents decrypted and re-encrypted via `XINFO`, `XEXTRACT` and `XCREATE`; TMD re-signed only when something changed |
| 3DS CCI / CIA | Disc/package | 🔍 | ⛔ | Identified by `XINFO`, not yet unpacked |
| Switch XCI / NSP | Disc/package | 🔍 | ⛔ | Identified by `XINFO`, not yet unpacked |
| NKit (`.nkit.iso`) | Disc image | ✅ | ⛔ | Restore via `XCONVERT`; Wii is byte exact against the header CRC32; GameCube is implemented but still unverified against a real sample |

✅ supported · 🟡 partial · 🔍 detected, not decoded · ⛔ not implemented

### RVZ

RVZ images are detected automatically wherever a WIA is accepted — `wit VERIFY`,
`wit DUMP`, `wit EXTRACT`, `wit COPY` and friends all work:

```
wit VERIFY  game.rvz
wit COPY --iso --raw game.rvz --dest game.iso
wit EXTRACT game.rvz --dest game.d/
```

Reading RVZ needs Zstandard; `./setup.sh` detects `zstd.h` automatically and the
build falls back to a clear "not supported" error if it is missing.  Writing RVZ
is not implemented — use `--wia` for a compressed output format.

The implementation follows Dolphin's
[WiaAndRvz.md](https://github.com/dolphin-emu/dolphin/blob/master/docs/WiaAndRvz.md).
It has been checked against Redump RVZ images for both Wii (every partition hash
including H3 verifies, so the decoded image is byte-identical to the original
disc) and GameCube.

### Wii U (WUX / WUD)

WUX is a sparse container: the payload sectors are stored verbatim, but
identical sectors are stored once and referenced repeatedly, which is what
makes a 25 GB disc image manageable.  Converting between the two encodings
needs no key, because it does not touch the payload at all:

```
wit XCONVERT game.wux game.wud
wit XCONVERT game.wud game.wux
wit XINFO    game.wux
```

The round trip is byte-identical in both directions, including images whose
size is not a multiple of the sector size.  Reading has been checked against a
retail Redump WUX; writing dedupes with a hash table and confirms every
candidate by comparing the stored bytes, so a hash collision can cost time but
never corrupt the output.

### Nintendo DS

```
wit XINFO    game.nds
wit XEXTRACT game.nds game.d/
wit XCREATE  game.d/ new.nds
```

`XEXTRACT` writes the header, both CPU binaries (plus the nitro footer when the
cartridge has one), the overlay tables, the banner, the overlays as
`overlay/arm9_NNNN.bin`, and the file system under `data/`.  `XCREATE` rebuilds
the FNT and FAT from the directory, so files may be added, removed or resized.

Rebuilding assigns directory ids depth first and orders names case
insensitively, which is what the original build tools did: repacking a retail
cartridge unchanged reproduces its FNT byte for byte and every file keeps its
exact size and content.  The image is not byte-identical, because retail images
place file data in a build specific physical order and often leave a large gap
before it; the rebuilt image is compact and in file id order.

### Wii WAD

```
wit XINFO    title.wad
wit XEXTRACT title.wad title.d/
wit XCREATE  title.d/ new.wad
```

Contents are decrypted with the title key from the ticket and written as
`<content id>.app`; each one is checked against its TMD hash, which is the only
thing that can tell you the key was right.  `XCREATE` re-encrypts them, updates
the TMD sizes and hashes, and fake signs the TMD — but only if a content
actually changed, so extracting and repacking an untouched WAD gives back the
original file byte for byte and a genuinely signed title keeps its signature.

### NKit

NKit shrinks a GameCube/Wii ISO by throwing away the disc's *junk data* — the
pseudo-random padding the SDK writes between files — and keeping just enough
per-gap metadata to regenerate it later.  `XCONVERT` restores the original
image:

```
wit XCONVERT game.nkit.iso game.iso
```

GameCube and Wii images are told apart automatically by the disc magic the NKit
header still carries.  The Wii path rebuilds each partition's file system,
regenerates the junk, re-derives the whole H0–H3 hash tree and re-encrypts every
group with the ticket's title key, then checks the finished image against the
CRC32 stored in the NKit header — so a successful restore is a byte exact one,
not merely a plausible one.  Restoring an image whose update partition was
removed at conversion time is refused, because putting it back needs a copy of
that partition this tool has no source for.

Note that `.nkit.gcz` — the form most NKit images are distributed in — is an
NKit stream wrapped in Dolphin's GCZ container, and `wit` cannot unwrap it.
`wit`'s GCZ reader decompresses the container and then validates the payload as
a GC/Wii disc, which an NKit stream deliberately is not, so it is rejected with
`WRONG FILE TYPE / GameCube or Wii ISO image expected` before any copy happens;
no flag (`--raw` included) changes that, because the rejection is in source
detection, not in the copy.  Strip the GCZ layer with any plain GCZ
decompressor first, then convert the `.nkit.iso`:

```
gcz-decompress game.nkit.gcz game.nkit.iso   # any GCZ tool; Dolphin's format, zlib blocks
wit XCONVERT   game.nkit.iso  game.iso
wit VERIFY     game.iso
```

<dl>
<dt>Note:</dt>
<dd>
This is only a copy of Wiimms private SVN repository.
Only official releases are exported to <i>GitHub</i>.
Therefor merge requests can not imported directly and must be included manually.
</dd>

<dt>License:</dt>
<dd>
This program is free software;
you can redistribute it and/or modify it under the terms of the
GNU General Public License as published by the Free Software Foundation;
either version 2 of the License, or (at your option) any later version.

See file project/gpl-2.0.txt or http://www.gnu.org/licenses/gpl-2.0.txt for details.
</dd>
</dl>

*Wiimm, 2020-08-22*
