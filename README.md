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

### Format support

| Format | Read | Write | Notes |
|---|---|---|---|
| ISO / WDF / CISO / WBFS / WIA / GCZ / FST | yes | yes | upstream |
| **RVZ** | **yes** | no | Dolphin's WIA derivative: Zstandard, sub-2 MiB chunks and losslessly packed pseudo-random padding |
| NKit | planned | planned | |
| WUX / WUD (Wii U) | planned | planned | |
| NDS / 3DS / Switch / WAD | planned | planned | |

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
