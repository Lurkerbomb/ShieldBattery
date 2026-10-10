# Replay analyzer prototype

A headless OpenBW/BWAPI executable that simulates Remastered replays and writes
frame-indexed NDJSON. This is a developer prototype; it is not connected to the
Electron app or included in its installer.

The core is adapted from starcraft-masters' native replay simulator. The build
fetches OpenBW at `8265ec449b903e0752060a00ed5f930a3656bf00` and OpenBW BWAPI at
`48124ba8ed1b4d52b3dfd52acbaf34afb9a37fe2`, applies the adjacent SCR patches,
and verifies the revisions, patched file contents, and changed-file sets at
configuration and build time. Dependencies live inside the build directory.
Do not edit those checkouts: update the committed patches and use a fresh build
directory when changing them.

The patches add Remastered container/zlib/action decoding, extended map strings,
loose tileset loading, simulation fixes, event capture, and fidelity diagnostics.
The original patch also contains the optional deterministic game UID hook; the
analyzer does not enable it. Training observations and the melee harness are
not built here.

## Build

Requirements: Git, CMake 3.24+, a C++17 compiler, zlib development files, and
Python 3 for tests. The first configure needs network access to fetch the two
pinned source repositories. OpenBW, BWAPI, and BWAPILIB are linked statically.

On Windows, from a Visual Studio 2022 developer PowerShell with vcpkg installed:

```powershell
vcpkg install zlib:x64-windows-static-md
cmake -S native/replay-analyzer -B build/replay-analyzer -A x64 `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static-md
cmake --build build/replay-analyzer --config Release --parallel 4
ctest --test-dir build/replay-analyzer -C Release --output-on-failure
```

On macOS or Linux with zlib installed:

```sh
cmake -S native/replay-analyzer -B build/replay-analyzer -DCMAKE_BUILD_TYPE=Release
cmake --build build/replay-analyzer --parallel 4
ctest --test-dir build/replay-analyzer --output-on-failure
```

The executable is `build/replay-analyzer/bin/sb-replay-analyzer` (`.exe` on
Windows). `--help` and `--version` do not load StarCraft data. The Windows CI
workflow builds and tests the executable without proprietary game assets;
it does not establish full-game simulation parity.

## Analyze a replay

Provide your own local StarCraft game data:

- `OPENBW_MPQ_PATH`: a directory containing `StarDat.mpq`, `BrooDat.mpq`, and
  `Patch_rt.mpq` from classic StarCraft. A Remastered CASC directory cannot be
  used directly.
- `OPENBW_OVERRIDE_PATH`: extracted Remastered `.cv5` and `.vf4` files for
  `badlands`, `platform`, `install`, `ashworld`, `jungle`, `Desert`, `Ice`, and
  `Twilight`, either flat or inside `Tileset/`. Classic tilesets can silently
  corrupt modern map terrain. The executable checks presence and nonzero size;
  it does not authenticate the provenance or version of these files.

```powershell
$env:OPENBW_MPQ_PATH = 'C:\StarCraftData\mpq'
$env:OPENBW_OVERRIDE_PATH = 'C:\StarCraftData\tilesets'
.\build\replay-analyzer\bin\sb-replay-analyzer.exe `
  --replay 'C:\Replays\game.rep' --output 'C:\Replays\game.ndjson'
```

```sh
OPENBW_MPQ_PATH=/path/to/mpqs OPENBW_OVERRIDE_PATH=/path/to/tilesets \
  build/replay-analyzer/bin/sb-replay-analyzer \
  --replay /path/to/game.rep --output /path/to/game.ndjson
```

Use trusted developer replays for this prototype. It parses native replay/map
structures in the calling user's process. The inherited Linux resource limits
and syscall filter do not provide Windows or macOS isolation. Before exposing
analysis through Electron, add the preflight and process isolation appropriate
to that platform, cancellation, resource/output bounds, and reliable job cleanup.
Do not run simulation inside the renderer or the injected game DLL.

## Output contract

`--interval-frames N` controls periodic snapshots (default 24, range 1–1440).
Events retain their simulation frame independently of this sampling interval.
Output is an NDJSON file; stdout/stderr may contain engine diagnostics and are
not the event transport. Exit status is 0 for success, 1 for simulation failure,
and 2 for argument or input validation failure. An interrupted or failed run may
leave a partial file. Consumers must require success and a final `complete`
record before accepting an artifact.

| Record | Content |
| --- | --- |
| `metadata` | Backend version, players, map, frame count, capabilities, base sites |
| `snapshot` | Player economy, supply, production, upgrades, and army state |
| `unitEvent`, `playerEvent` | Unit lifecycle and player departures |
| `unitPositionSnapshot`, `armyPosition`, `territorySnapshot` | Spatial evidence |
| `damageEvent`, `spellCastEvent`, `statusEvent` | Combat, casts, and statuses |
| `resourceDelivery` | Resource return events |
| `gameResult` | Result derived by the simulator |
| `diagnostics` | Fidelity counters, tag resolution, dropped actions, pool usage |
| `complete` | Final simulated frame |

Simulation completion alone is not proof of fidelity. Preserve `diagnostics`
and add fidelity grading before presenting analytics as trustworthy. BWAPI unit
IDs are local to each execution; do not compare raw IDs between platforms/runs.
The current output is a prototype contract inherited from the source simulator,
not yet a stable ShieldBattery IPC schema.

## Validation and distribution

CTest exercises synthetic Remastered compressed blocks (including CRC and
truncation failures), the unframed replay field, and executable input validation.
Full validation requires the same real replay and game data on Mac and Windows,
comparison of snapshots/events after normalizing execution-local unit IDs, and
review of the fidelity diagnostics. Do not commit game archives, extracted
Blizzard assets, or private player replays.

Keep dependency licensing and source provenance intact. OpenBW BWAPI's pinned
checkout includes LGPL-3.0 license files; the pinned OpenBW root has no license
file. Resolve OpenBW redistribution terms and the imported simulator's license
before packaging a public installer. The CI executable is a developer test
artifact, not a released ShieldBattery binary.
