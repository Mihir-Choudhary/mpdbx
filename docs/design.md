# mpdbx — MpEngineDB Explorer v2 (Rust) — Design Spec

Date: 2026-11-09 · rev 2

## 1. Purpose

A single small Windows executable (`mpdbx.exe`) that turns a copied Microsoft Defender
`Scans\mpenginedb.db` (+ `-wal`) and `Scans\History\{Store,Results}` into **correlated, decoded
forensic records** — locations, files, process runs, hashes, events and host context — not a table browser.

Users and priority:
1. Deep-dive on one host (GUI).
2. Reporting (HTML/CSV/JSON of tagged rows + summary).
3. Many hosts / snapshot comparison (headless CLI in the same exe).

Success criteria:
- Opens a reference copy (~3.5k BPI rows, ≤ 600 WAL frames) and shows the correlated timeline in < 3 s.
- Every displayed value is decoded (time, FileRef, SID, enum, JSON) with the raw value one click away.
- Every derived record shows its provenance and every link shows its rule and strength.
- On intact reference evidence, per-table row counts and WAL-only row sets equal the Python v1 oracle.
- Release exe ≤ 8,388,608 bytes (x86_64-pc-windows-msvc), no installer, no runtime dependencies.
- Writes nothing except files the user explicitly exports or saves.

## 2. Scope

**v1 inputs**
- `mpenginedb.db` (required), `mpenginedb.db-wal` (auto-detected beside it), optional `mpengine.dll` (key fallback).
- `Scans\History\Store\*`, `Scans\History\Results\{Quick,Resource}\*` (auto-detected when a `Scans` folder is opened).
- Optional FileRef resolver: an MFTECmd `$MFT` CSV (`EntryNumber, SequenceNumber, ParentPath, FileName`). Because the CSV
  carries no volume serial, the user binds it to one VSN (picked from the VSNs present in `FileHashes`) when loading it.

**Non-goals for v1**: live acquisition (raw NTFS / VSS), MPLog, DetectionHistory, Quarantine, EVTX, mpcache-*.bin,
editing, plugins, any network access. The README documents acquiring DB, WAL and History **from one VSS snapshot**
(`esentutl /y <src> /d <dst> /vss` per file, or a single shadow copy) and why a DB/WAL pair taken at different moments is
inconsistent.

## 3. Format reference (validated in this research; NOTES R9, DEEPDIVE DD-2/DD-2b)

| Item | Fact |
|---|---|
| RC4 use | Every encrypted region uses a **fresh keystream** (KSA reused, PRGA restarted at byte 0): per DB page, per WAL frame payload, per Store/Results region. |
| Key | Defender's fixed 256-byte mpengine RC4 key (embedded). Fallback: search `mpengine.dll` for `mov r8d,100h; lea rdx,[rip+key]` candidates and accept the one whose RC4 of page-1 bytes 0–15 equals `SQLite format 3\0`. |
| DB page 1 | bytes 0–15 = RC4(`SQLite format 3\0`) (key check); 16–23 plaintext; 24..end = RC4 fresh keystream (keystream byte 0 ↔ file byte 24). Page size = BE u16 @16, value 1 = 65536; must be a power of two in 512..65536 and the file length a multiple of it (trailing partial page → warning, ignored). |
| DB pages ≥ 2 | RC4 fresh keystream over the whole page. |
| WAL header | 32 bytes plaintext: magic (0x377f0682 LE-checksum / 0x377f0683 BE-checksum), version 3007000, page size (u32, real size incl. 65536, must equal the DB's), checkpoint seq, salt1, salt2, checksum over bytes 0–23. |
| WAL frames | 24-byte plaintext header (page no, commit db-size, salt1, salt2, checksum1, checksum2) + payload encrypted like a DB page (page no 1 → page-1 rule). **Stored checksums cover the encrypted payload** (verified: chains valid 68/68 … 570/570 on all 7 reference WALs; 0 match over decrypted bytes). |
| WAL replay | SQLite semantics on the **original encrypted chain**: header checksum must validate; walk frames while salts match **and** the cumulative checksum validates; stop at the first failure (never resume). Valid range ends at the last commit frame (db-size ≠ 0) within the validated run; per page the latest frame in range wins; database is sized to that commit's db-size. Outcomes: WAL absent / < 32 B / header invalid / no commit → merged = DB-only, with a diagnostic. Frames after the last commit, after a salt break or after a checksum failure are reported (count, offsets) and never applied. Page no 0 or > commit db-size of its transaction → stop with diagnostic. |
| Loading images | Before `sqlite3_deserialize`, the loading copy of each image gets header bytes 18–19 set to 1 (rollback-journal mode); WAL-mode images cannot be deserialized. The transformation is recorded; Evidence shows the original values. |
| Store record | `RC4(file[0:0x3C])`: magic `db e8 c5 01` @0, len1 @0x28, len2 @0x2C, `db e8 c5 02` @0x38. sec1 = RC4(file[0x3C : 0x3C+len1]), sec2 = RC4(next len2 bytes), fresh keystream each. sec2 = `u32 total` then `{u32 name_len_bytes (incl. NUL), UTF-16LE name, u32 type, value}*`. Types: 3 u32, 4 u64 (unsigned), 5 u8 bool, 6 u32 byte-len + UTF-16LE, **9 = fixed 8 bytes** (all zero on 84 real records; corrected 2026-11-09 during implementation — the earlier "length 0" reading made the old Python parser stop early and drop the tail properties `PROCESSDEVICEPATH`/`Id` on 58/84 records); **every other type = u32 byte-len + bytes** (observed: 7 text-like blob, 8 blob of 8/16/52/240 B). File name = PersistId (32 hex). |
| Results record | Same container. Validated: sec1 begins with the scan GUID (bytes_le, equals file name); sec2 begins with u64 start FILETIME, u64 end FILETIME. Everything else (type/subtype, counters, signature version, resource table) is **unvalidated** → shown as raw hex/u32 list, labelled "unverified". len1 is not assumed to be 48. |

Validated table semantics used by correlation (R9):
- `BackupProcessInfo`: one row per image path at first start in a ~7-day window; `FirstStartTime` = kernel process
  creation (ms-exact) when it is a plausible FILETIME; module rows carry a non-FILETIME value; images with a valid
  Microsoft embedded signature are skipped.
- `AttributePersistContext`: `Context='ExecutedPENoCert'` = first execution of an image **without an embedded
  certificate** (catalog-signed binaries included), `InsertTime` ≈ 6 ms before creation, reset at daily maintenance,
  ~999-row cap. `FilePath` prefixes `ENG:OFNPROCESSED:<path>` (Context `processed`) and `ENG:OFNSET:<path>` (Context =
  OriginalFileName, written at file creation). v1 also treats an **unprefixed** row whose Context looks like a PE file
  name different from the leaf as an OFN observation (kept, labelled inferred).
- `FileHashes`: column `SHA1` holds MD5 (16 B), column `MD5` holds SHA1 (20 B) — mapping is per these two named columns
  (verified 13/13) and checked by length; `SHA256` 32 B. `FileID` = NTFS reference, `VSN` = volume serial (signed in SQLite).
  Not joinable to paths by USN (0/104 match `BackupProcessInfo.NextUSN`).
- `Key` columns are per-table internal hashes (0/38 shared for the same path) → **never join on `Key`.**
- `AmsiFileCache.PersistId` = Store file name; `ExpirationDate` observed ≈ record creation + 1 h (DD-2, not proven per record).
- Store `CONTEXT_DATA_PROCESS_PPID` = `pid:<N>,ProcessStart:<FILETIME>` of the acting process (pid = `PROCESS_ID`).
- RollingQueues on this host: `RecentThreatsOnMachine` (TTL 1800), `domainInfo` (7 d), `KernelCallBackAddress` (1 y),
  `Tact-pid:N,ProcessStart:FT[-suffix]`. From another host's dump (DefRev): `RQ_RecentExecDropped`,
  `RQ_RecentScriptDropped`, `RDP-*`, `RDP-Event-Success` JSON (`Wsn, SLId, LT, Ip, TSid`) — decoders fall back to generic
  key/value when the shape differs.

## 4. Architecture

```
open ─► crypto ─► pager ─► sqldb(mem ×2) ─► tables ─► decode ─► correlate ─► Case (Arc, immutable)
 │      RC4      validate+replay  deserialize     typed rows   display     observations+links  │
 └ evidence: path, size, mtime, SHA256 (before/after read)                                         ▼
history (Store, Results) ─────────────────────────────────────────────────────────►  ui │ cli │ export
```

One crate, binary `mpdbx`. Modules:

| Module | Responsibility | Interface (sketch) |
|---|---|---|
| `evidence` | read inputs read-only into memory, hash, detect change during read | `fn read(path)->Result<Input{bytes, sha256, size, mtime, changed:bool}>` |
| `crypto` | RC4, embedded key, dll key search | `struct Rc4Ks`, `fn crypt(&self,&[u8])->Vec<u8>`, `fn find_key(dll,&page1)->Option<Key>` |
| `pager` | page decryption, WAL validation and replay | `fn build(db:&Input, wal:Option<&Input>, key)->Result<Images>`; `Images{db_only, merged, wal:WalReport, notes}` |
| `sqldb` | deserialize an image (header patched), schema, typed row iteration | `fn open(img:&[u8])->Result<Db>`; `Db::tables()->Vec<TableInfo{name, without_rowid, pk_cols}>`; `Db::rows(t)->Result<Vec<Row>>` |
| `provenance` | endpoint comparison DB-only vs merged | `fn classify(&Db,&Db)->ProvMap` (§5.5) |
| `history` | Store + Results containers, bounded parsing | `fn store(dir)->Vec<Result<StoreRec,ParseErr>>`, `fn results(dir)->…` |
| `decode` | pure raw→display functions (§6) | e.g. `fn filetime(u64)->FtClass` |
| `normalize` | path parsing/normalisation, VolMap | `fn parse_path(&str)->WinPath`, `fn infer_volmap(..)->VolMap` |
| `correlate` | observations, entities, links (§5) | `fn build(&Tables,&History,&Opts)->Case` |
| `query` | search parser, filtering, facets, histogram | `fn parse(&str)->Result<Query,QErr>`, `fn apply(&Case,&Query)->Vec<u32>` |
| `export` | CSV / JSON / HTML report / diff, safe output paths | `fn write_view(..)`, `fn report(..)`, `fn diff(&Case,&Case)->Diff` |
| `ui` | eframe/egui app, theme tokens, layout C1 | `App::new(cc)` |
| `cli` | hand-rolled argument parsing, headless commands | `fn run(args)->ExitCode` |

**Threading**: loading runs on a worker thread that sends `Progress` over a channel; the UI polls each frame. Result is
`Arc<Case>`; the UI holds filter state and `Vec<u32>` index lists. Release builds use `panic="unwind"` so a worker panic
is caught (`catch_unwind`) and shown as an error panel; ordinary input failures are `Result`s.

**Robust parsing**: all lengths/offsets use checked arithmetic and bounded slices; caps: input file ≤ 2 GiB, Store/Results
record ≤ 16 MiB, property name ≤ 1024 B, property value ≤ declared container length; malformed UTF-16 decoded lossily
with a flag; duplicate property names kept in order; trailing bytes reported.

**Evidence safety**
- Inputs opened with read access only and `FILE_SHARE_READ` (retry with `FILE_SHARE_READ|WRITE` plus a warning if the
  file is held open by another program). Size and mtime are compared before and after the read; a change is a warning.
- SQLite connections: in-memory deserialized images, `PRAGMA temp_store=MEMORY`, `PRAGMA query_only=1`, no `ATTACH`
  of files, no extensions. No temp files are created by the tool (verified by a test that watches the temp directory and
  the input directory during a load).
- Outputs: every export path is checked against all inputs by file identity (volume serial + file index via
  `GetFileInformationByHandle`) and refused if it matches; generated file names are sanitised and confined to the chosen
  directory; existing files are not overwritten without confirmation (GUI) or `--force` (CLI).
- Bookmark sidecar `<name>.mpdbx.json` is written only by an explicit "Save bookmarks".

**Build**: Rust 1.99, target `x86_64-pc-windows-msvc`, static CRT (`+crt-static`), `Cargo.lock` committed.
Profile: `opt-level="z"`, `lto="fat"`, `codegen-units=1`, `panic="unwind"`, `strip=true`. Dependencies (complete):
`eframe` (default-features off; `glow`, `default_fonts`), `egui_extras`, `rusqlite` (`bundled`, `serialize`), `serde`,
`serde_json`, `sha2`, `regex-lite`, `rfd`. Versions are pinned in the first build step, which builds a skeleton containing
all dependencies and measures its size; if the skeleton exceeds 6 MB, `rfd` is replaced by a direct `IFileOpenDialog`
call before any feature work.

## 5. Correlation model

### 5.1 Identities
- **WinPath** (parsed, not string-stripped): kinds `Drive(X:\…)`, `Device(\Device\HarddiskVolumeN\…)`, `Unc(\\server\share\…)`
  (from `\\?\UNC\…`, `\??\UNC\…` or `\\…`), `VolumeGuid`, `SystemRoot(\SystemRoot\…)`, `Relative/Other`. `\\?\X:\` and
  `\??\X:\` become `Drive`; `ENG:<TAG>:` is split off into a tag first. The raw spelling is always kept.
  **PathKey** = kind + case-folded (Windows-style ordinal upper-case) components; `/` → `\`; no other rewriting.
- **VolMap** (Device N → drive X): inferred when ≥ 2 distinct full volume-relative paths (whole path after the volume
  root, not just the leaf) of Device N equal Drive-X paths and no path contradicts. Inferred mappings are **heuristic**:
  any link that depends on one is at most ◐. The user can confirm a mapping (then it counts as exact, recorded as
  "analyst assertion") or edit it. Shown in Evidence with supporting paths. `SystemRoot` maps to the Windows drive when
  the case shows one unambiguously (Drive paths under `X:\Windows\`), heuristic as well.
- **FileRef** = `(VSN u32, record u48, seq u16)`, from `FileID` as u64 bits (`FileID as u64`; record = low 48 bits,
  seq = high 16) and `VSN as u32`.
- **ProcessObservation** = `{path: Option<PathKey>, pid: Option<u32>, start: Option<FILETIME>}` from BPI, Store,
  AMSI, Tact queues, BmProcessInfo. **ProcessRun** = a cluster of observations joined by rule P (§5.4).
- **Digest** = `(algorithm, bytes)`; algorithm from the source column mapping (§3), never from length alone except as a
  consistency check. FileLowFiAsync `SigSha` is a **signature digest**, a separate kind.

### 5.2 Entities
- **Location** (hub, PathKey): a container of timestamped **observations** from each source. It never holds timeless
  attributes; flags shown on it are "observed at <time> by <source>". Derived labels:
  - `system dir`: exact directory boundaries `X:\Windows\`, `X:\Program Files\`, `X:\Program Files (x86)\` (v1 rule);
    `outside system dirs`: other Drive paths; `unknown`: other kinds. (Writability is not claimed.)
  - `no embedded cert (exec)`: an APC `ExecutedPENoCert` observation exists.
  - `OFN`: from `ENG:OFNSET` (exact) or the unprefixed v1 rule (inferred); `rename_kind` per v1 rule
    (executable rename / resource-component / other).
- **File content** (FileRef + Digests): one per FileHashes row; linked to a Location only via the bound MFT CSV.
- **ProcessRun**, **Digest**, **Event** (§5.3), **HostContext** (domainInfo, RDP aggregates, FolderGuardPaths per SID,
  SQLiteGlobals, DynSigRevisions, Results scans, Engine/Inventory rows when present).

### 5.3 Event catalogue

| Event type | Source | Time | Notes / links |
|---|---|---|---|
| Process first start | BPI with plausible FILETIME at most 7 days (BPI retention) before InstanceTimeStamp — added 2026-11-17: 21 DLL/.pyd rows on the reference copy had date-like FirstStartTime values 48+ years off | FirstStartTime | Location, ProcessObservation(path,start) |
| Module first load | BPI whose FirstStartTime is not a plausible FILETIME | InstanceTimeStamp | Location; FirstStartTime shown raw ("opaque") |
| No-embedded-cert execution | APC `ExecutedPENoCert` | InsertTime | Location; ProcessRun via rule 6 |
| OriginalFileName set | APC `ENG:OFNSET` (exact) / unprefixed OFN rule (inferred) | InsertTime | Location, rename_kind |
| OFN processed | APC `ENG:OFNPROCESSED` | InsertTime | Location |
| Defender file context | APC other Contexts | InsertTime | Location |
| LowFi signature hit | FileLowFiAsync | InstanceTimeStamp | Location, signature digest |
| File hashed | FileHashes | InstanceTimeStamp | File content (FileRef, digests) |
| Process start (from Store) | Store `PROCESS_PPID` | ProcessStart | ProcessObservation(path,pid,start) |
| File scan observed | Store CONTEXT | **unknown**; estimate shown only when an AmsiFileCache row links (rule 7): `≈ ExpirationDate − 1 h`, marked heuristic with derivation | Location of FILEPATH\FILENAME, ProcessRun |
| AMSI scan observed | Store AMSI | unknown (same estimate rule) | ProcessObservation(pid, AMSIPidCreationTime) |
| Process start (from AMSI) | Store AMSI | AMSIPidCreationTime | ProcessObservation |
| Store cache expiry | AmsiFileCache | ExpirationDate | Store record |
| Registry change | SystemRegistryCache | InstanceTimeStamp | FileIDHash shown raw |
| Queue entry | RollingQueuesValues | InsertTime (ExpireTime shown) | per decoder |
| RDP logon success | `RDP-Event-Success` | LT | HostContext |
| Scan run | Results | start (end, duration) | HostContext |
| Bm / Ransomware / Block | Bm*, RansomwareDetections, ProcessBlockHistory | their FILETIME columns | Location, ProcessObservation, ThreatRecordId |

Timeline rows without a known time (scan observations without a cache link) appear in the Artifacts views and in a
"no time" facet, never at a substituted time.

### 5.4 Link rules (● exact, ◐ partial, ○ heuristic)

Strength of a link is the minimum of its rule strength and the strength of any VolMap/SystemRoot mapping it relied on.
Rules are evaluated in order; a pair matched by an earlier rule is not re-matched by a later one.

| # | Link | Rule | Strength |
|---|---|---|---|
| 1 | Location ↔ observation | equal PathKey | ● |
| 2 | Digest ↔ File content | same FileHashes row | ● |
| 3 | File content ↔ Location | bound MFT CSV with matching VSN gives (record, seq) → path; all hard-link names kept; labelled "path as of MFT acquisition" | ● |
| 4 | File content ↔ File content | equal SHA256 | ● |
| 4b | File content ↔ File content | no SHA256 on one side, equal SHA1 | ◐ ; equal MD5 only → ○. Conflicting SHA256 never merged. |
| P | ProcessObservation clustering | (a) equal PID and start within ±1 ms → same run ●; (b) equal path and start within ±1 ms → same run ●; (c) conflicting PIDs or paths never cluster; (d) start-only match → ○, shown as candidate, never clustered | as listed |
| 5 | Store record ↔ BPI first start | Store acting image PathKey (`PROCESSDEVICEPATH` + `PROCESSNAME`) equals BPI path and ProcessStart within ±1 ms of FirstStartTime | ● (via P) |
| 5b | Store record ↔ BPI image | same PathKey, ProcessStart differs by > 1 ms: "same image, earlier run" if before FirstStartTime (BPI predates or rolled over), "same image, later run" if after | ◐ |
| 6 | NoCert exec ↔ BPI first start | same PathKey and 0 ≤ FirstStartTime − InsertTime ≤ 100 ms, unique candidate | ● ; otherwise if ≤ 1 s → ○ |
| 7 | AmsiFileCache ↔ Store record | PersistId equals Store file name (case-insensitive hex) | ● |
| 8 | Explicit FKs | `BmFileActions.FileInfoId → BmFileInfo.ID`; `BmHipsRuleInfo.ProcessInfoId → BmProcessInfo.ID`; `BmFileActions.ThreatRecordId`, `BmFileStartupActions.{Fdr,Evaluator,TrustedInstaller,LFR}ThreatRecordId` grouped by equal value within the case, values 0/NULL excluded. FolderGuardPaths grouped by `UserId` (SID text); `UserIdHash` shown raw. | ● (ThreatRecordId groups ◐ until validated on real data) |
| 9 | Tact queue ↔ ProcessRun | `Tact-pid:N,ProcessStart:FT` → ProcessObservation(pid N, start FT) → rule P | via P |
| 10 | Time proximity | analyst-chosen window (default ±5 s) | ○, computed on demand in the inspector, never stored |

### 5.5 Provenance
- Database rows: `RowKey = Rowid(i64) | Pk(Vec<Value>)` (WITHOUT ROWID tables use their declared primary key; tables with
  neither a usable rowid nor a PK use full-row identity). Status (endpoint comparison of DB-only vs merged image):
  `InBoth`, `WalOnly`, `WalModified{old}`, `RemovedByWal{old}`, `Unknown` (table unreadable in either image).
  It describes the two endpoints only; DB-only is not claimed to be a pristine pre-WAL state.
- History records: `{file name, section, byte offset of property}`.
- Every Event and observation carries its provenance; the inspector shows it, and old values for WalModified/RemovedByWal.

## 6. Decoders (raw → display; raw always retained)

- **FILETIME** classification (u64 ticks since 1601): `Zero`, `Max` (0x7FFF… / 0xFFFF…), `Plausible` (v1 bounds:
  1970-01-01 ≤ t < 2076, i.e. 116444736000000000 ≤ t < 150000000000000000), `Representable` (other ≤ 9999-12-31,
  shown with a "implausible" mark), `Opaque` (negative as i64 or beyond). Only `Plausible` values are placed on the
  timeline; BPI module classification uses "not Plausible".
- **Time zone**: display zone = UTC (default) or a fixed offset the analyst enters (e.g. `+05:30`, typically the
  evidence host's offset). No DST rules. Display and exports always include the offset (`…Z` or `…+05:30`). Query
  times without an explicit offset use the display zone **at the moment the query is typed**; the parsed query is stored
  in UTC, so changing the display zone does not alter an applied query.
- **Integers**: SQLite i64 values are reinterpreted bit-for-bit where the field is unsigned (`FileID`, `VSN`, CRCs,
  Store type 4). JSON exports write 64-bit integers as strings; CSV writes them verbatim.
- TEXT dates (`ExpirationDate`, `LastUpdated`) parsed as UTC.
- FileRef → `<record>-<seq>`; VSN → `XXXX-XXXX`.
- Digest BLOBs → lower hex with algorithm label from §3 mapping; CTPH displayed as text.
- GUID BLOBs (16 B, mixed-endian) → `{…}`; FolderGuardPaths GUID → known-folder name where in the built-in table.
- `SystemRegistryCache`: RegType names; data by type (DWORD/QWORD LE, SZ/EXPAND_SZ UTF-16, MULTI_SZ list, binary hex);
  RegOperation raw + name where known.
- Enums/flags (`ActionFlags`, `MonitoringFlags_*`, `Action`, `RuleAction`, `ProcessIntegrity`, `ProcessTaintReason`, Store
  `SCANREASON` 2 = on-open / 5 = on-close-after-write): name where known, `0x… (unknown)` otherwise; flags split into bits.
- Store bags: typed values (§3); `PROCESS_PPID` → PID + start; `FILE_AGE*` → seconds with "interpretation" label.
- Queues: `domainInfo`, `RecentThreatsOnMachine`, `Tact-pid`, `RQ_Recent{Exec,Script}Dropped`, `RDP-*`,
  `RDP-Event-Success`, `KernelCallBackAddress`; unknown → generic key/value.
- Results: GUID, start, end, duration; remaining bytes raw ("unverified").

## 7. Query language

Free text (case-insensitive substring over display fields); terms AND-combined; `-term` negates; quotes group.
Terms: `path:`, `name:`, `sha256:`/`sha1:`/`md5:`, `pid:`, `type:`, `src:db|walonly|walmod|removed`,
`loc:system|outside`, `nocert:yes`, `after:`/`before:` (ISO 8601, optional offset), glob `*`/`?` in term values,
`/regex/` (free-text, `regex-lite`, case-insensitive). Parse errors shown inline; the last valid query stays applied.

## 8. UI

### 8.1 Tokens (`ui/theme.rs`, three layers)
- **Primitive**: neutral ramp `n0…n950` (11 steps), `blue500/600`, `amber400/900`, `red400/900`, `green400`,
  `violet400`; spacing 4/8/12/16/24; radius 4/6; font sizes 12/13/15/18.
- **Semantic**: `bg.app, bg.panel, bg.raised, bg.input, border, text.primary, text.muted, text.mono, accent, accent.weak,
  state.walonly, state.walmod, state.removed, state.flag, state.exact, state.partial, state.heuristic, focus`.
- **Component**: `row.h` (20 compact / 24 comfortable), `chip.*`, `tab.*`, `inspector.w` (360 default, resizable,
  collapsible), `facets.w` (220), `hist.h` (56), `hist.bar`, `hist.brush`.
- Dark (default) and Light map semantic tokens to `egui::Visuals` + `Style`; text tokens ≥ 4.5:1 contrast. Monospace for
  paths, hashes, times, IDs. Long paths: middle ellipsis in the grid, full value in the inspector.

### 8.2 Layout C1
- **Top bar**: Open (file or `Scans` folder) · case label + short SHA256 · search · time zone (UTC / offset) · density ·
  theme · Export ▾ (view CSV/JSON, HTML report) · Save bookmarks.
- **Tabs**: Timeline · Artifacts · Evidence (`Ctrl+1/2/3`).
- **Timeline**: histogram (bucket minute/hour/day by span; drag = brush window, double-click = reset, hover = count);
  facets (event type, location class, no-cert, provenance status, link strength, source table, "no time") with live
  counts; virtualised grid (Time, Type, Summary, Path, Src), sortable/resizable/hideable columns; row tints by
  provenance status, flag marker for red-flag rules (§10).
- **Artifacts**: Locations, Process runs, File content & hashes, No-cert executions, Renamed binaries (OFN), Defender
  file contexts, Store provenance, AMSI, Scan history, Queues, RDP, Host context, CFA folders, Registry cache, LowFi
  hits; then **Raw tables** (all tables, decoded where a decoder applies). Same grid + inspector.
- **Evidence**: inputs (path, size, mtime, SHA256, changed-during-read), page size/count, header bytes 18–19, key source,
  WAL report (header validity, frames total/validated/applied, commits, salts, first failure and reason, ignored
  ranges), per-table counts DB-only vs merged and status counts, VolMap with support, MFT CSV binding, parse warnings.
- **Inspector**: title + type badge; decoded fields with per-field raw toggle and copy; provenance; **Related** grouped
  by entity with strength dot + rule number/text; pivots (±N window, same digest, same process run, same location,
  filter on value); bookmark ★ + tag + note.
- **Keys**: `Ctrl+F` search, `Ctrl+E` export view, `Enter` follow first related, `Alt+←/→` pivot history, `Ctrl+B`
  bookmark, `Ctrl+C` copy row (TSV).
- **Empty state**: drop zone + "Open mpenginedb.db or a Scans folder" + the acquisition command.

## 9. CLI (same exe; console attached only when arguments are given)

```
mpdbx                          GUI
mpdbx open <path>              GUI with a case preloaded
mpdbx export <path> --out DIR [--format csv|json] [--force]
mpdbx report <path> --out FILE.html [--bookmarks F.mpdbx.json] [--force]
mpdbx diff <pathA> <pathB> --out FILE.csv|FILE.html [--force]
mpdbx info <path>              evidence + counts + WAL report to stdout
```
`<path>` = db file or Scans folder. Options: `--key-dll FILE`, `--mft FILE --mft-vsn XXXX-XXXX --mft-drive X` (the drive is required: MFTECmd paths are volume-relative), `--tz Z|+HH:MM`,
`--volmap N=X` (repeatable, analyst assertion). Exit codes: 0 ok, 2 usage, 3 input unreadable, 4 decrypt failed,
5 output refused (would overwrite an input or an existing file).

## 10. Export and report
- CSV: UTF-8 with BOM, one file per view, display columns + `raw_*` columns + provenance columns.
- JSON: records with `display`, `raw`, `prov`, `links` (64-bit integers as strings).
- HTML report: one self-contained file (inline CSS, no JS, no external resources): evidence block incl. WAL report,
  summary counts, red-flag list — no-embedded-cert executions outside system dirs, executable renames, threat queue
  entries, RDP successes, WalOnly/RemovedByWal rows — bookmarked rows with notes, appendix of link rules and labels.
- Diff: per-view natural keys that include the event/source kind — e.g. Process first start = (type, PathKey,
  FirstStartTime); OFN = (type, PathKey, OFN); queue = (queue name, entry key, InsertTime); Store = (PersistId);
  File content = (VSN, FileRef, SHA256); Raw tables = (table, RowKey). Keys are compared as **multisets** (duplicates
  counted); unknown and absent values are distinct; both cases must use the same VolMap/time-zone settings or the diff
  refuses with a message.

## 11. Error handling
- Wrong key (page-1 check fails) → GUI prompts for `mpengine.dll`; CLI exit 4.
- WAL problems → never fatal; merged image falls back per §3 with diagnostics.
- SQLite error on a table in one image → that table's provenance becomes `Unknown`; other tables continue.
- Unknown table/column → shown raw; never fatal. Store/Results parse failure → listed with file, offset and reason.
- All input-derived failures are `Result`s; panics in the worker are caught and shown; the UI never blocks.

## 12. Testing and verification
- **Unit**: decoders (incl. FILETIME classes, signed/unsigned reinterpretation, GUID), RC4 vectors, WAL checksum,
  WinPath parsing (each namespace), VolMap inference, each link rule incl. ambiguity and conflicts, query parser
  (incl. time-zone semantics), Store/Results parsers incl. malformed lengths, diff multiset logic, output-path refusal.
- **Synthetic fixtures** (`tests/fixtures/`, generated by `tests/gen_fixtures.py`): Defender-like tables encrypted with
  the page format; WALs covering: absent, empty, header-only, bad header checksum, multiple commits with repeated pages,
  uncommitted tail, checksum failure mid-chain followed by valid-looking commits, salt reset followed by stale frames,
  page size 65536, db-size growth/shrink; a WITHOUT ROWID table; Store/Results records incl. truncated and oversized
  lengths. Expected results come from the spec rules, not from v1.
- **Oracle (local, `#[ignore]`)**: on the 7 reference copies (all with fully valid WAL chains), per-table row counts for
  both images and WAL-only row-key sets must equal Python v1 output (`tests/oracle/*.json`, produced by a script).
  Documented intentional differences from v1: strict checksum validation, RemovedByWal/WalModified states.
- **Golden**: correlation summary (events per type, links per rule and strength) on the reference copy, reviewed, pinned.
- **No-write test**: load + export-free session with temp and input directories watched; zero new/modified files.
- **Review**: every change is reviewed for bugs and logic errors; each finding is verified with a test before it is fixed
  or rejected.
- **Size gate**: script fails if the release exe exceeds 8,388,608 bytes.
- **UI smoke**: launch with a fixture, screenshot each tab, manual review.

## 13. Risks and open research items
- Store scan time unknown (estimate only via AmsiFileCache); research: find a per-record time.
- `Key` hash algorithm unknown; not needed.
- Enum/flag tables partial; ThreatRecordId grouping unvalidated (no non-empty Bm* tables on reference data).
- RDP/RQ queue shapes come from one external dump; decoders degrade to key/value.
- Results layout beyond GUID/start/end unverified.
- Size: eframe+glow ≈ 3–4 MB, bundled SQLite ≈ 1.5 MB; measured before feature work.
