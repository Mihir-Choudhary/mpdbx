"""Generate synthetic, Defender-format encrypted fixtures for mpdbx tests (stdlib only).

usage: python tests/gen_fixtures.py tests/fixtures

Every variant directory holds mpenginedb.db (+ mpenginedb.db-wal) encrypted exactly like Defender's engine DB
(spec §3) and a manifest.json with the results the spec's rules require. No real evidence is used.
"""
import json, os, shutil, sqlite3, struct, sys, tempfile

KEY = bytes.fromhex(
    '1e87781b8dbaa844ce69702c0c78b786a3f623b738f5edf9af83530fb3fc54faa21eb9cf1331fd0f0da954f687cb9e18279697900e53fb317c9cb'
    'ce48e23d05371ecc15951b8f3649d7ca33ed68dc9047e82c9baad9799d0d458cb847ca9ffbe3c8a775233557dde13a8b14087cc1bc8f10f6ecdd0'
    '83a959cff84a9d1d50755e3e191818af23e2293558766d2c07e25712b2ca0b535ed8f6c56ce73d24bdd0291771861a54b4c285a9a3db7aca6d224'
    'aeacd621db9f2a22ed1e9e11d75bed7dc0ecb0a8e68a2ff1263408dc808dffd164b116774cd0b9b8d05411ed6262e429ba495676b8398db2f35d3'
    'c1b9ced52636f2765e1a95cb7ca4c3ddabddbff38253')
MAGIC = b'SQLite format 3\x00'
assert len(KEY) == 256

_KS = {}


def keystream(n):
    if n not in _KS:
        s = list(range(256)); j = 0
        for i in range(256):
            j = (j + s[i] + KEY[i]) & 0xFF; s[i], s[j] = s[j], s[i]
        out = bytearray(n); i = j = 0
        for k in range(n):
            i = (i + 1) & 0xFF; j = (j + s[i]) & 0xFF; s[i], s[j] = s[j], s[i]
            out[k] = s[(s[i] + s[j]) & 0xFF]
        _KS[n] = bytes(out)
    return _KS[n]


def rc4(b):
    ks = keystream(len(b))
    return bytes(x ^ y for x, y in zip(b, ks))


def enc_page(p, first):
    return rc4(p[:16]) + p[16:24] + rc4(p[24:]) if first else rc4(p)


def wal_ck(data, s0, s1, big):
    n = len(data) // 4
    w = struct.unpack(('>' if big else '<') + f'{n}I', data[:n * 4])
    for i in range(0, n, 2):
        s0 = (s0 + w[i] + s1) & 0xFFFFFFFF
        s1 = (s1 + w[i + 1] + s0) & 0xFFFFFFFF
    return s0, s1


SCHEMA = '''
CREATE TABLE BackupProcessInfo(ID INTEGER PRIMARY KEY, Key INTEGER, FilePath NVARCHAR, FirstStartTime INTEGER,
  NextUSN INTEGER, AutomaticRemovalPolicy INTEGER, ImpactedCBPNameSpaces NVARCHAR, InstanceTimeStamp INTEGER);
CREATE TABLE AttributePersistContext(ID INTEGER PRIMARY KEY, Key INTEGER, FilePath NVARCHAR, Context NVARCHAR,
  InsertTime INTEGER, ExpireTime INTEGER);
CREATE TABLE FileHashes(ID INTEGER PRIMARY KEY, Key INTEGER, VSN INTEGER, FileID INTEGER, USN INTEGER,
  InstanceTimeStamp INTEGER, SHA1 BLOB, MD5 BLOB, SHA256 BLOB, LSHASH BLOB, LSHASHS BLOB, CTPH BLOB,
  PartialCRC1 UNSIGNED INT, PartialCRC2 UNSIGNED INT, PartialCRC3 UNSIGNED INT, KCRC1 UNSIGNED INT,
  KCRC2 UNSIGNED INT, KCRC3 UNSIGNED INT, KCRC3n UNSIGNED INT);
CREATE TABLE AmsiFileCache(ID INTEGER PRIMARY KEY, PersistId VARCHAR, PersistIdBlob BLOB, ExpirationDate TEXT);
CREATE TABLE RollingQueuesTables(ID INTEGER PRIMARY KEY, Key INTEGER, Name NVARCHAR, Capacity INTEGER,
  TimeToLive INTEGER, Mode INTEGER, Namespace NVARCHAR);
CREATE TABLE RollingQueuesValues(ID INTEGER PRIMARY KEY, EntryTable NVARCHAR, EntryKey NVARCHAR,
  EntryValue NVARCHAR, InsertTime INTEGER, ExpireTime INTEGER);
CREATE TABLE InventoryState(key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
CREATE TABLE Bulk(ID INTEGER PRIMARY KEY, B BLOB);
CREATE TABLE FileLowFiAsync(ID INTEGER PRIMARY KEY, Key INTEGER, FileName NVARCHAR, SigSeq INTEGER, SigSha BLOB,
  SigIsSync BOOLEAN, InstanceTimeStamp INTEGER);
CREATE TABLE SystemRegistryCache(ID INTEGER PRIMARY KEY, Key INTEGER, FileIDHash INTEGER, RegPath NVARCHAR,
  RegOperation INTEGER, NewRegType INTEGER, OldRegType INTEGER, OldRegData BLOB, NewRegData BLOB, InstanceTimeStamp INTEGER);
CREATE TABLE FolderGuardPaths(ID INTEGER PRIMARY KEY, UserIdHash INTEGER, UserId NVARCHAR, GUID BLOB, Path NVARCHAR);
CREATE TABLE SQLiteGlobals(ID INTEGER PRIMARY KEY, Version INTEGER, Current BOOLEAN, LastUpdated TEXT);
'''
TABLES = ['BackupProcessInfo', 'AttributePersistContext', 'FileHashes', 'AmsiFileCache', 'RollingQueuesTables',
          'RollingQueuesValues', 'InventoryState', 'Bulk', 'FileLowFiAsync', 'SystemRegistryCache', 'FolderGuardPaths',
          'SQLiteGlobals']
T0 = 134369015368153546  # 2026-10-19 16:38:56.8153546Z
DOCS_GUID = 'd09ad3fd8f23af46adb46c85480369c7'  # {FDD39AD0-238F-46AF-ADB4-6C85480369C7} = Documents

BASE = [
    "INSERT INTO BackupProcessInfo VALUES(1, 11, 'C:\\T\\a.exe', %d, 100, 0, '', %d)" % (T0, T0 + 80000),
    "INSERT INTO BackupProcessInfo VALUES(2, 12, 'C:\\Windows\\System32\\m.dll', 42, 101, 0, '', %d)" % (T0 + 5),
    "INSERT INTO AttributePersistContext VALUES(1, 21, 'c:\\t\\a.exe', 'ExecutedPENoCert', %d, %d)" % (T0 - 60000, T0 + 864000000000),
    "INSERT INTO AttributePersistContext VALUES(3, 23, 'c:\\t\\renamed.exe', 'cmd.exe', %d, %d)" % (T0 - 10**7, T0),
    "INSERT INTO AttributePersistContext VALUES(5, 25, 'ENG:OFNPROCESSED:c:\\t\\a.exe', 'processed', %d, %d)" % (T0 - 2 * 10**7, T0),
    "INSERT INTO AttributePersistContext VALUES(6, 26, 'c:\\t\\s.ps1', 'AsrObfusWasScanned', %d, %d)" % (T0 - 3 * 10**7, T0),
    "INSERT INTO RollingQueuesTables VALUES(1, 31, 'RecentThreatsOnMachine', 100, 1800, 1, '')",
    "INSERT INTO AmsiFileCache VALUES(1, '0123456789ABCDEF0123456789ABCDEF', x'0123456789abcdef0123456789abcdef', '2026-10-19 17:38:56')",
    "INSERT INTO FileLowFiAsync VALUES(1, 51, 'D:\\x\\y.exe', 7, x'%s', 1, %d)" % ('44' * 20, T0 - 4 * 10**7),
    "INSERT INTO SystemRegistryCache VALUES(1, 61, -5, 'HKLM\\SYSTEM\\ControlSet001\\Services\\BITS', 21, 4, 0, NULL, x'02000000', %d)" % (T0 - 5 * 10**7),
    "INSERT INTO FolderGuardPaths VALUES(1, -7, 'S-1-5-18', x'%s', '')" % DOCS_GUID,
    "INSERT INTO SQLiteGlobals VALUES(1, 41, 1, '2026-10-14')",
]
TXNS = [
    ["INSERT INTO BackupProcessInfo VALUES(3, 13, 'C:\\T\\b.exe', %d, 102, 0, '', %d)" % (T0 + 10**7, T0 + 10**7 + 9),
     "INSERT INTO AttributePersistContext VALUES(4, 24, 'c:\\t\\b.exe', 'ExecutedPENoCert', %d, %d)" % (T0 + 10**7 - 60000, T0 + 864000000000),
     "INSERT INTO AttributePersistContext VALUES(2, 22, 'ENG:OFNSET:c:\\t\\zz.exe', 'robocopy.exe', %d, %d)" % (T0 + 2 * 10**7, T0 + 3 * 10**7)],
    ["UPDATE BackupProcessInfo SET FirstStartTime=%d WHERE ID=1" % (T0 + 1)],
    ["DELETE FROM AttributePersistContext WHERE ID=1",
     "INSERT INTO InventoryState VALUES('schema_version','2')"],
    ["INSERT INTO RollingQueuesValues VALUES(1, 'RecentThreatsOnMachine', 'Behavior:Win32/Test.A', '1', %d, %d)" % (T0, T0 + 18000000000),
     "INSERT INTO RollingQueuesValues VALUES(2, 'Tact-pid:4120,ProcessStart:%d-amsifrag', 'PS_ManageAuto', '3', %d, %d)" % (T0, T0, T0 + 36000000000)],
    ["INSERT INTO FileHashes(ID, Key, VSN, FileID, USN, InstanceTimeStamp, SHA1, MD5, SHA256) VALUES(1, 41, -328604643, 2533274790530311, 5, %d, x'%s', x'%s', x'%s')"
     % (T0, '11' * 16, '22' * 20, '33' * 32)],
]
GROWTH_TXN = ["INSERT INTO Bulk VALUES(1, zeroblob(300000))"]


def counts(con):
    return {t: con.execute(f'SELECT count(*) FROM "{t}"').fetchone()[0] for t in TABLES}


def build_plain(page_size, txns):
    """Return (db_bytes, wal_bytes, counts_after[0..n]) for a WAL-mode DB with one base checkpoint and n txns."""
    d = tempfile.mkdtemp(prefix='mpdbx_fx_')
    p = os.path.join(d, 'x.db')
    con = sqlite3.connect(p, isolation_level=None)
    con.execute(f'PRAGMA page_size={page_size}')
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA wal_autocheckpoint=0')
    con.executescript(SCHEMA)
    for s in BASE:
        con.execute(s)
    con.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    after = [counts(con)]
    for t in txns:
        con.execute('BEGIN')
        for s in t:
            con.execute(s)
        con.execute('COMMIT')
        after.append(counts(con))
    db = open(p, 'rb').read()
    wal = open(p + '-wal', 'rb').read()
    con.close()
    shutil.rmtree(d, ignore_errors=True)
    return db, wal, after


FIXED_SALTS = (0x11223344, 0x55667788)  # SQLite picks random salts; fixed ones keep fixtures deterministic


def parse_wal(wal):
    magic, ver, ps, ckseq, salt1, salt2 = struct.unpack('>6I', wal[:24])
    salt1, salt2 = FIXED_SALTS
    frames = []
    off = 32
    while off + 24 + ps <= len(wal):
        pg, commit = struct.unpack('>II', wal[off:off + 8])
        frames.append([pg, commit, wal[off + 24:off + 24 + ps], (salt1, salt2)])
        off += 24 + ps
    return magic, ver, ps, ckseq, salt1, salt2, frames


def encrypt_db(db, ps):
    return b''.join(enc_page(db[i:i + ps], i == 0) for i in range(0, len(db), ps))


def write_wal(magic, ver, ps, ckseq, salt1, salt2, frames):
    big = bool(magic & 1)
    hdr = struct.pack('>6I', magic, ver, ps, ckseq, salt1, salt2)
    s0, s1 = wal_ck(hdr, 0, 0, big)
    out = bytearray(hdr + struct.pack('>II', s0, s1))
    for pg, commit, plain, salts in frames:
        payload = enc_page(plain, pg == 1)
        fh8 = struct.pack('>II', pg, commit)
        s0, s1 = wal_ck(fh8, s0, s1, big)
        s0, s1 = wal_ck(payload, s0, s1, big)
        out += fh8 + struct.pack('>II', *salts) + struct.pack('>II', s0, s1) + payload
    return bytes(out)


def commit_indices(frames):
    return [i for i, f in enumerate(frames) if f[1] != 0]


def emit(outdir, name, db_enc, wal_enc, manifest):
    d = os.path.join(outdir, name)
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, 'mpenginedb.db'), 'wb').write(db_enc)
    walp = os.path.join(d, 'mpenginedb.db-wal')
    if wal_enc is None:
        if os.path.exists(walp):
            os.remove(walp)
    else:
        open(walp, 'wb').write(wal_enc)
    json.dump(manifest, open(os.path.join(d, 'manifest.json'), 'w'), indent=1, sort_keys=True)
    print(f'{name:18} frames_applied={manifest["frames_applied"]:3} commits={manifest["commits"]} stop={manifest["stop"]}')


def man(after, n_commits, frames, stop):
    ci = commit_indices(frames)
    applied = ci[n_commits - 1] + 1 if n_commits else 0
    return {'expect_counts': after[n_commits], 'frames_applied': applied, 'commits': n_commits, 'stop': stop}


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    db, wal, after = build_plain(4096, TXNS)
    magic, ver, ps, ckseq, s1, s2, frames = parse_wal(wal)
    n = len(commit_indices(frames))
    assert n == len(TXNS), (n, len(TXNS))
    hdr = (magic, ver, ps, ckseq, s1, s2)
    dbe = encrypt_db(db, ps)
    full = write_wal(*hdr, frames)
    fsz = 24 + ps
    ci = commit_indices(frames)

    m = man(after, n, frames, None)
    # Expected correlation results for the multi_commit DB + history fixture (spec §5.3 event catalogue).
    m['expect_events'] = {
        'ProcessFirstStart': 2, 'ModuleFirstLoad': 1, 'NoCertExec': 2, 'OfnSet': 1, 'OfnSetInferred': 1,
        'OfnProcessed': 1, 'FileContext': 1, 'LowFiHit': 1, 'FileHashed': 1, 'StoreProcessStart': 1, 'FileScan': 2,
        'AmsiScan': 1, 'AmsiProcessStart': 1, 'StoreExpiry': 1, 'RegistryChange': 1, 'QueueEntry': 2, 'ScanRun': 1,
    }
    # Spec §5.4 applied by hand: 12 located events, 1 hashed content, 5 observations (BPI a/b, Store, Tact, AMSI),
    # NoCert a/b each 6 ms before first start, AmsiFileCache PersistId = Store CTX file. Runs: {a}, {b}, {Store+Tact}, {AMSI}.
    # Tact queue → run is rule 9 (4 P memberships + 1 rule-9 membership).
    m['expect_links'] = {'1': 12, '2': 1, 'P': 4, '9': 1, '6': 2, '7': 1}
    m['expect_runs'] = 4
    emit(outdir, 'multi_commit', dbe, full, m)
    emit(outdir, 'nowal', dbe, None, man(after, 0, frames, None))
    emit(outdir, 'empty_wal', dbe, b'', man(after, 0, frames, None))
    emit(outdir, 'header_only', dbe, full[:32], man(after, 0, frames, None))
    bad = bytearray(full); bad[24] ^= 0xFF
    emit(outdir, 'bad_header_ck', dbe, bytes(bad), man(after, 0, frames, None))

    fr = [list(f) for f in frames]; fr[ci[-1]][1] = 0
    emit(outdir, 'uncommitted_tail', dbe, write_wal(*hdr, fr), man(after, n - 1, frames, None))

    k = ci[1] + 1  # first frame of txn 3
    w = bytearray(full); w[32 + k * fsz + 24 + 100] ^= 0x01
    emit(outdir, 'ck_fail_mid', dbe, bytes(w), man(after, 2, frames, 'checksum'))

    fr = [list(f) for f in frames]
    for i in range(ci[2] + 1, len(fr)):  # frames of txn 4 onward carry a stale salt
        fr[i][3] = ((s1 + 1) & 0xFFFFFFFF, s2)
    emit(outdir, 'salt_reset_stale', dbe, write_wal(*hdr, fr), man(after, 3, frames, 'salt'))

    fr = [list(f) for f in frames]
    for f in fr:
        f[3] = ((s1 + 1) & 0xFFFFFFFF, s2)
    emit(outdir, 'salt_first_frame', dbe, write_wal(*hdr, fr), man(after, 0, frames, 'salt'))

    cut = full[:32 + (len(frames) - 1) * fsz + 24 + 100]  # last (commit) frame truncated mid-payload
    emit(outdir, 'truncated', dbe, cut, man(after, n - 1, frames, 'truncated'))

    db6, wal6, after6 = build_plain(65536, TXNS)
    m6 = parse_wal(wal6)
    emit(outdir, 'ps65536', encrypt_db(db6, 65536), write_wal(*m6[:6], m6[6]), man(after6, len(TXNS), m6[6], None))

    dbg, walg, afterg = build_plain(4096, TXNS + [GROWTH_TXN])
    mg = parse_wal(walg)
    emit(outdir, 'growth', encrypt_db(dbg, 4096), write_wal(*mg[:6], mg[6]), man(afterg, len(TXNS) + 1, mg[6], None))


# ---------------------------------------------------------------- Scans\History (Store / Results)
STORE_CTX = '0123456789ABCDEF0123456789ABCDEF'
STORE_AMSI = '11111111111111111111111111111111'
STORE_UNK = '22222222222222222222222222222222'
STORE_TRUNC = '33333333333333333333333333333333'
STORE_HUGE = '44444444444444444444444444444444'
SCAN_GUID = '{52C578BA-7190-4A14-84B3-57F157281CB5}'


def container(sec1, sec2, len2_override=None):
    hdr = bytearray(0x3C)
    hdr[0:4] = bytes([0xdb, 0xe8, 0xc5, 0x01])
    struct.pack_into('<I', hdr, 4, 0x10)
    struct.pack_into('<II', hdr, 0x28, len(sec1), len(sec2) if len2_override is None else len2_override)
    hdr[0x30:0x34] = b'\xff\xff\xff\xff'
    hdr[0x34:0x38] = b'\x12\x34\x56\x78'
    hdr[0x38:0x3C] = bytes([0xdb, 0xe8, 0xc5, 0x02])
    return rc4(bytes(hdr)) + rc4(sec1) + rc4(sec2)


def prop(name, typ, val):
    n = (name + '\x00').encode('utf-16-le')
    out = struct.pack('<I', len(n)) + n + struct.pack('<I', typ)
    if typ == 3:
        out += struct.pack('<I', val)
    elif typ == 4:
        out += struct.pack('<Q', val)
    elif typ == 5:
        out += bytes([val])
    elif typ == 6:
        s = (val + '\x00').encode('utf-16-le')
        out += struct.pack('<I', len(s)) + s
    elif typ == 9:
        out += bytes(8)  # fixed 8-byte value (all zero in every real record observed)
    else:
        out += struct.pack('<I', len(val)) + val
    return out


def bag(props):
    body = b''.join(prop(*p) for p in props)
    return struct.pack('<I', 4 + len(body)) + body


def history(outdir):
    h = os.path.join(outdir, 'history')
    st = os.path.join(h, 'Store')
    rq = os.path.join(h, 'Results', 'Quick')
    shutil.rmtree(h, ignore_errors=True)
    os.makedirs(st)
    os.makedirs(rq)
    ctx = bag([
        ('CONTEXT_DATA_PROCESSNAME', 6, 'curl.exe'),
        ('CONTEXT_DATA_PROCESS_ID', 3, 4120),
        ('CONTEXT_DATA_PROCESS_PPID', 6, 'pid:4120,ProcessStart:%d' % T0),
        ('CONTEXT_DATA_PROCESSDEVICEPATH', 6, '\\Device\\HarddiskVolume3\\T'),
        ('CONTEXT_DATA_FILEPATH', 6, '\\Device\\HarddiskVolume3\\T'),
        ('CONTEXT_DATA_FILENAME', 6, 'out.bin'),
        ('CONTEXT_DATA_SCANREASON', 3, 5),
        ('CONTEXT_DATA_HAS_MOTW_ADS', 5, 0),
        ('CONTEXT_DATA_FILE_AGE', 4, 0),
        ('CONTEXT_DATA_AMSI_UAC_REQUEST_CONTEXT', 9, None),
        ('Id', 8, bytes(range(16))),
        ('CONTEXT_DATA_DESIREDACCESS', 3, 0x120089),
    ])
    open(os.path.join(st, STORE_CTX), 'wb').write(container(b'', ctx))
    amsi = bag([
        ('AMSISession', 4, 7),
        ('AMSIApp', 6, 'VSSAMSI'),
        ('AMSIOpProcName', 6, 'VSSVC.exe'),
        ('AMSIPid', 3, 900),
        ('AMSIPidCreationTime', 4, T0 - 10**9),
        ('Content', 8, bytes(52)),
    ])
    open(os.path.join(st, STORE_AMSI), 'wb').write(container(b'', amsi))
    unk = bag([('Weird', 12, b'\x01\x02\x03\x04'), ('CONTEXT_DATA_FILENAME', 6, 'after.txt')])
    open(os.path.join(st, STORE_UNK), 'wb').write(container(b'', unk))
    open(os.path.join(st, STORE_TRUNC), 'wb').write(container(b'', ctx)[:0x3C + 40])
    open(os.path.join(st, STORE_HUGE), 'wb').write(container(b'', ctx, len2_override=0xFFFFFFF0))
    import uuid
    g = uuid.UUID(SCAN_GUID.strip('{}')).bytes_le
    sec1 = g + struct.pack('<QHH', T0, 1, 1) + bytes(48 - 16 - 12)
    sec2 = struct.pack('<QQ', T0, T0 + 41 * 10**7) + bytes(64) + b'file\x00regkey\x00'
    open(os.path.join(rq, SCAN_GUID), 'wb').write(container(sec1, sec2))
    man = {
        'store': {
            STORE_CTX: {'kind': 'Context', 'props': 12, 'ppid': [4120, T0], 'last': 'CONTEXT_DATA_DESIREDACCESS'},
            STORE_AMSI: {'kind': 'Amsi', 'props': 6},
            STORE_UNK: {'kind': 'Context', 'props': 2, 'last': 'CONTEXT_DATA_FILENAME'},
        },
        'store_errors': [STORE_TRUNC, STORE_HUGE],
        'results': {SCAN_GUID: {'category': 'Quick', 'start': T0, 'end': T0 + 41 * 10**7}},
    }
    json.dump(man, open(os.path.join(h, 'manifest.json'), 'w'), indent=1, sort_keys=True)
    # The multi_commit case also carries this History folder, so a fully opened case has Store/Results events.
    dst = os.path.join(outdir, 'multi_commit', 'History')
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(h, dst, ignore=shutil.ignore_patterns('manifest.json'))
    print('history: 5 Store files (2 malformed), 1 Results/Quick record')


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), 'fixtures')
    main(out)
    history(out)
