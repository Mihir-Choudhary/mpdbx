#!/usr/bin/env python3
"""mpdbx (Python edition) — MpEngineDB Explorer for any OS with Python 3.8+ (standard library only).

Reads a COPY of Microsoft Defender's engine database (Scans\\mpenginedb.db + mpenginedb.db-wal), decrypts it in memory,
replays the WAL with SQLite semantics, and shows the same Findings / Timeline / Files & processes / Evidence layout as
the mpdbx.exe GUI.  The same rules as mpdbx are used, so event counts match mpdbx for the DB and WAL
(the Scans\\History Store/Results files are read only by mpdbx.exe).

    python mpdbx.py                      open the GUI
    python mpdbx.py <Scans folder|db>    open the GUI with a case
    python mpdbx.py info <path>          print the evidence report
    python mpdbx.py export <path> --out DIR [--tz +05:30]   write Timeline.csv and one CSV per view

Evidence safety: inputs are only read.  Decrypted images stay in memory (Python 3.11+); on older Pythons each image is
written to a private temporary file that is deleted as soon as its tables are read.  Exports never overwrite an input.
"""
import csv
import datetime as _dt
import decimal
import hashlib
import json
import os
import re
import shutil
import sqlite3
import struct
import sys
import tempfile

VERSION = '2.0'
KEY = bytes.fromhex(
    '1e87781b8dbaa844ce69702c0c78b786a3f623b738f5edf9af83530fb3fc54faa21eb9cf1331fd0f0da954f687cb9e18279697900e53fb317c'
    '9cbce48e23d05371ecc15951b8f3649d7ca33ed68dc9047e82c9baad9799d0d458cb847ca9ffbe3c8a775233557dde13a8b14087cc1bc8f10f6e'
    'cdd083a959cff84a9d1d50755e3e191818af23e2293558766d2c07e25712b2ca0b535ed8f6c56ce73d24bdd0291771861a54b4c285a9a3db7aca'
    '6d224aeacd621db9f2a22ed1e9e11d75bed7dc0ecb0a8e68a2ff1263408dc808dffd164b116774cd0b9b8d05411ed6262e429ba495676b8398db'
    '2f35d3c1b9ced52636f2765e1a95cb7ca4c3ddabddbff38253')
MAGIC = b'SQLite format 3\x00'
PLAUSIBLE_MIN, PLAUSIBLE_MAX = 116444736000000000, 150000000000000000
REPRESENTABLE_MAX = 2650467743999999999
BPI_MAX_START_LAG = 7 * 864000000000
MAX_IMAGE = 2 * 1024 ** 3
MAX_INPUT = 2 * 1024 ** 3


# ===================================================================== decryption + WAL replay
def keystream(n, key=KEY):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray(n)
    i = j = 0
    for k in range(n):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[k] = s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def xor(data, ks):
    n = len(data)
    return (int.from_bytes(data, 'little') ^ int.from_bytes(ks[:n], 'little')).to_bytes(n, 'little')


class Codec:
    def __init__(self, ps, encrypted):
        self.encrypted = encrypted
        self.ks = keystream(ps) if encrypted else b''

    def page(self, p, first):
        if not self.encrypted:
            return bytes(p)
        if first:
            return MAGIC + bytes(p[16:24]) + xor(p[24:], self.ks)
        return xor(p, self.ks)


def wal_checksum(data, s0, s1, big):
    n = len(data) // 8 * 2
    words = struct.unpack(('>' if big else '<') + 'I' * n, data[:n * 4])
    for i in range(0, n, 2):
        s0 = (s0 + words[i] + s1) & 0xFFFFFFFF
        s1 = (s1 + words[i + 1] + s0) & 0xFFFFFFFF
    return s0, s1


def be32(b, o):
    return struct.unpack_from('>I', b, o)[0]


def build_images(db, wal):
    """-> dict(db_only, merged, page_size, encrypted, wal report, notes). Rules identical to mpdbx (pager/)."""
    if len(db) < 100:
        raise ValueError('database file is empty or truncated')
    notes = []
    encrypted = not db.startswith(MAGIC)
    if encrypted and xor(db[:16], keystream(16)) != MAGIC:
        raise ValueError('page 1 does not decrypt to the SQLite magic: not an mpenginedb.db, or a newer key')
    if not encrypted:
        notes.append('input is a plain (unencrypted) SQLite file')
    v = struct.unpack('>H', db[16:18])[0]
    ps = 65536 if v == 1 else v
    if ps < 512 or ps > 65536 or ps & (ps - 1):
        raise ValueError(f'invalid page size {ps}')
    pages = len(db) // ps
    if pages == 0:
        raise ValueError('database file is empty or truncated')
    if len(db) % ps:
        notes.append(f'trailing partial page of {len(db) % ps} bytes ignored')
    codec = Codec(ps, encrypted)
    db_only = b''.join(codec.page(db[i * ps:(i + 1) * ps], i == 0) for i in range(pages))
    rep = dict(present=wal is not None, header_valid=False, page_size=0, salts=(0, 0), frames_total=0, frames_valid=0,
               frames_applied=0, commits=0, stop=None, ignored_tail=0, big_endian=False)
    merged = db_only
    if wal is not None:
        merged = _replay(db_only, wal, ps, codec, rep, notes)
    return dict(db_only=db_only, merged=merged, page_size=ps, pages=pages, encrypted=encrypted, wal=rep, notes=notes,
                header_18_19=(db_only[18], db_only[19]))


def _replay(db_only, w, ps, codec, r, notes):
    if len(w) < 32:
        notes.append(f'WAL has {len(w)} bytes (< 32-byte header); not applied')
        return db_only
    magic = be32(w, 0)
    big = bool(magic & 1)
    r['big_endian'] = big
    r['page_size'] = be32(w, 8)
    r['salts'] = (be32(w, 16), be32(w, 20))
    hck = wal_checksum(w[:24], 0, 0, big)
    version = be32(w, 4)
    r['header_valid'] = (magic & ~1) == 0x377f0682 and version == 3007000 and hck == (be32(w, 24), be32(w, 28))
    if not r['header_valid']:
        notes.append('WAL header invalid (magic, version or checksum); not applied')
        return db_only
    if r['page_size'] != ps:
        notes.append(f"WAL page size {r['page_size']} differs from DB page size {ps}; not applied")
        r['header_valid'] = False
        return db_only
    fsz = 24 + ps
    r['frames_total'] = (len(w) - 32) // fsz
    chain = hck
    last = None
    txn_start = 0
    orig_pages = len(db_only) // ps
    max_pg = 0
    off, idx = 32, 0
    while off + fsz <= len(w):
        pg, commit = be32(w, off), be32(w, off + 4)
        if (be32(w, off + 8), be32(w, off + 12)) != r['salts']:
            r['stop'] = f'salt mismatch at frame {idx} (offset {off})'
            break
        c = wal_checksum(w[off:off + 8], chain[0], chain[1], big)
        c = wal_checksum(w[off + 24:off + fsz], c[0], c[1], big)
        if c != (be32(w, off + 16), be32(w, off + 20)):
            r['stop'] = f'checksum mismatch at frame {idx} (offset {off})'
            break
        if pg == 0:
            r['stop'] = f'page number 0 at frame {idx}'
            break
        chain = c
        max_pg = max(max_pg, pg)
        if commit:
            if commit > max(orig_pages, max_pg) or commit * ps > MAX_IMAGE:
                r['stop'] = f'bad commit size {commit} at frame {idx}'
                break
            bad = next((i for i in range(txn_start, idx + 1) if be32(w, 32 + i * fsz) > commit), None)
            if bad is not None:
                r['stop'] = f'page {be32(w, 32 + bad * fsz)} beyond commit size at frame {bad}'
                break
            last = (idx, commit)
            r['commits'] += 1
            txn_start = idx + 1
        r['frames_valid'] += 1
        idx += 1
        off += fsz
    if r['stop'] is None and off < len(w):
        r['stop'] = f'truncated frame at offset {off}'
    if last is None:
        r['ignored_tail'] = r['frames_valid']
        return db_only
    li, db_pages = last
    r['frames_applied'] = li + 1
    r['ignored_tail'] = r['frames_valid'] - r['frames_applied']
    m = bytearray(db_only[:db_pages * ps])
    m.extend(b'\x00' * (db_pages * ps - len(m)))
    for i in range(li + 1):
        o = 32 + i * fsz
        pg = be32(w, o)
        if pg > db_pages:
            continue
        m[(pg - 1) * ps:pg * ps] = codec.page(w[o + 24:o + fsz], pg == 1)
    return bytes(m)


def text_lossless(b):
    """UTF-8 text with every invalid byte kept as \\xNN (mpdbx sqldb::text_lossless)."""
    out = []
    i, n = 0, len(b)
    while i < n:
        try:
            out.append(b[i:].decode('utf-8'))
            break
        except UnicodeDecodeError as e:
            out.append(b[i:i + e.start].decode('utf-8'))
            bad = max(1, e.end - e.start)
            out.extend(f'\\x{x:02x}' for x in b[i + e.start:i + e.start + bad])
            i += e.start + bad
    return ''.join(out)


def read_image(img):
    """{name: dict(columns, rows=[(key, values)], error)} for one decrypted image; the connection (and any temporary
    file) is closed before returning. Raises ValueError when SQLite cannot read the schema at all."""
    b = bytearray(img)
    b[18] = b[19] = 1
    b[28:32] = b'\x00\x00\x00\x00'  # in-header page count: let SQLite size the database from the buffer
    tmpdir = None
    con = sqlite3.connect(':memory:', check_same_thread=False)
    try:
        if hasattr(con, 'deserialize'):
            con.deserialize(bytes(b))
        else:
            con.close()
            tmpdir = tempfile.mkdtemp(prefix='mpdbx_')
            p = os.path.join(tmpdir, 'image.db')
            with open(p, 'wb') as fh:
                fh.write(b)
            con = sqlite3.connect(f'file:{p}?mode=ro', uri=True, check_same_thread=False)
        con.text_factory = text_lossless
        try:
            con.execute('SELECT count(*) FROM sqlite_master').fetchone()
            names = [(r[0], r[1]) for r in con.execute("SELECT name, coalesce(sql,'') FROM sqlite_master WHERE type='table' ORDER BY name")]
        except sqlite3.Error as e:
            raise ValueError(str(e))
        return {n: _read_table(con, n, s) for n, s in names if not n.startswith('sqlite_') or n in ('sqlite_sequence', 'sqlite_stat1')}
    finally:
        con.close()
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


def _q(n):
    return '"' + n.replace('"', '""') + '"'


def _read_table(con, name, sql):
    t = dict(columns=[], rows=[], error=None)
    tail = sql.upper().rsplit(')', 1)[-1]
    words = [w for w in re.split(r'[\s,]+', tail) if w]
    without_rowid = any(words[i] == 'WITHOUT' and words[i + 1] == 'ROWID' for i in range(len(words) - 1))
    try:
        info = [(r[1], r[5], r[6]) for r in con.execute(f'PRAGMA table_xinfo({_q(name)})')]
    except sqlite3.Error as e:
        t['error'] = str(e)
        return t
    if not info:
        t['error'] = 'no column metadata'
        return t
    cols = [(c[0], c[1]) for c in info if c[2] != 1]
    pk = [i for _, i in sorted((c[1], i) for i, c in enumerate(cols) if c[1] > 0)]
    alias = None
    if not without_rowid:
        alias = next((a for a in ('rowid', '_rowid_', 'oid') if not any(c[0].lower() == a for c in cols)), None)
    t['columns'] = [c[0] for c in cols]
    sel = ', '.join(_q(c) for c in t['columns'])
    try:
        cur = con.execute(f'SELECT {alias}, {sel} FROM {_q(name)}' if alias else f'SELECT {sel} FROM {_q(name)}')
        for r in cur:
            if alias:
                t['rows'].append((('rowid', r[0]), tuple(r[1:])))
            else:
                v = tuple(r)
                t['rows'].append((('pk', tuple(_canon(v[i]) for i in pk)) if pk else ('row', tuple(_canon(x) for x in v)), v))
    except sqlite3.Error as e:
        t['rows'] = []
        t['error'] = str(e)
    return t


def _canon(v):
    """Type-tagged, hashable form of one SQLite value (floats bitwise), so 1 and 1.0 differ as in mpdbx."""
    if v is None:
        return (0,)
    if isinstance(v, int):
        return (1, v)
    if isinstance(v, float):
        return (2, struct.pack('<d', v))
    if isinstance(v, str):
        return (3, v)
    return (4, bytes(v))


def _enc(c):
    tag = c[0]
    if tag == 0:
        return b'\x00'
    if tag == 1:
        return b'\x01' + struct.pack('<q', c[1])
    if tag == 2:
        return b'\x02' + c[1]
    d = c[1].encode('utf-8') if tag == 3 else c[1]
    return bytes([tag]) + struct.pack('<Q', len(d)) + d


def _key_bytes(k):
    if k[0] == 'rowid':
        return b'\x00' + struct.pack('<q', k[1])
    return (b'\x01' if k[0] == 'pk' else b'\x02') + b''.join(_enc(c) for c in k[1])


def _row_eq(a, b):
    return len(a) == len(b) and all(_canon(x) == _canon(y) for x, y in zip(a, b))


def _classify_table(base, merged):
    """(rows [(key, values, status, old)], error, db_only count, merged count) — mpdbx provenance::classify_table."""
    if merged['error']:
        ok = base is not None and not base['error']
        src = base['rows'] if ok else []
        return [(k, v, 'unknown', None) for k, v in src], merged['error'], (len(src) if ok else None), None
    if base is not None and base['error']:
        return [(k, v, 'unknown', None) for k, v in merged['rows']], base['error'], None, len(merged['rows'])
    if base is None:
        return [(k, v, 'WAL-only', None) for k, v in merged['rows']], None, 0, len(merged['rows'])
    old = {k: v for k, v in base['rows']}
    res = []
    for k, v in merged['rows']:
        if k in old:
            ov = old.pop(k)
            res.append((k, v, 'DB', None) if _row_eq(ov, v) else (k, v, 'WAL-modified', ov))
        else:
            res.append((k, v, 'WAL-only', None))
    for k in sorted(old, key=_key_bytes):
        res.append((k, old[k], 'Removed by WAL', old[k]))
    return res, None, len(base['rows']), len(merged['rows'])


def classify(a, b):
    out = {}
    for name, tb in b.items():
        rows, err, n0, n1 = _classify_table(a.get(name), tb)
        out[name] = dict(columns=tb['columns'] or (a[name]['columns'] if name in a else []), rows=rows, error=err, db_only=n0, merged=n1)
    for name, ta in a.items():
        if name not in out:
            rows, err, n0, n1 = _classify_table(ta, dict(columns=[], rows=[], error=None))
            out[name] = dict(columns=ta['columns'], rows=rows, error=err, db_only=n0, merged=n1)
    return out


def classify_unknown(b, err):
    """DB-only image unreadable: every merged row has unknown provenance."""
    return {name: dict(columns=tb['columns'], rows=[(k, v, 'unknown', None) for k, v in tb['rows']], error=tb['error'] or err,
                       db_only=None, merged=None if tb['error'] else len(tb['rows'])) for name, tb in b.items()}


# ===================================================================== time / value helpers
def plausible(v):
    if isinstance(v, bool) or not isinstance(v, int):
        return None
    return v if PLAUSIBLE_MIN <= v < PLAUSIBLE_MAX else None


def fmt_ft(t, tz=0):
    local = t + tz * 600000000
    if local < 0 or local > REPRESENTABLE_MAX:
        return f'{t} (raw)'
    days, rem = divmod(local, 864000000000)
    d = _dt.date(1601, 1, 1) + _dt.timedelta(days=days)
    secs, frac = divmod(rem, 10000000)
    return f'{d.year:04}-{d.month:02}-{d.day:02} {secs // 3600:02}:{secs // 60 % 60:02}:{secs % 60:02}.{frac:07}{tz_suffix(tz)}'


def tz_suffix(tz):
    if tz == 0:
        return 'Z'
    a = abs(tz)
    return f"{'-' if tz < 0 else '+'}{a // 60:02}:{a % 60:02}"


def parse_tz(s):
    """'Z', 'UTC', '+HH:MM', '-HH:MM' (|offset| <= 14:00) -> minutes; None when invalid."""
    s = s.strip()
    if not s.isascii():
        return None
    if s.lower() in ('z', 'utc'):
        return 0
    m = re.fullmatch(r'([+-])([0-9]{2}):([0-9]{2})', s)
    if not m:
        return None
    h, mi = int(m.group(2)), int(m.group(3))
    if mi >= 60 or h * 60 + mi > 840:
        return None
    return (1 if m.group(1) == '+' else -1) * (h * 60 + mi)


def ft_classified(v, tz=0):
    if v == 0:
        return '0 (zero)'
    if v in (-1, 2 ** 63 - 1):
        return f'{v} (max)'
    if v < 0 or v > REPRESENTABLE_MAX:
        return f'{v} (opaque)'
    if PLAUSIBLE_MIN <= v < PLAUSIBLE_MAX:
        return fmt_ft(v, tz)
    return f'{fmt_ft(v, tz)} (implausible)'


def parse_time(s, tz=0):
    """ISO 8601 subset YYYY-MM-DD[(T| )HH:MM[:SS[.f{1,7}]]][Z|±HH:MM] -> FILETIME (UTC); None when invalid (time.rs)."""
    s = s.strip()
    if len(s) < 10 or not s.isascii():
        return None
    date, rest = s[:10], s[10:]
    m = re.fullmatch(r'([0-9]+)-([0-9]+)-([0-9]+)', date)
    if not m:
        return None
    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if not 1601 <= y <= 9999 or not 1 <= mo <= 12:
        return None
    try:
        day = _dt.date(y, mo, d)
    except ValueError:
        return None
    zone = tz
    if rest.endswith(('Z', 'z')):
        zone, rest = 0, rest[:-1]
    elif len(rest) >= 6 and rest[-6] in '+-' and rest[-3] == ':':
        zone = parse_tz(rest[-6:])
        if zone is None:
            return None
        rest = rest[:-6]
    ticks = 0
    if rest:
        if rest[0] not in 'T ':
            return None
        t = rest[1:]
        hms, _, frac = t.partition('.')
        parts = hms.split(':')
        if not 2 <= len(parts) <= 3 or any(len(p) != 2 or not p.isdigit() for p in parts):
            return None
        h, mi, se = int(parts[0]), int(parts[1]), int(parts[2]) if len(parts) == 3 else 0
        if h > 23 or mi > 59 or se > 59:
            return None
        if '.' in t:
            if len(parts) != 3 or not frac or len(frac) > 7 or not frac.isdigit():
                return None
            ticks += int(frac) * 10 ** (7 - len(frac))
        ticks += (h * 3600 + mi * 60 + se) * 10000000
    utc = (day - _dt.date(1601, 1, 1)).days * 864000000000 + ticks - zone * 600000000
    return utc if 0 <= utc <= REPRESENTABLE_MAX else None


def _rust_float(f):
    if f != f:
        return 'NaN'
    if f in (float('inf'), float('-inf')):
        return 'inf' if f > 0 else '-inf'
    r = repr(f)
    if 'e' in r or 'E' in r:
        r = format(decimal.Decimal(r), 'f')
    return r[:-2] if r.endswith('.0') else r


def raw_of(v):
    if v is None:
        return ''
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).hex()
    if isinstance(v, float):
        return _rust_float(v)
    return str(v)


def leaf(p):
    return re.split(r'[\\/]', p or '')[-1]


def _hex64(v):
    return f'{v & 0xFFFFFFFFFFFFFFFF:X}'


def reg_type_name(t):
    names = {0: 'REG_NONE', 1: 'REG_SZ', 2: 'REG_EXPAND_SZ', 3: 'REG_BINARY', 4: 'REG_DWORD', 5: 'REG_DWORD_BIG_ENDIAN', 6: 'REG_LINK',
             7: 'REG_MULTI_SZ', 8: 'REG_RESOURCE_LIST', 9: 'REG_FULL_RESOURCE_DESCRIPTOR', 10: 'REG_RESOURCE_REQUIREMENTS_LIST', 11: 'REG_QWORD'}
    return names.get(t, f'0x{_hex64(t)} (unknown)')


def _utf16z(b):
    words = [b[i:i + 2] for i in range(0, len(b) // 2 * 2, 2)]
    segs, cur = [], []
    for w in words:
        if w == b'\x00\x00':
            segs.append(b''.join(cur))
            cur = []
        else:
            cur.append(w)
    segs.append(b''.join(cur))
    return [s.decode('utf-16-le', 'replace') for s in segs]


def reg_data(t, b):
    """Registry data by type; malformed lengths fall back to hex (values.rs reg_data)."""
    n = len(b)
    if t == 4 and n == 4:
        return str(struct.unpack('<I', b)[0])
    if t == 5 and n == 4:
        return str(struct.unpack('>I', b)[0])
    if t == 11 and n == 8:
        return str(struct.unpack('<Q', b)[0])
    if t in (1, 2) and n % 2 == 0:
        return _utf16z(b)[0]
    if t == 7 and n % 2 == 0:
        return ' | '.join(s for s in _utf16z(b) if s)
    return bytes(b).hex()


def enum_name(field, v):
    known = {('SCANREASON', 2): 'on-open', ('SCANREASON', 5): 'on-close after write'}.get((field, v))
    return known or f'0x{_hex64(v)} (unknown)'


def flag_bits(v):
    v &= 0xFFFFFFFFFFFFFFFF
    if v == 0:
        return '0x0'
    return f"0x{v:X} = bits {','.join(str(i) for i in range(64) if v >> i & 1)}"


def fmt_guid(b):
    if len(b) != 16:
        return None
    d1, d2, d3 = struct.unpack('<IHH', b[:8])
    return '{' + f'{d1:08X}-{d2:04X}-{d3:04X}-{b[8]:02X}{b[9]:02X}-{bytes(b[10:]).hex().upper()}' + '}'


KNOWN_FOLDERS = {
    '{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}': 'Desktop', '{FDD39AD0-238F-46AF-ADB4-6C85480369C7}': 'Documents',
    '{374DE290-123F-4565-9164-39C4925E467B}': 'Downloads', '{4BD8D571-6D19-48D3-BE97-422220080E43}': 'Music',
    '{33E28130-4E1E-4676-835A-98395C3BC3BB}': 'Pictures', '{18989B1D-99B5-455B-841C-AB7C74E4DDFC}': 'Videos',
    '{1777F761-68AD-4D8A-87BD-30B759FA33DD}': 'Favorites', '{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}': 'Public Desktop',
    '{ED4824AF-DCE4-45A8-81E2-FC7965083634}': 'Public Documents', '{3214FAB5-9757-4298-BB61-92A9DEAA44FF}': 'Public Music',
    '{B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5}': 'Public Pictures', '{2400183A-6185-49FB-A2D8-4A392A602BA3}': 'Public Videos'}
GUID_COLUMNS = ('guid', 'ruleid', 'hipsinjectionid', 'folderguardid', 'lsassreadmemid')


def decode_cell(name, v, tz=0):
    """(display, raw) for any table cell by column name (load.rs decode_cell)."""
    raw = raw_of(v)
    timeish = name.endswith('Time') or name.endswith('TS') or 'TimeStamp' in name
    if isinstance(v, int) and not isinstance(v, bool):
        if timeish:
            return ft_classified(v, tz), raw
        if name in ('ProcessIntegrity', 'ProcessTaintReason', 'Action', 'RuleAction', 'State'):
            return enum_name(name, v), raw
        if 'Flags' in name:
            return flag_bits(v), raw
    if isinstance(v, (bytes, bytearray)) and len(v) == 16 and (name.lower() in GUID_COLUMNS or name.endswith('Guid')):
        return fmt_guid(v), raw
    return raw, raw


def file_ref(fid, vsn):
    v = fid & 0xFFFFFFFFFFFFFFFF
    return f'{v & 0xFFFFFFFFFFFF}-{v >> 48}', f'{(vsn & 0xFFFFFFFF) >> 16:04X}-{vsn & 0xFFFF:04X}'


def _uint(s, bits):
    """Rust str::parse::<uN>: optional '+', ASCII digits, in range."""
    if not re.fullmatch(r'\+?[0-9]{1,40}', s):
        return None
    v = int(s)
    return v if v < 2 ** bits else None


# ===================================================================== paths
def split_tag(s):
    m = re.match(r'^ENG:([A-Z0-9_]+):(.*)$', s, re.S)
    return (f'ENG:{m.group(1)}', m.group(2)) if m else (None, s)


def parse_path(s):
    """-> (kind, arg, components, tag)   kind: drive|device|sysroot|unc|vguid|other (normalize/path.rs)."""
    tag, body = split_tag(s)
    n = body.replace('/', '\\')

    def comps(rest):
        r = rest[1:] if rest.startswith('\\') else rest
        if not r:
            return []
        v = r.split('\\')
        if v and v[-1] == '':
            v.pop()
        return v

    def drive(x):
        if len(x) >= 2 and x[0].isascii() and x[0].isalpha() and x[1] == ':' and (len(x) == 2 or x[2] == '\\'):
            return x[0].upper(), x[2:]
        return None

    for vp in ('\\\\?\\', '\\??\\', '\\\\.\\'):
        if n[:len(vp)].lower() == vp.lower():
            rest = n[len(vp):]
            if rest[:4].lower() == 'unc\\':
                return ('unc', None, comps(rest[4:]), tag)
            d = drive(rest)
            if d:
                return ('drive', d[0], comps(d[1]), tag)
            if rest[:7].lower() == 'volume{':
                return ('vguid', None, comps(rest), tag)
            return ('other', None, [n], tag)
    p = '\\device\\harddiskvolume'
    if n[:len(p)].lower() == p:
        rest = n[len(p):]
        dg = re.match(r'[0-9]*', rest).group(0)
        tail = rest[len(dg):]
        num = int(dg) if dg and len(dg) <= 10 else None
        if num is not None and num <= 0xFFFFFFFF and (tail == '' or tail.startswith('\\')):
            return ('device', num, comps(tail), tag)
    if n[:11].lower() == '\\systemroot' and (len(n) == 11 or n[11] == '\\'):
        return ('sysroot', None, comps(n[11:]), tag)
    d = drive(n)
    if d:
        return ('drive', d[0], comps(d[1]), tag)
    if n.startswith('\\\\'):
        return ('unc', None, comps(n[2:]), tag)
    return ('other', None, [n], tag)


def upper(s):
    return ''.join(c.upper() if len(c.upper()) == 1 else c for c in s)


def infer_volmap(paths):
    dev, drv = {}, {}
    for kind, arg, comps, _ in paths:
        if not comps:
            continue
        rel = '\\'.join(upper(c) for c in comps)
        if kind == 'device':
            dev.setdefault(arg, set()).add(rel)
        elif kind == 'drive':
            drv.setdefault(arg, set()).add(rel)
    vm = {}
    for n, dp in dev.items():
        hits = [(d, dp & xp) for d, xp in drv.items() if dp & xp]
        if len(hits) == 1 and len(hits[0][1]) >= 2:
            vm[n] = hits[0][0]
    win = [d for d, ps in drv.items() if any(p == 'WINDOWS' or p.startswith('WINDOWS\\') for p in ps)]
    return vm, (win[0] if len(win) == 1 else None)


def path_key(p, vm, sysroot):
    kind, arg, comps, _ = p
    j = lambda pre, cs: pre + ''.join('\\' + upper(c) for c in cs)
    if kind == 'drive':
        return j(f'{arg}:', comps)
    if kind == 'device':
        return j(f'{vm[arg]}:', comps) if arg in vm else j(f'\\DEVICE\\HARDDISKVOLUME{arg}', comps)
    if kind == 'sysroot':
        return j(f'{sysroot}:', ['WINDOWS'] + comps) if sysroot else j('\\SYSTEMROOT', comps)
    if kind == 'unc':
        return '\\' + j('', comps)
    if kind == 'vguid':
        return j('\\\\?', comps)
    return upper('\\'.join(comps))


def loc_class(p, vm):
    kind, arg, comps, _ = p
    if kind == 'sysroot':
        return 'system dir'
    if kind == 'device' and arg not in vm:
        return 'unknown'
    if kind in ('drive', 'device'):
        c = upper(comps[0]) if comps else None
        return 'system dir' if c in ('WINDOWS', 'PROGRAM FILES', 'PROGRAM FILES (X86)') else 'outside system dirs'
    return 'unknown'


# ===================================================================== events
KIND_LABEL = {
    'ProcessFirstStart': 'Process first start', 'ModuleFirstLoad': 'Module first load', 'NoCertExec': 'No-cert execution',
    'OfnSet': 'OriginalFileName set', 'OfnSetInferred': 'OriginalFileName (inferred)', 'OfnProcessed': 'OFN processed',
    'FileContext': 'Defender file context', 'LowFiHit': 'LowFi signature hit', 'FileHashed': 'File hashed',
    'StoreExpiry': 'Store cache expiry', 'RegistryChange': 'Registry change', 'QueueEntry': 'Queue entry', 'RdpLogon': 'RDP logon',
    'BmRecord': 'Behaviour-monitor record'}
ROUTINE = {'ModuleFirstLoad', 'FileHashed', 'StoreExpiry', 'OfnProcessed', 'FileContext'}
WAL_STATUSES = ('WAL-only', 'WAL-modified', 'Removed by WAL')
BM_EXTRA = ('RansomwareDetections', 'ProcessBlockHistory', 'SystemFileCache')
DIGEST_FIELDS = {'md5': 'MD5 (column SHA1)', 'sha1': 'SHA1 (column MD5)', 'sha256': 'SHA256 (column SHA256)'}


class Event:
    __slots__ = ('id', 'kind', 'time', 'summary', 'loc', 'fields', 'table', 'key', 'status', 'old', 'flag', 'text')

    def field(self, name):
        for f in self.fields:
            if f[0] == name:
                return f[1]
        return None


class Location:
    __slots__ = ('id', 'key', 'spellings', 'cls', 'events')


def rename_kind(fname, ofn):
    f, o = fname.lower(), ofn.lower()
    ext = f.rsplit('.', 1)[-1]
    if re.search(r'\.(mui|efi|tlb)(_[0-9a-f]{8})?$', f) or re.search(r'_[0-9a-f]{8}$', f) or re.fullmatch(r'[0-9a-f]{40}', ext) \
            or o.endswith('.mui') or re.match(r'^[0-9a-f]+_[0-9]+\.[0-9]+', f):
        return 'resource/component'
    if re.search(r'\.(exe|dll|sys|scr|com|cpl|ocx)$', f):
        return 'executable rename'
    return 'other'


def looks_like_ofn(ctx, path):
    return bool(re.fullmatch(r'[\w.\- ]+\.(exe|dll|sys|com|scr|ocx|cpl|mui|efi|drv)', ctx, re.I | re.A)) and ctx.lower() != leaf(path).lower()


def _tact(name):
    """'Tact-pid:<N>,ProcessStart:<FT>[-suffix]' -> (pid, start, suffix) (queues.rs tact + store.rs parse_pid_start)."""
    if not name.startswith('Tact-'):
        return None
    rest = name[5:]
    s = rest.strip()
    if not s.startswith('pid:') or ',' not in s[4:]:
        return None
    pid_s, r2 = s[4:].split(',', 1)
    if not r2.startswith('ProcessStart:'):
        return None
    digits = re.match(r'[0-9]*', r2[13:]).group(0)
    pid, start = _uint(pid_s, 32), _uint(digits, 64)
    if pid is None or start is None or 'ProcessStart:' not in rest:
        return None
    tail = rest.split('ProcessStart:', 1)[1].lstrip('0123456789')
    if tail == '':
        return pid, start, ''
    if tail.startswith('-') and len(tail) > 1:
        return pid, start, tail[1:]
    return None


def _json_scalar(v):
    return v is None or isinstance(v, str) or (isinstance(v, (int, float)) and not isinstance(v, bool))


def _json_ft(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v if 0 <= v < 2 ** 64 else None
    if isinstance(v, str):
        return _uint(v.strip(), 64) if not v.strip().startswith('+') else None
    return None


def _json_str(v):
    if v is None:
        return ''
    if isinstance(v, str):
        return v
    return json.dumps(v)


def decode_queue(table, key, value):
    """-> list of (fact, data) — decode/queues.rs (Threat, Host, Process, Dropped, Rdp, RdpLogon, Address, Generic)."""
    t = _tact(table) or _tact(key)
    if t:
        v = [('Process', t)]
        if not _tact(key):
            v.append(('Generic', (key, value)))
        return v
    if table == 'RecentThreatsOnMachine':
        return [('Threat', (key, value))]
    if table == 'domainInfo':
        if key == 'TCP-hostname':
            return [('Host', ('hostname', value))]
        parts = key.split('.')
        v4 = len(parts) == 4 and all(_uint(o, 8) is not None for o in parts)
        f = _uint(value.strip(), 64)
        if f is not None and key:
            return [('Host', ('ipv4' if v4 else 'name', f'{key} (flags {f:#x}, meaning unverified)'))]
        return [('Generic', (key, value))]
    if table in ('RQ_RecentExecDropped', 'RQ_RecentScriptDropped'):
        return [('Dropped', (key, table == 'RQ_RecentScriptDropped'))]
    if table == 'RDP-Event-Success':
        def bad_const(x):
            raise ValueError(x)
        try:
            j = json.loads(value, parse_constant=bad_const)
        except (ValueError, RecursionError):
            j = None
        if isinstance(j, dict) and all(_json_scalar(j[k]) for k in ('Wsn', 'SLId', 'Ip', 'TSid', 'LT') if k in j) \
                and ('LT' not in j or _json_ft(j['LT']) is not None):
            lt = _json_ft(j['LT']) if 'LT' in j else None
            g = lambda k: _json_str(j.get(k))
            return [('RdpLogon', dict(time=lt, ip=g('Ip'), sid=g('SLId'), ws=g('Wsn'), session=g('TSid')))]
        return [('Generic', (key, value))]
    if table.startswith('RDP-'):
        return [('Rdp', (table, f'{key}={value}'))]
    if table == 'KernelCallBackAddress':
        s = value.strip()
        a = (int(s[2:], 16) if re.fullmatch(r'0[xX][0-9a-fA-F]{1,16}', s) else _uint(s, 64))
        if key.startswith('fn_AddressRange') and a is not None:
            return [('Address', (key, a))]
    return [('Generic', (key, value))]


def _read(p):
    with open(p, 'rb') as fh:
        if os.fstat(fh.fileno()).st_size > MAX_INPUT:
            raise ValueError(f'{p} is larger than 2 GiB')
        b = fh.read(MAX_INPUT + 1)
    if len(b) > MAX_INPUT:
        raise ValueError(f'{p} is larger than 2 GiB')
    return b


def _mtime(p):
    try:
        st = os.stat(p).st_mtime_ns
        return fmt_ft(st // 100 + 116444736000000000)
    except OSError:
        return ''


def _text(v):
    if isinstance(v, str):
        return v
    if isinstance(v, int) and not isinstance(v, bool):
        return str(v)
    return None


def _int(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if re.fullmatch(r'[+-]?[0-9]{1,19}', s):
            x = int(s)
            if -2 ** 63 <= x < 2 ** 63:
                return x
    return None


class Case:
    """Everything loaded from one Scans folder copy."""

    def __init__(self, path, tz=0, progress=lambda s: None):
        self.tz = tz
        self.path = path
        db = os.path.join(path, 'mpenginedb.db') if os.path.isdir(path) else path
        if not os.path.isfile(db):
            raise ValueError(f'no mpenginedb.db at {path}')
        self.warnings = []
        progress('reading files')
        raw = _read(db)
        self.inputs = [(db, len(raw), hashlib.sha256(raw).hexdigest(), _mtime(db))]
        wal = None
        wp = db + '-wal'
        if os.path.isfile(wp):
            try:
                wal = _read(wp)
                self.inputs.append((wp, len(wal), hashlib.sha256(wal).hexdigest(), _mtime(wp)))
            except (OSError, ValueError) as e:
                self.warnings.append(f'WAL unreadable ({e}); loaded the database alone')
        progress('decrypting and replaying the WAL')
        self.img = build_images(raw, wal)
        self.warnings.extend(self.img['notes'])
        progress('reading tables')
        try:
            b = read_image(self.img['merged'])
        except ValueError as e:
            raise ValueError(f'merged image unreadable: {e}')
        try:
            a = b if self.img['merged'] is self.img['db_only'] else read_image(self.img['db_only'])
            self.tables = classify(a, b)
        except ValueError as e:
            self.warnings.append(f'DB-only image unreadable ({e}); provenance unknown')
            self.tables = classify_unknown(b, str(e))
        progress('building events')
        self.events, self.locations, self.host = [], [], []
        self._loc_index = {}
        self._load()
        progress('indexing')
        for e in self.events:
            key = self.locations[e.loc].key if e.loc is not None else ''
            e.text = ' '.join([e.summary, self.path_of(e), key, KIND_LABEL.get(e.kind, e.kind)] + [f'{f[1]} {f[2]}' for f in e.fields]).lower()

    # ---- loading
    def _cols(self, t):
        return {c.lower(): i for i, c in enumerate(self.tables[t]['columns'])}

    def _load(self):
        paths = []
        for t, c in (('BackupProcessInfo', 'FilePath'), ('AttributePersistContext', 'FilePath'), ('FileLowFiAsync', 'FileName'),
                     ('BmProcessInfo', 'ImageFileName'), ('BmFileInfo', 'DosPath'), ('BmFileInfo', 'NormalizedPath'), ('BmFileStartupActions', 'FilePath'),
                     ('ProcessBlockHistory', 'ProcessPath'), ('ProcessBlockHistory', 'TargetPath'), ('SystemFileCache', 'SystemFilePath')):
            if t in self.tables:
                i = self._cols(t).get(c.lower())
                if i is not None:
                    for _, v, _, _ in self.tables[t]['rows']:
                        s = _text(v[i] if i < len(v) else None)
                        if s is not None:
                            paths.append(parse_path(s))
        if 'RollingQueuesValues' in self.tables:  # dropped-file queues: the key is a path
            idx = self._cols('RollingQueuesValues')
            ti, ki = idx.get('entrytable'), idx.get('entrykey')
            if ti is not None and ki is not None:
                for _, v, _, _ in self.tables['RollingQueuesValues']['rows']:
                    if (_text(v[ti]) if ti < len(v) else None) in ('RQ_RecentExecDropped', 'RQ_RecentScriptDropped'):
                        s = _text(v[ki]) if ki < len(v) else None
                        if s is not None:
                            paths.append(parse_path(s))
        self.volmap, self.sysroot = infer_volmap(paths)
        handlers = {'BackupProcessInfo': self._bpi, 'AttributePersistContext': self._apc, 'FileHashes': self._hashes,
                    'FileLowFiAsync': self._lowfi, 'AmsiFileCache': self._amsi, 'SystemRegistryCache': self._reg,
                    'RollingQueuesValues': self._queues, 'FolderGuardPaths': self._cfa}
        for name in sorted(self.tables):
            tp = self.tables[name]
            if tp['error']:
                self.warnings.append(f"table {name}: {tp['error']}")
            h = handlers.get(name)
            if h:
                h(name)
            elif name in ('SQLiteGlobals', 'DynSigRevisions', 'Engine', 'InventoryState'):
                self._hostrows(name)
            elif name.startswith('Bm') or name in BM_EXTRA:
                self._bm(name)

    def _getter(self, t):
        idx = self._cols(t)

        def mk(v):
            def get(c):
                i = idx.get(c.lower())
                return v[i] if i is not None and i < len(v) else None
            return get
        return idx, mk

    def _rows(self, t, required, what):
        idx, mk = self._getter(t)
        miss = [c for c in required if c.lower() not in idx]
        if miss:
            self.warnings.append(f"table {t} lacks column(s) {', '.join(miss)}; {what} events skipped")
            return
        for k, v, st, old in self.tables[t]['rows']:
            yield k, mk(v), st, old

    def location(self, raw):
        if not raw or not raw.strip():
            return None
        p = parse_path(raw)
        key = path_key(p, self.volmap, self.sysroot)
        lid = self._loc_index.get(key)
        if lid is not None:
            loc = self.locations[lid]
            if raw not in loc.spellings:
                loc.spellings.append(raw)
            return lid
        loc = Location()
        loc.id, loc.key, loc.spellings, loc.cls, loc.events = len(self.locations), key, [raw], loc_class(p, self.volmap), []
        self.locations.append(loc)
        self._loc_index[key] = loc.id
        return loc.id

    def cls(self, lid):
        return self.locations[lid].cls if lid is not None else 'unknown'

    def push(self, kind, time, summary, loc, fields, table, key, st, old, flag):
        e = Event()
        e.id, e.kind, e.time, e.summary, e.loc, e.fields = len(self.events), kind, time, summary, loc, fields
        e.table, e.key, e.status, e.old = table, key, st, old
        e.flag = flag or st in ('WAL-only', 'Removed by WAL')
        e.text = ''
        self.events.append(e)
        if loc is not None:
            self.locations[loc].events.append(e.id)
        return e

    def tf(self, name, v):
        iv = _int(v)
        return (name, ft_classified(iv, self.tz) if iv is not None else '', '' if iv is None else str(iv))

    def _bpi(self, t):
        for k, g, st, old in self._rows(t, ['FilePath', 'FirstStartTime', 'InstanceTimeStamp'], 'process/module first-start'):
            path = _text(g('FilePath')) or ''
            fst, its = _int(g('FirstStartTime')), _int(g('InstanceTimeStamp'))
            loc = self.location(path)
            pf, pi = plausible(fst), plausible(its)
            start = pf if (pf is not None and pi is not None and 0 <= pi - pf <= BPI_MAX_START_LAG) or (pf is not None and pi is None) else None
            raw = '' if fst is None else str(fst)
            if start is not None:
                ff = self.tf('FirstStartTime', fst)
            elif pf is not None:
                ff = ('FirstStartTime', f'{raw} (module value; date-like by chance, not a start time)', raw)
            else:
                ff = ('FirstStartTime', f'{raw} (opaque)', raw)
            fields = [('Path', path, path), ff, self.tf('InstanceTimeStamp', its)]
            u = _int(g('NextUSN'))
            if u is not None:
                fields.append(('NextUSN', str(u), str(u)))
            if start is not None:
                self.push('ProcessFirstStart', start, f'Process first start: {leaf(path)}', loc, fields, t, k, st, old, False)
            else:
                self.push('ModuleFirstLoad', pi, f'Module first load: {leaf(path)}', loc, fields, t, k, st, old, False)

    def _apc(self, t):
        for k, g, st, old in self._rows(t, ['FilePath', 'Context', 'InsertTime'], 'attribute-context'):
            raw_path = _text(g('FilePath')) or ''
            ctx = _text(g('Context')) or ''
            tag, _ = split_tag(raw_path)
            path = raw_path[len(tag) + 1:] if tag else raw_path
            ins = _int(g('InsertTime'))
            loc = self.location(path)
            outside = self.cls(loc) == 'outside system dirs'
            fields = [('Path', path, raw_path), ('Context', ctx, ctx), self.tf('InsertTime', ins), self.tf('ExpireTime', g('ExpireTime'))]
            if tag:
                fields.append(('Engine tag', tag, tag))
            name = leaf(path)
            if tag is None and ctx == 'ExecutedPENoCert':
                kind, summ, flag = 'NoCertExec', f'Execution, no embedded cert: {name}', outside
            elif tag == 'ENG:OFNSET' or (tag is None and looks_like_ofn(ctx, path)):
                inferred = tag is None
                rk = 'same as file name' if ctx.lower() == name.lower() else rename_kind(name, ctx)
                fields += [('OriginalFileName', ctx, ctx), ('Rename kind', rk, rk)]
                kind = 'OfnSetInferred' if inferred else 'OfnSet'
                summ = f"OriginalFileName {ctx} on {name}{' (inferred)' if inferred else ''}"
                flag = rk == 'executable rename' and outside
            elif tag == 'ENG:OFNPROCESSED':
                kind, summ, flag = 'OfnProcessed', f'OFN processed: {name}', False
            else:
                kind, summ, flag = 'FileContext', f'Defender file context {ctx}: {name}', False
            self.push(kind, plausible(ins), summ, loc, fields, t, k, st, old, flag)

    def _hashes(self, t):
        for k, g, st, old in self._rows(t, ['VSN', 'FileID', 'InstanceTimeStamp'], 'file-hash'):
            fid, vsn = g('FileID'), g('VSN')
            ident = file_ref(fid, vsn) if isinstance(fid, int) and isinstance(vsn, int) and not isinstance(fid, bool) else None
            its = _int(g('InstanceTimeStamp'))
            if ident:
                fields = [('FileRef', ident[0], raw_of(fid)), ('Volume serial', ident[1], raw_of(vsn))]
            else:
                fields = [('FileRef', 'missing (FileID or VSN not an integer)', f'{raw_of(fid)} / {raw_of(vsn)}')]
            fields.append(self.tf('InstanceTimeStamp', its))
            for col, label, n in (('SHA1', 'MD5', 16), ('MD5', 'SHA1', 20), ('SHA256', 'SHA256', 32)):
                d = g(col)
                if isinstance(d, (bytes, bytearray)):
                    if len(d) == n:
                        fields.append((f'{label} (column {col})', d.hex(), d.hex()))
                    else:
                        fields.append((f'{label} (column {col}; length {len(d)} ≠ {n}, kept raw)', d.hex(), d.hex()))
            for col in ('USN', 'LSHASH', 'LSHASHS', 'CTPH', 'PartialCRC1', 'PartialCRC2', 'PartialCRC3', 'KCRC1', 'KCRC2', 'KCRC3', 'KCRC3n'):
                v = g(col)
                if v is None:
                    continue
                if col == 'CTPH' and isinstance(v, (bytes, bytearray)):
                    fields.append((col, bytes(v).decode('utf-8', 'replace'), bytes(v).hex()))
                else:
                    fields.append((col, raw_of(v), raw_of(v)))
            summ = f'File hashed: MFT {ident[0]} on {ident[1]}' if ident else 'File hashed: MFT reference missing'
            self.push('FileHashed', plausible(its), summ, None, fields, t, k, st, old, False)

    def _lowfi(self, t):
        for k, g, st, old in self._rows(t, ['FileName', 'InstanceTimeStamp'], 'LowFi'):
            path = _text(g('FileName')) or ''
            loc = self.location(path)
            fields = [('Path', path, path), self.tf('InstanceTimeStamp', g('InstanceTimeStamp'))]
            s = g('SigSha')
            if isinstance(s, (bytes, bytearray)):
                fields.append(('Signature SHA', bytes(s).hex(), bytes(s).hex()))
            q = _int(g('SigSeq'))
            if q is not None:
                fields.append(('SigSeq', str(q), str(q)))
            self.push('LowFiHit', plausible(_int(g('InstanceTimeStamp'))), f'LowFi signature hit: {leaf(path)}', loc, fields, t, k, st, old, False)

    def _amsi(self, t):
        for k, g, st, old in self._rows(t, ['PersistId', 'ExpirationDate'], 'Store-cache expiry'):
            pid, exp = _text(g('PersistId')) or '', _text(g('ExpirationDate')) or ''
            parsed = parse_time(exp, 0)
            fields = [('PersistId (Store file name)', pid, pid), ('ExpirationDate', ft_classified(parsed, self.tz) if parsed is not None else exp, exp)]
            self.push('StoreExpiry', plausible(parsed), f'Store cache expiry: {pid}', None, fields, t, k, st, old, False)

    def _reg(self, t):
        for k, g, st, old in self._rows(t, ['RegPath', 'InstanceTimeStamp'], 'registry-cache'):
            path = _text(g('RegPath')) or ''
            nt = _int(g('NewRegType'))
            ot = _int(g('OldRegType'))
            nt = -1 if nt is None else nt
            ot = -1 if ot is None else ot
            op = _int(g('RegOperation'))
            nd, od = g('NewRegData'), g('OldRegData')
            fields = [('RegPath', path, path), ('RegOperation', enum_name('RegOperation', -1 if op is None else op), raw_of(g('RegOperation'))),
                      ('NewRegType', reg_type_name(nt), str(nt)), ('NewRegData', reg_data(nt, nd) if isinstance(nd, (bytes, bytearray)) else '', raw_of(nd)),
                      ('OldRegType', reg_type_name(ot), str(ot)), ('OldRegData', reg_data(ot, od) if isinstance(od, (bytes, bytearray)) else '', raw_of(od)),
                      self.tf('InstanceTimeStamp', g('InstanceTimeStamp')), ('FileIDHash', raw_of(g('FileIDHash')), raw_of(g('FileIDHash')))]
            self.push('RegistryChange', plausible(_int(g('InstanceTimeStamp'))), f'Registry change: {path}', None, fields, t, k, st, old, False)

    def _queues(self, t):
        for k, g, st, old in self._rows(t, ['EntryTable', 'EntryKey', 'EntryValue', 'InsertTime'], 'rolling-queue'):
            qt, key, val = _text(g('EntryTable')) or '', _text(g('EntryKey')) or '', _text(g('EntryValue')) or ''
            ins = _int(g('InsertTime'))
            fields = [('Queue', qt, qt), ('Key', key, key), ('Value', val, val), self.tf('InsertTime', ins), self.tf('ExpireTime', g('ExpireTime'))]
            flag, loc = False, None
            for fact, d in decode_queue(qt, key, val):
                if fact == 'Threat':
                    flag = True
                    fields.append(('Threat', f'{d[0]} ×{d[1]}', d[0]))
                elif fact == 'Host':
                    self.host.append((f'domainInfo {d[0]}', d[1], t, k, st))
                elif fact == 'Process':
                    fields.append(('Process', f'PID {d[0]} started {ft_classified(d[1], self.tz)}', f'{d[0]},{d[1]}'))
                    if d[2]:
                        fields.append(('Counter set', d[2], d[2]))
                elif fact == 'Dropped':
                    loc = self.location(d[0])
                    fields.append(('Script dropped' if d[1] else 'Executable dropped', d[0], d[0]))
                elif fact == 'Rdp':
                    self.host.append((d[0], d[1], t, k, st))
                elif fact == 'RdpLogon':
                    tm = d['time']
                    fl = [('Source IP', d['ip'], d['ip']), ('User SID', d['sid'], d['sid']), ('Workstation', d['ws'], d['ws']),
                          ('Session', d['session'], d['session']), self.tf('Logon time', tm if tm is None or tm < 2 ** 63 else None)]
                    self.push('RdpLogon', plausible(tm), f"RDP logon success from {d['ip']}", None, fl, t, k, st, old, True)
                elif fact == 'Address':
                    fields.append((d[0], f'{d[1]:#x}', str(d[1])))
                else:
                    fields.append((d[0], d[1], d[1]))
            self.push('QueueEntry', plausible(ins), f'{qt}: {key}', loc, fields, t, k, st, old, flag)

    def _cfa(self, t):
        idx, mk = self._getter(t)
        for k, v, st, old in self.tables[t]['rows']:
            g = mk(v)
            sid = _text(g('UserId')) or ''
            gu = g('GUID')
            guid = (fmt_guid(gu) or '') if isinstance(gu, (bytes, bytearray)) else ''
            name = next((n for gg, n in KNOWN_FOLDERS.items() if gg.lower() == guid.lower()), guid)
            path = _text(g('Path')) or ''
            self.host.append((f'CFA protected folder ({sid})', f'{name} ({path})' if path else name, t, k, st))

    def _hostrows(self, t):
        cols = self.tables[t]['columns']
        idx, mk = self._getter(t)
        for k, v, st, old in self.tables[t]['rows']:
            if t == 'SQLiteGlobals':
                g = mk(v)
                self.host.append(('SQLite schema version', f"{raw_of(g('Version'))} (current {raw_of(g('Current'))}, updated {raw_of(g('LastUpdated'))})", t, k, st))
            else:
                self.host.append((t, ', '.join(f'{n}={raw_of(x)}' for n, x in zip(cols, v)), t, k, st))

    def _bm(self, t):
        idx, mk = self._getter(t)
        cols = self.tables[t]['columns']
        time_col = next((x for x in ('ProcessStartTime', 'TimeStamp', 'DetectionTS', 'LkgTS', 'RemedComplTS', 'InstanceTimeStamp') if x.lower() in idx), None)
        path_col = next((x for x in ('ImageFileName', 'ProcessPath', 'FilePath', 'NormalizedPath', 'DosPath', 'SystemFilePath') if x.lower() in idx), None)
        for k, v, st, old in self.tables[t]['rows']:
            g = mk(v)
            tm = plausible(_int(g(time_col))) if time_col else None
            path = (_text(g(path_col)) if path_col else None) or ''
            loc = self.location(path)
            fields = [(n,) + decode_cell(n, x, self.tz) for n, x in zip(cols, v)]
            self.push('BmRecord', tm, f'{t}: {leaf(path)}', loc, fields, t, k, st, old, False)

    # ---- accessors
    def path_of(self, e):
        return self.locations[e.loc].spellings[0] if e.loc is not None else ''

    def key_label(self, k):
        if k[0] == 'rowid':
            return f'rowid {k[1]}'
        vals = ', '.join(raw_of(c[1] if len(c) > 1 and c[0] != 2 else (struct.unpack('<d', c[1])[0] if c[0] == 2 else None)) for c in k[1])
        return f"{'pk' if k[0] == 'pk' else 'row'} ({vals})"

    def time_str(self, t):
        return fmt_ft(t, self.tz) if t is not None else '—'


# ===================================================================== findings, quick views, search
def _f(**kw):
    d = dict(kinds=None, status=None, cls=None, flagged=False, only=None, special=None)
    d.update(kw)
    return d


def _special_ok(e, special):
    if special == 'renamed_exe':
        return e.kind in ('OfnSet', 'OfnSetInferred') and e.field('Rename kind') == 'executable rename'
    if special == 'detections':
        return (e.kind == 'QueueEntry' and e.field('Threat') is not None) or e.kind == 'LowFiHit'
    return True


def findings(c):
    """[(level, title, explain, ids, examples)] in display order (same cards and rules as mpdbx)."""
    out = []

    def add(level, title, explain, pred):
        ids, ex = set(), []
        for e in c.events:
            if pred(e):
                ids.add(e.id)
                if len(ex) < 3 and e.loc is not None:
                    n = leaf(c.locations[e.loc].spellings[0])
                    if n and n not in ex:
                        ex.append(n)
        out.append((level, title, explain, ids, ex))
    add('flag', 'Unsigned programs run outside system folders',
        'First run of a binary with no embedded certificate, not under Windows or Program Files.',
        lambda e: e.kind == 'NoCertExec' and c.cls(e.loc) == 'outside system dirs')
    add('flag', 'Renamed executables outside system folders',
        "The file's OriginalFileName (set at creation) differs from its name, e.g. a copied robocopy.exe renamed.",
        lambda e: _special_ok(e, 'renamed_exe') and c.cls(e.loc) == 'outside system dirs')
    add('flag', 'Threat detections', 'Behaviour or signature detections Defender keeps in its recent-threats queue.',
        lambda e: e.kind == 'QueueEntry' and e.field('Threat') is not None)
    add('flag', 'RDP logons', 'Successful inbound RDP logons recorded by Defender (source IP, user, workstation).',
        lambda e: e.kind == 'RdpLogon')
    add('flag', 'Rows found only in the WAL (or deleted by it)',
        'Newest activity not yet written into the main database, and rows the WAL removed. (Changed rows: Found only in the WAL view.)',
        lambda e: e.status in ('WAL-only', 'Removed by WAL'))
    add('info', 'Programs started', "First start of each program in Defender's ~7-day window (time = process creation).",
        lambda e: e.kind == 'ProcessFirstStart')
    add('info', 'All unsigned program runs', 'Every first run of a binary without an embedded certificate, including system folders.',
        lambda e: e.kind == 'NoCertExec')
    add('info', 'Signature hits (low-fidelity)', 'Files that matched a low-fidelity signature and were sent for a closer look.',
        lambda e: e.kind == 'LowFiHit')
    add('info', 'File hashes', 'MD5 / SHA1 / SHA256 of files Defender hashed, by MFT reference.',
        lambda e: e.kind == 'FileHashed' and not (e.field('FileRef') or '').startswith('missing'))
    add('info', 'Behaviour-monitor records', 'Rows from the behaviour-monitoring, ransomware, process-block and system-file tables.',
        lambda e: e.kind == 'BmRecord')
    add('info', 'Registry changes', 'Registry values Defender backed up with old and new data.', lambda e: e.kind == 'RegistryChange')
    return out


QUICK_VIEWS = [
    ('All activity', 'everything except routine background records', _f()),
    ('Red flags', 'unsigned runs outside system folders, renamed executables, threats, RDP logons, WAL-only/removed rows', _f(flagged=True)),
    ('Programs run', 'process starts and first runs of unsigned binaries', _f(kinds={'ProcessFirstStart', 'NoCertExec'})),
    ('Unsigned programs', 'first runs of binaries with no embedded certificate', _f(kinds={'NoCertExec'})),
    ('Renamed executables', 'OriginalFileName of an executable differs from its file name (any folder)', _f(special='renamed_exe')),
    ('Detections & signatures', 'threats from the recent-threats queue and low-fidelity signature hits', _f(special='detections')),
    ('Found only in the WAL', 'rows that exist only in, were changed by, or were removed by the WAL', _f(status=set(WAL_STATUSES))),
]

SEARCH_EXAMPLES = [
    ('rustc.exe', 'anything mentioning a name'),
    ('path:c:\\users\\*', 'events under a folder (wildcards * and ?)'),
    ('name:*.ps1', 'by file name'),
    ('sha256:4510b0', 'a hash or part of one'),
    ('type:no-cert', 'one event type (e.g. no-cert, process, originalfilename)'),
    ('src:wal-only', 'rows that exist only in the WAL'),
    ('after:2026-10-19 before:2026-10-20', 'a time range (display time zone)'),
    ('-module', 'exclude something (minus sign)'),
    ('/mimi.*katz/', 'regular expression'),
]


def _matcher(pat):
    """Glob with * and ?; without a wildcard: case-insensitive substring (query Glob semantics)."""
    p = pat.lower()
    if '*' in p or '?' in p:
        rx = re.compile('^' + re.escape(p).replace('\\*', '.*').replace('\\?', '.') + '$', re.S)
        return lambda s: bool(rx.match(s.lower()))
    return lambda s: p in s.lower()


SRC_KEYS = {'db': 'DB', 'wal': 'WAL-only', 'walonly': 'WAL-only', 'walmod': 'WAL-modified', 'walmodified': 'WAL-modified',
            'removed': 'Removed by WAL', 'removedbywal': 'Removed by WAL', 'unknown': 'unknown'}
LOC_KEYS = {'system': 'system dir', 'outside': 'outside system dirs', 'unknown': 'unknown'}
SEARCH_KEYS = ('path', 'name', 'sha256', 'sha1', 'md5', 'pid', 'type', 'src', 'loc', 'nocert', 'after', 'before')


def search_tokens(q):
    r"""-> [(negated, token, kind)] with kind 'plain' (may be key:value), 'regex' (/.../) or 'literal' (a quote opened
    before any ':', so free text even if it looks like key:value). Double quotes group words, also after key:
    (path:"C:\Program Files\*"); a /regex/ runs to the next '/' followed by whitespace or the end (as the exe)."""
    out, i, n = [], 0, len(q)
    while i < n:
        if q[i].isspace():
            i += 1
            continue
        neg = False
        if q[i] == '-' and i + 1 < n and not q[i + 1].isspace():
            neg, i = True, i + 1
        if q[i] == '/':
            j = next((j for j in range(i + 1, n) if q[j] == '/' and (j + 1 == n or q[j + 1].isspace())), None)
            if j is not None:
                out.append((neg, q[i + 1:j], 'regex'))
                i = j + 1
                continue
        tok, quoted, kind, key_seen = [], False, 'plain', False
        while i < n and (quoted or not q[i].isspace()):
            ch = q[i]
            if ch == '"':
                if not key_seen:
                    kind = 'literal'
                quoted = not quoted
            else:
                if ch == ':':
                    key_seen = True
                tok.append(ch)
            i += 1
        if quoted:
            raise ValueError('unterminated quote')
        out.append((neg, ''.join(tok), kind))
    return out


def _nocert_locs(c):
    return {e.loc for e in c.events if e.kind == 'NoCertExec' and e.loc is not None}


def _pid_of(e):
    """Process ID an event observes (Tact queue 'Process' fact, BmProcessInfo PID), as the exe's process observations."""
    if e.kind == 'QueueEntry':
        for f in e.fields:
            if f[0] == 'Process':
                return int(f[2].split(',', 1)[0])
    elif e.kind == 'BmRecord' and e.table == 'BmProcessInfo':
        for f in e.fields:
            if f[0] == 'PID':
                try:
                    v = int(f[2])
                except (TypeError, ValueError):
                    return None
                return v if 0 <= v < 2 ** 32 else None
    return None


def _parse(q, tz=0):
    """-> [(negated, test(event, case), cell_test(cells) or None)]; cell_test is set for free text and /regex/, the terms
    that can also be judged on the text a grid row shows. Raises ValueError with a message for a bad term."""
    terms = []
    for neg, t, kind in search_tokens(q):
        if kind == 'regex':
            try:
                rx = re.compile(t, re.I)
            except re.error as ex:
                raise ValueError(f'bad regular expression: {ex}')
            terms.append((neg, lambda e, c, rx=rx: bool(rx.search(e.text)), lambda cells, rx=rx: any(rx.search(str(x)) for x in cells)))
            continue
        m = re.match(r'^([A-Za-z0-9]+):(.*)$', t, re.S) if kind == 'plain' else None
        if not m or m.group(1).lower() not in SEARCH_KEYS:
            s = t.lower()
            terms.append((neg, lambda e, c, s=s: s in e.text, lambda cells, s=s: any(s in str(x).lower() for x in cells)))
            continue
        k, v = m.group(1).lower(), m.group(2)
        if not v:
            raise ValueError(f'{k}: needs a value')
        if k in ('after', 'before'):
            ft = parse_time(v, tz)
            if ft is None:
                raise ValueError(f'{k}:{v} is not a date (use YYYY-MM-DD or YYYY-MM-DD HH:MM)')
            test = (lambda e, c, ft=ft: e.time is not None and e.time >= ft) if k == 'after' \
                else (lambda e, c, ft=ft: e.time is not None and e.time <= ft)
        elif k == 'path':
            g = _matcher(v)

            def test(e, c, g=g):
                if e.loc is None:
                    return False
                l = c.locations[e.loc]
                return g(l.key) or any(g(s) for s in l.spellings)
        elif k == 'name':
            g = _matcher(v)
            test = lambda e, c, g=g: e.loc is not None and g(c.locations[e.loc].key.rsplit('\\', 1)[-1])
        elif k in DIGEST_FIELDS:
            # no wildcard: a prefix, as the exe
            g, lab = _matcher(v if ('*' in v or '?' in v) else v + '*'), DIGEST_FIELDS[k]
            test = lambda e, c, g=g, lab=lab: e.kind == 'FileHashed' and not (e.field('FileRef') or '').startswith('missing') \
                and any(f[0] == lab and g(f[1]) for f in e.fields)
        elif k == 'pid':
            if not re.fullmatch(r'[0-9]+', v) or int(v) >= 2 ** 32:
                raise ValueError(f'pid:{v} is not a number')
            pid = int(v)
            test = lambda e, c, pid=pid: _pid_of(e) == pid
        elif k == 'type':
            g = _matcher(v)
            test = lambda e, c, g=g: g(e.kind) or g(KIND_LABEL.get(e.kind, e.kind))
        elif k == 'src':
            want = SRC_KEYS.get(v.lower().replace('-', '').replace(' ', ''))
            if want is None:
                raise ValueError(f'src:{v} — use db, walonly, walmod, removed, unknown')
            test = lambda e, c, want=want: e.status == want
        elif k == 'loc':
            want = LOC_KEYS.get(v.lower())
            if want is None:
                raise ValueError(f'loc:{v} — use system, outside, unknown')
            test = lambda e, c, want=want: c.cls(e.loc) == want
        else:  # nocert
            if v.lower() != 'yes':
                raise ValueError("nocert: takes only 'yes'")

            def test(e, c):
                if getattr(c, '_nocert', None) is None:
                    c._nocert = _nocert_locs(c)
                return e.loc is not None and e.loc in c._nocert
        terms.append((neg, test, None))
    return terms


def parse_search(q, tz=0):
    """-> list of (negate, test(event, case)->bool). Raises ValueError with a message for a bad term."""
    return [(n, t) for n, t, _ in _parse(q, tz)]


def row_events(c, name, evs, i):
    """The events a Files & processes row stands for: its own event, or every event at a location (Locations view)."""
    if evs:
        return [evs[i]]
    if name == 'Locations' and i < len(c.locations):
        return [c.events[j] for j in c.locations[i].events]
    return []


def row_filter(c, q, tz=0):
    """keep(cells, events) for a Files & processes view (events: what the row stands for, see row_events; one Event or
    None is accepted too). A query with structured terms (path:, sha256:, type:, ...) is judged on the row's events
    exactly as the Timeline does; rows without events cannot satisfy it. A free-text / regex query is judged term by
    term on the row's events and on the text shown in its cells. Unparsable search: plain substring over the cells."""
    q = q.strip()
    if not q:
        return lambda cells, e: True
    try:
        terms = _parse(q, tz)
    except ValueError:
        low = q.lower()
        return lambda cells, e: any(low in str(x).lower() for x in cells)

    def evlist(e):
        return [] if e is None else [e] if isinstance(e, Event) else list(e)
    if any(cell is None for _, _, cell in terms):
        ids = {e.id for e in apply(c, _f(), [(n, t) for n, t, _ in terms], True)}
        return lambda cells, e: any(x.id in ids for x in evlist(e))

    def keep(cells, e):
        es = evlist(e)
        return all((cell(cells) or any(t(x, c) for x in es)) != neg for neg, t, cell in terms)
    return keep


def apply(c, facets, terms, show_routine):
    """Events matching the filters and search, oldest first (untimed last). Routine types are hidden from broad lists only:
    a search, a type filter, an event set, a quick-view predicate, red flags or a WAL status shows its routine matches too."""
    out = []
    kinds = facets['kinds']
    targeted = facets['only'] is not None or facets.get('special') is not None or facets['flagged'] or facets['status'] is not None or terms
    if kinds is None and not show_routine and not targeted:
        kinds = {k for k in KIND_LABEL if k not in ROUTINE}
    for e in c.events:
        if facets['only'] is not None and e.id not in facets['only']:
            continue
        if kinds is not None and e.kind not in kinds:
            continue
        if facets['status'] is not None and e.status not in facets['status']:
            continue
        if facets['cls'] is not None and c.cls(e.loc) not in facets['cls']:
            continue
        if facets['flagged'] and not e.flag:
            continue
        if not _special_ok(e, facets.get('special')):
            continue
        if all(t(e, c) != neg for neg, t in terms):
            out.append(e)
    out.sort(key=lambda e: (e.time is None, e.time or 0))
    return out


# ===================================================================== views (Files & processes)
def views(c):
    """{name: (columns, rows[list], events or None)} for the Files & processes tab."""
    def ev_view(kinds, cols):
        es = sorted((e for e in c.events if e.kind in kinds), key=lambda e: (e.time is None, e.time or 0))
        rows = [[fn(e) for _, fn in cols] for e in es]
        return [n for n, _ in cols], rows, es
    T = lambda e: c.time_str(e.time)
    P = lambda e: c.path_of(e)
    N = lambda e: leaf(c.path_of(e))
    S = lambda e: e.status
    F = lambda name: (lambda e: e.field(name) or '')
    v = {}
    v['Process runs'] = ev_view({'ProcessFirstStart'}, [('First start', T), ('Image', N), ('Location', lambda e: c.cls(e.loc)), ('Path', P), ('NextUSN', F('NextUSN')), ('Source', S)])
    v['No-cert executions'] = ev_view({'NoCertExec'}, [('Inserted', T), ('File', N), ('Location', lambda e: c.cls(e.loc)), ('Path', P), ('Source', S)])
    v['Renamed binaries (OFN)'] = ev_view({'OfnSet', 'OfnSetInferred'}, [('Inserted', T), ('File', N), ('OriginalFileName', F('OriginalFileName')), ('Rename kind', F('Rename kind')),
                                                                         ('Rule', lambda e: KIND_LABEL[e.kind]), ('Location', lambda e: c.cls(e.loc)), ('Path', P), ('Source', S)])
    v['Module loads'] = ev_view({'ModuleFirstLoad'}, [('Recorded', T), ('Module', N), ('Path', P), ('Source', S)])
    v['File content & hashes'] = ev_view({'FileHashed'}, [('Hashed', T), ('FileRef', F('FileRef')), ('Volume', F('Volume serial')), ('SHA256', F('SHA256 (column SHA256)')),
                                                          ('SHA1', F('SHA1 (column MD5)')), ('MD5', F('MD5 (column SHA1)')), ('Source', S)])
    v['Defender file contexts'] = ev_view({'FileContext', 'OfnProcessed'}, [('Inserted', T), ('Context', F('Context')), ('Engine tag', F('Engine tag')), ('Path', P), ('Source', S)])
    v['LowFi hits'] = ev_view({'LowFiHit'}, [('Time', T), ('Path', P), ('Signature SHA (not a file hash)', F('Signature SHA')), ('SigSeq', F('SigSeq')), ('Source', S)])
    v['Queues'] = ev_view({'QueueEntry'}, [('Inserted', T), ('Queue', F('Queue')), ('Key', F('Key')), ('Value', F('Value')), ('Expires', F('ExpireTime')), ('Source', S)])
    v['RDP'] = ev_view({'RdpLogon'}, [('Logon', T), ('Source IP', F('Source IP')), ('User SID', F('User SID')), ('Workstation', F('Workstation')), ('Session', F('Session')), ('Source', S)])
    v['Registry cache'] = ev_view({'RegistryChange'}, [('Time', T), ('Key', F('RegPath')), ('Operation', F('RegOperation')), ('New type', F('NewRegType')), ('New data', F('NewRegData')),
                                                       ('Old type', F('OldRegType')), ('Old data', F('OldRegData')), ('Source', S)])
    v['Behaviour monitor'] = ev_view({'BmRecord'}, [('Time', T), ('Table', lambda e: e.table), ('Name', N), ('Path', P), ('Source', S)])
    v['Store cache (AMSI)'] = ev_view({'StoreExpiry'}, [('Expires', T), ('Store file name', F('PersistId (Store file name)')), ('Source', S)])
    v['Host context'] = (['Fact', 'Value', 'Table', 'Source'], [[h[0], h[1], h[2], h[4]] for h in c.host], None)
    v['Locations'] = (['Path', 'Class', 'Events', 'Spellings'], [[l.spellings[0], l.cls, str(len(l.events)), str(len(l.spellings))] for l in c.locations], None)
    return v


def raw_view(c, t):
    tp = c.tables[t]
    cols = list(tp['columns'])
    rows = []
    for k, v, st, old in tp['rows']:
        r = [decode_cell(n, v[i], c.tz)[0] if i < len(v) else '' for i, n in enumerate(cols)]
        rows.append(r + [st])
    src = 'Source'  # provenance column; bracketed until it no longer clashes with a table column of that name
    while any(x.lower() == src.lower() for x in cols):
        src = f'[{src}]'
    return cols + [src], rows


def evidence_text(c):
    i = c.img
    w = i['wal']
    L = [f'mpdbx (Python edition) {VERSION}', '', 'Inputs']
    for p, n, sha, mt in c.inputs:
        L.append(f'  {p}\n    {n} bytes   SHA256 {sha}   modified {mt}')
    if not w['present']:
        stop = 'no WAL file'
    elif not w['header_valid']:
        stop = 'WAL header invalid — WAL not applied'
    else:
        stop = w['stop'] or 'none — checksum chain fully validated'
    L += ['', 'Database and WAL',
          f"  Page size / pages              {i['page_size']} / {i['pages']}",
          f"  Encrypted                      {i['encrypted']}  (built-in mpengine key)",
          f"  Header bytes 18-19             {list(i['header_18_19'])}  (2,2 = WAL mode; loaded as a rollback-journal copy)",
          f"  WAL present / header valid     {w['present']} / {w['header_valid']}",
          f"  WAL frames total/valid/applied {w['frames_total']} / {w['frames_valid']} / {w['frames_applied']}",
          f"  WAL commits applied            {w['commits']}",
          f"  Frames after the last commit   {w['ignored_tail']} (ignored)",
          f"  WAL stop                       {stop}",
          f"  WAL salts                      {w['salts'][0]:#010x} {w['salts'][1]:#010x}"]
    L += ['', f"  {'Table':<32}{'DB-only':>9}{'Merged':>9}{'WAL-only':>10}{'WAL-mod':>9}{'Removed':>9}"]
    for t in sorted(c.tables):
        tp = c.tables[t]
        cnt = {s: 0 for s in WAL_STATUSES}
        for r in tp['rows']:
            if r[2] in cnt:
                cnt[r[2]] += 1
        L.append(f"  {t:<32}{str(tp['db_only']):>9}{str(tp['merged']):>9}{cnt['WAL-only']:>10}{cnt['WAL-modified']:>9}{cnt['Removed by WAL']:>9}")
    if c.warnings:
        L += ['', 'Warnings'] + [f'  {x}' for x in c.warnings]
    L += ['', f'Volume map (inferred): ' + (', '.join(f'HarddiskVolume{n} = {d}:' for n, d in sorted(c.volmap.items())) or 'none')]
    return '\n'.join(L)


def has_stream(path):
    """':' outside a leading drive designator names an NTFS alternate data stream (created inside another file)."""
    s = str(path)
    for pre in ('\\\\?\\', '\\\\.\\'):
        if s.startswith(pre):
            s = s[len(pre):]
    if len(s) >= 2 and s[0].isascii() and s[0].isalpha() and s[1] == ':':
        s = s[2:]
    return ':' in s


def check_output(path, inputs):
    """Refuse a destination that is (or would overwrite) an input file: same canonical path or same file identity."""
    if has_stream(path):
        raise ValueError(f'{path} names an NTFS alternate data stream; choose a plain file name')
    dst = os.path.normcase(os.path.realpath(path))
    for p in inputs:
        if os.path.normcase(os.path.realpath(p)) == dst:
            raise ValueError(f'refusing to overwrite an input file: {path}')
        try:
            if os.path.exists(path) and os.path.samefile(path, p):
                raise ValueError(f'refusing to overwrite an input file (same file under another name): {path}')
        except OSError:
            pass


def write_csv(path, cols, rows, inputs=()):
    check_output(path, inputs)
    with open(path, 'w', newline='', encoding='utf-8-sig') as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        w.writerows(rows)


def timeline_rows(c, events):
    return [[c.time_str(e.time) if e.time is not None else '', KIND_LABEL[e.kind], e.summary, c.path_of(e), e.status, '▲' if e.flag else '',
             '' if e.time is None else str(e.time), e.table, c.key_label(e.key), e.status] for e in events]


TIMELINE_COLS = ['Time', 'Type', 'Summary', 'Path', 'Source', 'Flag', 'raw_time', 'prov_source', 'prov_key', 'prov_status']


def safe_name(s):
    """One harmless file-name component (no separators, no leading dots, no reserved device names)."""
    n = re.sub(r'[^\w&() .-]+', '_', s).strip(' .') or '_'
    if n.split('.')[0].upper() in ('CON', 'PRN', 'AUX', 'NUL') or re.fullmatch(r'(COM|LPT)[0-9]', n.split('.')[0].upper()):
        n = '_' + n
    return n[:150]


def export_all(c, out):
    os.makedirs(out, exist_ok=True)
    root = os.path.realpath(out)
    ins = [x[0] for x in c.inputs]

    used = set()

    def dest(stem, ext):
        # sanitised names can collide ('a:b', 'a?b', 'A:B'): suffix _2, _3 ... case-insensitively (as the exe)
        name, n = safe_name(stem + ext), 2
        while name.lower() in used:
            name, n = safe_name(f'{stem}_{n}{ext}'), n + 1
        used.add(name.lower())
        p = os.path.join(out, name)
        if os.path.dirname(os.path.realpath(p)) != root:
            raise ValueError(f'export file would leave the output folder: {stem}{ext}')
        check_output(p, ins)
        return p
    evs = sorted(c.events, key=lambda e: (e.time is None, e.time or 0))
    jobs = [(dest('Timeline', '.csv'), TIMELINE_COLS, timeline_rows(c, evs))]
    for name, (cols, rows, _) in views(c).items():
        jobs.append((dest(name, '.csv'), cols, rows))
    for t in c.tables:
        cols, rows = raw_view(c, t)
        jobs.append((dest(f'raw_{t}', '.csv'), cols, rows))
    ev_path = dest('evidence', '.txt')
    # every target passed the guard: only now is anything written
    for path, cols, rows in jobs:
        write_csv(path, cols, rows, ins)
    with open(ev_path, 'w', encoding='utf-8') as fh:
        fh.write(evidence_text(c))
    return len(jobs) + 1


# ===================================================================== GUI (tkinter)
THEMES = {
    'dark': dict(bg='#0f1520', panel='#151c28', raised='#1b2433', input='#0b1018', border='#2a3445', text='#e6edf3', muted='#8b98a9',
                 accent='#3b82f6', accent_weak='#1e3a5f', flag='#f87171', walonly='#3a2f12', walmod='#2b2440', removed='#3a1d2a', sel='#1e3a5f', mono='#cbd5e1'),
    'light': dict(bg='#f6f8fa', panel='#ffffff', raised='#ffffff', input='#ffffff', border='#d0d7de', text='#1f2328', muted='#57606a',
                  accent='#0969da', accent_weak='#ddf4ff', flag='#cf222e', walonly='#fff3c4', walmod='#efe6ff', removed='#ffe3e8', sel='#ddf4ff', mono='#24292f'),
}


def run_gui(preload=None):
    import threading
    import tkinter as tk
    import tkinter.font as tkfont
    from tkinter import ttk, filedialog, messagebox

    root = tk.Tk()
    root.title('mpdbx — MpEngineDB Explorer (Python)')
    root.geometry('1400x880')
    root.minsize(760, 520)
    st = dict(case=None, theme='dark', tz=0, tab='Findings', facets=_f(), title='All activity', show_routine=False,
              selected=None, events=[], view=None, raw=None, loading=False)
    fam = 'Segoe UI' if sys.platform == 'win32' else ('Helvetica Neue' if sys.platform == 'darwin' else 'DejaVu Sans')
    mono = 'Consolas' if sys.platform == 'win32' else ('Menlo' if sys.platform == 'darwin' else 'DejaVu Sans Mono')
    F = dict(base=tkfont.Font(family=fam, size=10), small=tkfont.Font(family=fam, size=9), bold=tkfont.Font(family=fam, size=10, weight='bold'),
             h1=tkfont.Font(family=fam, size=15, weight='bold'), h2=tkfont.Font(family=fam, size=11, weight='bold'),
             big=tkfont.Font(family=fam, size=17, weight='bold'), mono=tkfont.Font(family=mono, size=9))
    style = ttk.Style(root)
    style.theme_use('clam')

    def C(k):
        return THEMES[st['theme']][k]

    def apply_theme():
        style.configure('.', background=C('bg'), foreground=C('text'), fieldbackground=C('input'), bordercolor=C('border'),
                        font=F['base'], lightcolor=C('border'), darkcolor=C('border'))
        style.configure('TFrame', background=C('bg'))
        style.configure('Panel.TFrame', background=C('panel'))
        style.configure('TLabel', background=C('bg'), foreground=C('text'))
        style.configure('Muted.TLabel', foreground=C('muted'))
        style.configure('Panel.TLabel', background=C('panel'))
        style.configure('TButton', background=C('raised'), foreground=C('text'), borderwidth=1, focusthickness=1, padding=(10, 4))
        style.map('TButton', background=[('active', C('accent_weak'))])
        style.configure('Tab.TButton', background=C('bg'), borderwidth=0, padding=(12, 5), font=F['bold'])
        style.configure('TabOn.TButton', background=C('accent_weak'), foreground=C('text'), borderwidth=0, padding=(12, 5), font=F['bold'])
        style.map('Tab.TButton', background=[('active', C('raised'))])
        style.configure('Quick.TButton', background=C('panel'), borderwidth=0, anchor='w', padding=(10, 5))
        style.configure('QuickOn.TButton', background=C('accent_weak'), borderwidth=0, anchor='w', padding=(10, 5))
        style.map('Quick.TButton', background=[('active', C('raised'))])
        style.configure('TCheckbutton', background=C('panel'), foreground=C('text'))
        style.map('TCheckbutton', background=[('active', C('panel'))])
        style.configure('TEntry', fieldbackground=C('input'), foreground=C('text'), insertcolor=C('text'), padding=4)
        style.configure('Treeview', background=C('panel'), fieldbackground=C('panel'), foreground=C('text'), rowheight=22, borderwidth=0, font=F['base'])
        style.configure('Treeview.Heading', background=C('raised'), foreground=C('text'), relief='flat', font=F['bold'], padding=4)
        style.map('Treeview', background=[('selected', C('sel'))], foreground=[('selected', C('text'))])
        style.map('Treeview.Heading', background=[('active', C('accent_weak'))])
        style.configure('Vertical.TScrollbar', background=C('raised'), troughcolor=C('panel'), arrowcolor=C('muted'))
        style.configure('Horizontal.TScrollbar', background=C('raised'), troughcolor=C('panel'), arrowcolor=C('muted'))
        root.configure(bg=C('bg'))
        for tv in trees:
            tv.tag_configure('walonly', background=C('walonly'))
            tv.tag_configure('walmod', background=C('walmod'))
            tv.tag_configure('removed', background=C('removed'))
            tv.tag_configure('flag', foreground=C('flag'))
        for w in texts:
            w.configure(bg=C('panel'), fg=C('text'), selectbackground=C('sel'))
            if isinstance(w, tk.Text):
                w.configure(insertbackground=C('text'))
        render()

    trees, texts = [], []

    # ---- top bar
    top = ttk.Frame(root, padding=(10, 8, 10, 4))
    top.pack(fill='x')
    open_btn = ttk.Menubutton(top, text='Open')
    open_menu = tk.Menu(open_btn, tearoff=0)
    open_btn['menu'] = open_menu
    open_btn.pack(side='left')
    case_lbl = ttk.Label(top, text='', font=F['h2'])
    case_lbl.pack(side='left', padx=(12, 12))
    search_var = tk.StringVar()
    search = ttk.Entry(top, textvariable=search_var, width=48)
    search.pack(side='left')
    hint = 'Search names, paths, hashes…   (Ctrl+F)'

    def hint_in(_=None):
        if search_var.get() == hint:
            search_var.set('')
            search.configure(foreground=C('text'))

    def hint_out(_=None):
        if not search_var.get():
            search_var.set(hint)
            search.configure(foreground=C('muted'))
    search.bind('<FocusIn>', hint_in)
    search.bind('<FocusOut>', hint_out)
    help_btn = ttk.Menubutton(top, text='?', width=2)
    help_menu = tk.Menu(help_btn, tearoff=0)
    help_btn['menu'] = help_menu
    help_btn.pack(side='left', padx=(4, 0))
    for q, what in SEARCH_EXAMPLES:
        help_menu.add_command(label=f'{q}    —  {what}', command=lambda q=q: (search.focus_set(), search_var.set(q)))
    settings_btn = ttk.Menubutton(top, text='Settings')
    settings_menu = tk.Menu(settings_btn, tearoff=0)
    settings_btn['menu'] = settings_menu
    settings_btn.pack(side='right')
    export_btn = ttk.Menubutton(top, text='Export')
    export_menu = tk.Menu(export_btn, tearoff=0)
    export_btn['menu'] = export_menu
    export_btn.pack(side='right', padx=6)
    status_lbl = ttk.Label(top, text='', style='Muted.TLabel')
    status_lbl.pack(side='right', padx=10)

    tabs = ttk.Frame(root, padding=(10, 0, 10, 6))
    tabs.pack(fill='x')
    tab_btns = {}
    for name in ('Findings', 'Timeline', 'Files & processes', 'Evidence'):
        b = ttk.Button(tabs, text=name, style='Tab.TButton', command=lambda n=name: set_tab(n))
        b.pack(side='left', padx=(0, 4))
        tab_btns[name] = b
    sep = tk.Frame(root, height=1)
    sep.pack(fill='x')
    body = ttk.Frame(root)
    body.pack(fill='both', expand=True)

    # ---- pages
    pages = {n: ttk.Frame(body) for n in ('Empty', 'Findings', 'Timeline', 'Files & processes', 'Evidence')}

    # empty
    ep = pages['Empty']
    ttk.Label(ep, text='Open a copy of Defender’s Scans folder', font=F['h1']).pack(pady=(140, 8))
    ttk.Label(ep, text='Open (top left) → Scans folder… or mpenginedb.db file…', style='Muted.TLabel').pack()
    ttk.Label(ep, text="Copy the Scans folder (mpenginedb.db, mpenginedb.db-wal and History) out of ONE VSS shadow copy, so the DB and its WAL belong together; separate esentutl /vss calls take separate snapshots. Steps: README, 'Acquire'.",
              style='Muted.TLabel', wraplength=900).pack(pady=12)
    empty_err = ttk.Label(ep, text='', foreground='#f87171', wraplength=900)
    empty_err.pack(pady=8)

    # findings (scrollable canvas of cards)
    fp = pages['Findings']
    fcanvas = tk.Canvas(fp, highlightthickness=0, bd=0)
    fscroll = ttk.Scrollbar(fp, orient='vertical', command=fcanvas.yview)
    fcanvas.configure(yscrollcommand=fscroll.set)
    fscroll.pack(side='right', fill='y')
    fcanvas.pack(side='left', fill='both', expand=True)
    fcanvas.bind('<Configure>', lambda e: render_findings())

    def wheel(ev, cv=fcanvas):
        cv.yview_scroll(int(-ev.delta / 120) if ev.delta else (1 if ev.num == 5 else -1), 'units')
    fcanvas.bind('<Enter>', lambda e: (fcanvas.bind_all('<MouseWheel>', wheel), fcanvas.bind_all('<Button-4>', wheel), fcanvas.bind_all('<Button-5>', wheel)))
    fcanvas.bind('<Leave>', lambda e: (fcanvas.unbind_all('<MouseWheel>'), fcanvas.unbind_all('<Button-4>'), fcanvas.unbind_all('<Button-5>')))

    # timeline
    tp = pages['Timeline']
    tl_left = ttk.Frame(tp, style='Panel.TFrame', padding=(8, 10), width=230)
    tl_left.pack(side='left', fill='y')
    tl_left.pack_propagate(False)
    ttk.Label(tl_left, text='Quick views', style='Panel.TLabel', font=F['h2']).pack(anchor='w', pady=(0, 4))
    quick_btns = {}
    for name, tip, fac in QUICK_VIEWS:
        b = ttk.Button(tl_left, text=name, style='Quick.TButton', command=lambda n=name, f=fac: open_list(n, dict(f)))
        b.pack(fill='x')
        quick_btns[name] = b
    routine_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(tl_left, text='Show routine events', variable=routine_var, command=lambda: (st.update(show_routine=routine_var.get()), refresh_timeline())).pack(anchor='w', pady=(10, 2))
    ttk.Label(tl_left, text='module loads, file hashes, cache expiries…', style='Panel.TLabel', foreground='#8b98a9', font=F['small']).pack(anchor='w')
    more_var = tk.BooleanVar(value=False)
    more_btn = ttk.Button(tl_left, text='▸ More filters', style='Quick.TButton', command=lambda: toggle_more())
    more_btn.pack(fill='x', pady=(10, 0))
    more = ttk.Frame(tl_left, style='Panel.TFrame')
    kind_vars = {k: tk.BooleanVar(value=True) for k in KIND_LABEL}
    stat_vars = {s: tk.BooleanVar(value=True) for s in ('DB',) + WAL_STATUSES + ('unknown',)}
    cls_vars = {s: tk.BooleanVar(value=True) for s in ('outside system dirs', 'system dir', 'unknown')}
    flag_var = tk.BooleanVar(value=False)

    def custom_filter():
        ks = {k for k, v in kind_vars.items() if v.get()}
        ss = {k for k, v in stat_vars.items() if v.get()}
        cs = {k for k, v in cls_vars.items() if v.get()}
        st['facets'] = _f(kinds=None if len(ks) == len(kind_vars) else ks, status=None if len(ss) == len(stat_vars) else ss,
                          cls=None if len(cs) == len(cls_vars) else cs, flagged=flag_var.get())
        st['title'] = 'Custom filter'
        refresh_timeline()
    ttk.Checkbutton(more, text='Flagged only (▲)', variable=flag_var, command=custom_filter).pack(anchor='w')
    ttk.Label(more, text='Event type', style='Panel.TLabel', font=F['bold']).pack(anchor='w', pady=(6, 0))
    for k, lab in KIND_LABEL.items():
        ttk.Checkbutton(more, text=lab, variable=kind_vars[k], command=custom_filter).pack(anchor='w')
    ttk.Label(more, text='Source', style='Panel.TLabel', font=F['bold']).pack(anchor='w', pady=(6, 0))
    for s in stat_vars:
        ttk.Checkbutton(more, text=s, variable=stat_vars[s], command=custom_filter).pack(anchor='w')
    ttk.Label(more, text='Location', style='Panel.TLabel', font=F['bold']).pack(anchor='w', pady=(6, 0))
    for s in cls_vars:
        ttk.Checkbutton(more, text=s, variable=cls_vars[s], command=custom_filter).pack(anchor='w')

    def toggle_more():
        more_var.set(not more_var.get())
        more_btn.configure(text=('▾' if more_var.get() else '▸') + ' More filters')
        if more_var.get():
            more.pack(fill='x', after=more_btn)
        else:
            more.pack_forget()

    tl_main = ttk.Frame(tp, padding=(10, 8, 0, 0))
    tl_main.pack(side='left', fill='both', expand=True)
    hist = tk.Canvas(tl_main, height=64, highlightthickness=0, bd=0)
    hist.pack(fill='x')
    hist.bind('<Configure>', lambda e: draw_hist())
    tl_head = ttk.Frame(tl_main)
    tl_head.pack(fill='x', pady=(4, 4))
    tl_title = ttk.Label(tl_head, text='', font=F['h2'])
    tl_title.pack(side='left')
    tl_count = ttk.Label(tl_head, text='', style='Muted.TLabel')
    tl_count.pack(side='left', padx=8)
    tl_all = ttk.Button(tl_head, text='Show all activity', command=lambda: open_list('All activity', _f()))
    tl_err = ttk.Label(tl_head, text='', foreground='#f87171')
    tl_err.pack(side='left', padx=8)
    tl_paned = ttk.PanedWindow(tl_main, orient='horizontal')
    tl_paned.pack(fill='both', expand=True)

    def make_tree(parent, cols):
        fr = ttk.Frame(parent)
        tv = ttk.Treeview(fr, columns=cols, show='headings', selectmode='browse')
        ys = ttk.Scrollbar(fr, orient='vertical', command=tv.yview)
        xs = ttk.Scrollbar(fr, orient='horizontal', command=tv.xview)
        tv.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        tv.grid(row=0, column=0, sticky='nsew')
        ys.grid(row=0, column=1, sticky='ns')
        xs.grid(row=1, column=0, sticky='ew')
        fr.rowconfigure(0, weight=1)
        fr.columnconfigure(0, weight=1)
        trees.append(tv)
        return fr, tv

    TL_COLS = ('Time', 'What', 'Name', 'Details', 'Path', 'Source')
    tl_frame, tl_tree = make_tree(tl_paned, TL_COLS)
    for col, w in zip(TL_COLS, (200, 160, 190, 280, 360, 100)):
        tl_tree.heading(col, text=col, command=lambda c=col: sort_tree(tl_tree, c))
        tl_tree.column(col, width=w, minwidth=60, stretch=col in ('Details', 'Path'))
    tl_paned.add(tl_frame, weight=3)
    detail = tk.Text(tl_paned, wrap='word', bd=0, padx=12, pady=10, font=F['base'], width=44)
    texts.append(detail)
    detail_shown = [False]

    # files & processes
    vp = pages['Files & processes']
    v_left = ttk.Frame(vp, style='Panel.TFrame', padding=(8, 10), width=250)
    v_left.pack(side='left', fill='y')
    v_left.pack_propagate(False)
    ttk.Label(v_left, text='Views', style='Panel.TLabel', font=F['h2']).pack(anchor='w')
    v_list = tk.Listbox(v_left, bd=0, highlightthickness=0, activestyle='none', exportselection=False, font=F['base'])
    v_list.pack(fill='both', expand=True, pady=(4, 0))
    texts.append(v_list)
    v_main = ttk.Frame(vp, padding=(10, 8, 6, 6))
    v_main.pack(side='left', fill='both', expand=True)
    v_title = ttk.Label(v_main, text='', font=F['h2'])
    v_title.pack(anchor='w', pady=(0, 6))
    v_holder = ttk.Frame(v_main)
    v_holder.pack(fill='both', expand=True)
    v_tree_box = [None, None]

    # evidence
    evp = pages['Evidence']
    ev_text = tk.Text(evp, wrap='none', bd=0, padx=14, pady=12, font=F['mono'])
    ev_text.pack(fill='both', expand=True)
    texts.append(ev_text)

    # ---- behaviour
    def set_tab(n):
        if st['case'] is None and n != 'Findings':
            return
        st['tab'] = n
        render()
        if n == 'Timeline':
            refresh_timeline()
        elif n == 'Files & processes':
            sel = v_list.curselection()
            if sel:
                show_view(st['view_names'][sel[0]])

    def render():
        sep.configure(bg=C('border'))
        fcanvas.configure(bg=C('bg'))
        hist.configure(bg=C('bg'))
        v_list.configure(bg=C('panel'), fg=C('text'), selectbackground=C('sel'), selectforeground=C('text'))
        for n, b in tab_btns.items():
            b.configure(style='TabOn.TButton' if n == st['tab'] else 'Tab.TButton')
        for p in pages.values():
            p.pack_forget()
        if st['case'] is None:
            pages['Empty'].pack(fill='both', expand=True)
            return
        pages[st['tab']].pack(fill='both', expand=True)
        if st['tab'] == 'Findings':
            render_findings()
        elif st['tab'] == 'Timeline':
            for n, b in quick_btns.items():
                b.configure(style='QuickOn.TButton' if n == st['title'] else 'Quick.TButton')

    def render_findings():
        cv = fcanvas
        cv.delete('all')
        c = st['case']
        if c is None:
            return
        W = max(cv.winfo_width(), 400)
        width = min(W - 32, 1320)
        x0 = (W - width) / 2
        y = 18
        cv.create_text(x0, y, text='What stands out in this database', anchor='nw', fill=C('text'), font=F['h1'])
        y += 30
        cv.create_text(x0, y, text='Click a card to see exactly those events.', anchor='nw', fill=C('muted'), font=F['base'])
        y += 30
        cards = findings(c)
        hits = [k for k in cards if k[0] == 'flag' and k[3]]
        clear = [k for k in cards if k[0] == 'flag' and not k[3]]
        info = [k for k in cards if k[0] == 'info']
        gap, H, minw = 10, 108, 300
        ncol = max(1, min(3, int((width + gap) // (minw + gap))))
        cw = (width - gap * (ncol - 1)) / ncol

        def section(title, color, group, y):
            cv.create_text(x0, y, text=title, anchor='nw', fill=color, font=F['h2'])
            y += 26
            for i, k in enumerate(group):
                r, col = divmod(i, ncol)
                cx, cy = x0 + col * (cw + gap), y + r * (H + gap)
                card(k, cx, cy, cw, H)
            rows = (len(group) + ncol - 1) // ncol
            return y + rows * (H + gap) + 6

        def card(k, x, y, w, h):
            level, title, explain, ids, ex = k
            acc = C('flag') if level == 'flag' else C('accent')
            tag = f'card{id(k)}'
            cv.create_rectangle(x, y, x + w, y + h, fill=C('raised'), outline=acc if level == 'flag' else C('border'), width=1, tags=(tag, tag + 'bg'))
            cv.create_rectangle(x, y, x + 4, y + h, fill=acc, outline=acc, tags=tag)
            cnt = cv.create_text(x + 16, y + 12, text=str(len(ids)), anchor='nw', fill=acc, font=F['big'], tags=tag)
            bx = cv.bbox(cnt)
            cv.create_text(bx[2] + 10, y + 17, text=_fit(title, F['h2'], x + w - 12 - bx[2] - 10), anchor='nw', fill=C('text'), font=F['h2'], tags=tag)
            cv.create_text(x + 16, y + 46, text=explain, anchor='nw', fill=C('muted'), font=F['small'], width=w - 30, tags=tag)
            if ex:
                cv.create_text(x + 16, y + h - 20, text=_fit('e.g. ' + ' · '.join(ex), F['mono'], w - 30), anchor='nw', fill=C('mono'), font=F['mono'], tags=tag)
            cv.tag_bind(tag, '<Button-1>', lambda e, k=k: open_list(k[1], _f(only=set(k[3])), clear_search=True))
            cv.tag_bind(tag, '<Enter>', lambda e, t=tag: (cv.itemconfigure(t + 'bg', fill=C('input')), cv.configure(cursor='hand2')))
            cv.tag_bind(tag, '<Leave>', lambda e, t=tag: (cv.itemconfigure(t + 'bg', fill=C('raised')), cv.configure(cursor='')))

        y = section('Needs attention' if hits else 'Needs attention: nothing flagged', C('flag'), hits, y)
        if clear:
            cv.create_text(x0, y, text='✓ Checked, nothing found:  ' + '   ·   '.join(k[1] for k in clear), anchor='nw', fill=C('muted'), font=F['base'])
            y += 30
        y = section('Overview', C('text'), info, y)
        cv.configure(scrollregion=(0, 0, W, y + 20))

    def _fit(s, font, w):
        if font.measure(s) <= w:
            return s
        while s and font.measure(s + '…') > w:
            s = s[:-1]
        return s + '…'

    def reset_filter_controls():
        for v in list(kind_vars.values()) + list(stat_vars.values()) + list(cls_vars.values()):
            v.set(True)
        flag_var.set(False)

    def open_list(title, facets, clear_search=False):
        st['title'], st['facets'] = title, facets
        reset_filter_controls()
        if clear_search:
            search.focus_set()
            search_var.set('')
            root.focus_set()
            hint_out()
        st['tab'] = 'Timeline'
        render()
        refresh_timeline()

    def current_terms():
        q = search_var.get()
        if q == hint:
            q = ''
        try:
            t = parse_search(q, st['tz'])
            tl_err.configure(text='')
            return t
        except ValueError as e:
            tl_err.configure(text=f'search: {e}')
            return None

    def refresh_timeline(*_):
        c = st['case']
        if c is None:
            return
        terms = current_terms()
        if terms is None:
            return
        evs = apply(c, st['facets'], terms, st['show_routine'])
        st['events'] = evs
        tl_tree.delete(*tl_tree.get_children())
        for e in evs:
            p = c.path_of(e)
            nm = leaf(p)
            lab = KIND_LABEL[e.kind]
            det = e.summary[len(lab) + 2:] if e.summary.startswith(lab + ': ') else e.summary
            if nm and det.lower() == nm.lower():
                det = ''
            tags = []
            if e.status == 'WAL-only':
                tags.append('walonly')
            elif e.status == 'WAL-modified':
                tags.append('walmod')
            elif e.status == 'Removed by WAL':
                tags.append('removed')
            if e.flag:
                tags.append('flag')
            tl_tree.insert('', 'end', iid=str(e.id), values=(('▲ ' if e.flag else '') + c.time_str(e.time), lab, nm, det, p, e.status), tags=tags)
        tl_title.configure(text=st['title'])
        tl_count.configure(text=f'{len(evs)} events')
        if st['title'] != 'All activity':
            tl_all.pack(side='left', padx=6, before=tl_err)
        else:
            tl_all.pack_forget()
        for n, b in quick_btns.items():
            b.configure(style='QuickOn.TButton' if n == st['title'] else 'Quick.TButton')
        draw_hist()
        hide_detail()

    def draw_hist():
        hist.delete('all')
        evs = [e.time for e in st['events'] if e.time is not None]
        W = hist.winfo_width()
        if not evs or W < 50:
            return
        lo, hi = min(evs), max(evs)
        nb = max(10, min(240, W // 6))
        span = max(hi - lo, 1)
        counts = [0] * nb
        for t in evs:
            counts[min(nb - 1, (t - lo) * nb // (span + 1))] += 1
        mx = max(counts)
        bw = W / nb
        for i, n in enumerate(counts):
            if n:
                h = max(2, 46 * n / mx)
                hist.create_rectangle(i * bw + 1, 48 - h, (i + 1) * bw - 1, 48, fill=C('accent'), outline='')
        hist.create_text(2, 52, text=fmt_ft(lo, st['tz'])[:16], anchor='nw', fill=C('muted'), font=F['small'])
        hist.create_text(W - 2, 52, text=fmt_ft(hi, st['tz'])[:16], anchor='ne', fill=C('muted'), font=F['small'])

    def hide_detail():
        if detail_shown[0]:
            tl_paned.forget(detail)
            detail_shown[0] = False

    def show_detail(e):
        c = st['case']
        if not detail_shown[0]:
            tl_paned.add(detail, weight=1)
            detail_shown[0] = True
        detail.configure(state='normal')
        detail.delete('1.0', 'end')
        detail.tag_configure('h', font=F['h2'], foreground=C('text'), spacing1=6, spacing3=4)
        detail.tag_configure('k', foreground=C('muted'))
        detail.tag_configure('m', font=F['mono'], foreground=C('mono'))
        detail.tag_configure('flag', foreground=C('flag'), font=F['bold'])
        detail.insert('end', KIND_LABEL[e.kind] + '\n', 'h')
        if e.flag:
            detail.insert('end', '▲ red flag\n', 'flag')
        detail.insert('end', e.summary + '\n\n')
        detail.insert('end', 'Time  ', 'k')
        detail.insert('end', c.time_str(e.time) + '\n', 'm')
        if e.loc is not None:
            detail.insert('end', 'Location  ', 'k')
            detail.insert('end', f'{c.cls(e.loc)}\n')
        detail.insert('end', 'Fields\n', 'h')
        for n, d, r in e.fields:
            detail.insert('end', f'{n}\n', 'k')
            detail.insert('end', f'  {d}\n', 'm')
            if r and r != d:
                detail.insert('end', f'  raw: {r}\n', 'k')
        detail.insert('end', 'Where it came from\n', 'h')
        detail.insert('end', f'{e.table}  {c.key_label(e.key)}  —  {e.status}\n')
        if e.old is not None and e.status == 'WAL-modified':
            cols = c.tables[e.table]['columns']
            detail.insert('end', 'Values before the WAL:\n', 'k')
            for n2, v in zip(cols, e.old):
                detail.insert('end', f'  {n2} = {raw_of(v)}\n', 'm')
        if e.loc is not None:
            others = [c.events[i] for i in c.locations[e.loc].events if i != e.id]
            if others:
                detail.insert('end', f'Same file ({len(others)} other records)\n', 'h')
                for o in sorted(others, key=lambda o: (o.time is None, o.time or 0))[:40]:
                    detail.insert('end', f'{c.time_str(o.time)}  ', 'm')
                    detail.insert('end', f'{KIND_LABEL[o.kind]}\n')
        detail.configure(state='disabled')

    def on_select(_=None):
        sel = tl_tree.selection()
        if sel:
            show_detail(st['case'].events[int(sel[0])])

    tl_tree.bind('<<TreeviewSelect>>', on_select)

    def sort_tree(tv, col):
        desc = getattr(tv, '_sort', None) == (col, False)
        if tv is tl_tree and col == 'Time':
            ids = list(tv.get_children(''))
            timed = [i for i in ids if st['case'].events[int(i)].time is not None]
            untimed = [i for i in ids if st['case'].events[int(i)].time is None]
            timed.sort(key=lambda i: st['case'].events[int(i)].time, reverse=desc)
            data = [(None, i) for i in timed + untimed]
        else:
            data = [(tv.set(i, col), i) for i in tv.get_children('')]
            data.sort(key=lambda x: x[0].lstrip('▲ ').lower(), reverse=desc)
        for n, (_, i) in enumerate(data):
            tv.move(i, '', n)
        tv._sort = (col, desc)
        for c2 in tv['columns']:
            tv.heading(c2, text=c2 + ((' ▼' if desc else ' ▲') if c2 == col else ''))

    def fill_views():
        c = st['case']
        st['view_defs'] = views(c)
        v_list.delete(0, 'end')
        st['view_names'] = []
        for n, (cols, rows, _) in st['view_defs'].items():
            v_list.insert('end', f'  {n}  ({len(rows)})')
            st['view_names'].append(('view', n))
        v_list.insert('end', '')
        v_list.insert('end', '  Raw tables')
        v_list.itemconfigure('end', foreground=C('muted'))
        st['view_names'] += [(None, None), (None, None)]
        for t in sorted(c.tables):
            v_list.insert('end', f'    {t}  ({len(c.tables[t]["rows"])})')
            st['view_names'].append(('raw', t))
        v_list.selection_set(1)
        show_view(('view', 'No-cert executions'))

    def show_view(which):
        c = st['case']
        kind, name = which
        if kind is None:
            return
        if kind == 'view':
            cols, rows, evs = st['view_defs'][name]
            tags_of = [_row_tag(e) for e in evs] if evs else [()] * len(rows)
        else:
            cols, rows = raw_view(c, name)
            tags_of = [_status_tag(r[-1]) for r in rows]
        q = search_var.get().strip()
        if q == hint:
            q = ''
        f = row_filter(c, q, st['tz'])
        keep = [i for i, r in enumerate(rows) if f(r, row_events(c, name, evs, i) if kind == 'view' else None)]
        v_title.configure(text=f'{name}    {len(keep)} of {len(rows)} rows')
        if v_tree_box[0] is not None:
            trees.remove(v_tree_box[1])
            v_tree_box[0].destroy()
        fr, tv = make_tree(v_holder, cols)
        fr.pack(fill='both', expand=True)
        v_tree_box[:] = [fr, tv]
        apply_theme_tree(tv)
        for col in cols:
            sample = max([len(str(rows[i][cols.index(col)])) for i in keep[:200]] + [len(col)])
            tv.heading(col, text=col, command=lambda c2=col, t=tv: sort_tree(t, c2))
            tv.column(col, width=min(420, max(80, sample * 7 + 16)), minwidth=50, stretch=False)
        for i in keep:
            tv.insert('', 'end', values=[str(x) for x in rows[i]], tags=tags_of[i])

    def _status_tag(s):
        return {'WAL-only': ('walonly',), 'WAL-modified': ('walmod',), 'Removed by WAL': ('removed',)}.get(s, ())

    def _row_tag(e):
        return _status_tag(e.status) + (('flag',) if e.flag else ())

    def apply_theme_tree(tv):
        tv.tag_configure('walonly', background=C('walonly'))
        tv.tag_configure('walmod', background=C('walmod'))
        tv.tag_configure('removed', background=C('removed'))
        tv.tag_configure('flag', foreground=C('flag'))

    v_list.bind('<<ListboxSelect>>', lambda e: v_list.curselection() and show_view(st['view_names'][v_list.curselection()[0]]))

    search_after = [None]

    def on_search(*_):
        if search_after[0]:
            root.after_cancel(search_after[0])
        search_after[0] = root.after(250, do_search)

    def do_search():
        search_after[0] = None
        if st['case'] is None:
            return
        q = search_var.get()
        if q and q != hint and st['tab'] == 'Findings':
            st['tab'] = 'Timeline'
            render()
        if st['tab'] == 'Files & processes':
            sel = v_list.curselection()
            if sel:
                show_view(st['view_names'][sel[0]])
        else:
            refresh_timeline()
    search_var.trace_add('write', on_search)

    def load(path):
        if st['loading']:
            return
        st['loading'] = True
        status_lbl.configure(text='loading…')
        res = {}

        def work():
            try:
                res['case'] = Case(path, st['tz'], progress=lambda s: root.after(0, lambda: status_lbl.configure(text=s + '…')))
            except Exception as e:  # shown to the analyst
                res['err'] = f'{type(e).__name__}: {e}'

        def done():
            st['loading'] = False
            if 'err' in res:
                status_lbl.configure(text='')
                empty_err.configure(text='Could not open: ' + res['err'])
                messagebox.showerror('mpdbx', res['err'])
                render()
                return
            c = res['case']
            st['case'] = c
            name = os.path.basename(os.path.dirname(c.inputs[0][0])) or c.inputs[0][0]
            case_lbl.configure(text=name)
            status_lbl.configure(text=f'{len(c.events)} events · {c.img["wal"]["frames_applied"]} WAL frames applied')
            ev_text.configure(state='normal')
            ev_text.delete('1.0', 'end')
            ev_text.insert('1.0', evidence_text(c))
            ev_text.configure(state='disabled')
            fill_views()
            st['tab'] = 'Findings'
            st['title'], st['facets'] = 'All activity', _f()
            reset_filter_controls()
            render()
            refresh_timeline()

        def poll(th):
            if th.is_alive():
                root.after(80, poll, th)
            else:
                done()
        th = threading.Thread(target=work, daemon=True)
        th.start()
        poll(th)

    open_menu.add_command(label='Scans folder…', command=lambda: (lambda d: d and load(d))(filedialog.askdirectory(title='Copied Defender Scans folder')))
    open_menu.add_command(label='mpenginedb.db file…', command=lambda: (lambda f: f and load(f))(filedialog.askopenfilename(title='mpenginedb.db', filetypes=[('Defender engine DB', '*.db'), ('All files', '*')])))

    def export_list():
        """The list on screen: the Files & processes grid when that tab is shown, otherwise the Timeline. A search typed in
        the last moment (still waiting for its debounce) is applied first, so the export never holds stale rows."""
        c = st['case']
        if c is None:
            return
        pending = search_after[0] is not None
        if pending:
            root.after_cancel(search_after[0])
            search_after[0] = None
        on_view = st['tab'] == 'Files & processes' and v_tree_box[1] is not None
        # re-filter only when needed: a fresh refresh would also drop the order the analyst sorted the grid into
        if on_view:
            if pending:
                do_search()
        elif pending or st['tab'] != 'Timeline':
            refresh_timeline()
        p = filedialog.asksaveasfilename(defaultextension='.csv', initialfile='mpdbx-view.csv' if on_view else 'mpdbx-timeline.csv',
                                         filetypes=[('CSV', '*.csv')])
        if not p:
            return
        try:
            ins = [x[0] for x in c.inputs]
            if on_view:
                tv = v_tree_box[1]
                shown = [list(tv.item(i, 'values')) for i in tv.get_children('')]
                write_csv(p, list(tv['columns']), shown, ins)
            else:
                shown = [c.events[int(i)] for i in tl_tree.get_children('')]
                write_csv(p, TIMELINE_COLS, timeline_rows(c, shown), ins)
            status_lbl.configure(text=f'wrote {len(shown)} rows to {p}')
        except (OSError, ValueError) as e:
            messagebox.showerror('mpdbx', str(e))

    def export_everything():
        c = st['case']
        if c is None:
            return
        d = filedialog.askdirectory(title='Folder for the CSV files')
        if not d:
            return
        try:
            n = export_all(c, d)
            status_lbl.configure(text=f'wrote {n} files to {d}')
        except (OSError, ValueError) as e:
            messagebox.showerror('mpdbx', str(e))
    export_menu.add_command(label='This list as CSV…   (Ctrl+E)', command=export_list)
    export_menu.add_command(label='Everything (all views + raw tables, CSV)…', command=export_everything)

    def set_tz():
        from tkinter import simpledialog
        s = simpledialog.askstring('Time zone', 'Display time zone (Z or ±HH:MM):', initialvalue=tz_suffix(st['tz']), parent=root)
        if s is None:
            return
        tzv = parse_tz(s)
        if tzv is None:
            messagebox.showerror('mpdbx', 'time zone must be Z or ±HH:MM (at most 14:00)')
            return
        st['tz'] = tzv
        if st['case']:
            load(st['case'].path)
    theme_var = tk.BooleanVar(value=True)
    settings_menu.add_command(label='Time zone…', command=set_tz)
    settings_menu.add_checkbutton(label='Dark theme', variable=theme_var, command=lambda: (st.update(theme='dark' if theme_var.get() else 'light'), apply_theme()))

    root.bind_all('<Control-f>', lambda e: (search.focus_set(), search.select_range(0, 'end')))
    root.bind_all('<Control-e>', lambda e: export_list())
    for i, n in enumerate(('Findings', 'Timeline', 'Files & processes', 'Evidence'), 1):
        root.bind_all(f'<Control-Key-{i}>', lambda e, n=n: set_tab(n))

    apply_theme()
    hint_out()
    if preload:
        root.after(100, lambda: load(preload))
    root.mainloop()


# ===================================================================== CLI
USAGE = '''usage:
  mpdbx.py [<Scans folder or mpenginedb.db>]      open the GUI
  mpdbx.py info   <path> [--tz Z|+HH:MM]          evidence summary and event counts
  mpdbx.py export <path> --out DIR [--tz ...]     every view and raw table as CSV
exit codes: 0 ok · 2 usage · 3 input unreadable · 5 output refused'''


def main(argv):
    if len(argv) >= 2 and argv[1] in ('-h', '--help', '/?', 'help'):
        print(USAGE)
        return 0
    if len(argv) >= 2 and argv[1] == '--version':
        print(f'mpdbx (Python edition) {VERSION}')
        return 0
    if len(argv) >= 2 and argv[1].startswith('-'):
        print(f'mpdbx: unknown option {argv[1]}\n{USAGE}', file=sys.stderr)
        return 2
    if len(argv) >= 2 and argv[1] in ('info', 'export'):
        import argparse
        ap = argparse.ArgumentParser(prog='mpdbx.py ' + argv[1])
        ap.add_argument('path')
        ap.add_argument('--tz', default='Z')
        if argv[1] == 'export':
            ap.add_argument('--out', required=True)
        a = ap.parse_args(argv[2:])
        tzv = parse_tz(a.tz)
        if tzv is None:
            print('mpdbx: --tz must be Z or ±HH:MM', file=sys.stderr)
            return 2
        try:
            c = Case(a.path, tzv)
        except (ValueError, OSError) as e:
            print(f'mpdbx: {e}', file=sys.stderr)
            return 3
        if argv[1] == 'info':
            print(evidence_text(c))
            from collections import Counter
            print('\nEvents by type:')
            for k, n in Counter(KIND_LABEL[e.kind] for e in c.events).most_common():
                print(f'  {k:<32}{n}')
        else:
            try:
                n = export_all(c, a.out)
            except (ValueError, OSError) as e:
                print(f'mpdbx: {e}', file=sys.stderr)
                return 5
            print(f'wrote {n} files to {a.out}')
        return 0
    run_gui(argv[1] if len(argv) > 1 else None)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
