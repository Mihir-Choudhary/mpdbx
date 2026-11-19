"""Produce v1 (Python MpEngineDB Explorer) oracle counts for the local reference copies (local evidence only).

usage: python tests/oracle/gen_oracle.py <scratch dir under target/>
Writes tests/oracle/<name>.json = {"db_only": {table: n}, "merged": {table: n}, "wal_only": {table: [rowids]}}.
The JSON files are git-ignored (they are derived from real evidence).
"""
import json, os, sqlite3, sys
sys.path.insert(0, r'C:\dfir_research\tools\mpdb_explorer')
from mpdb_core import decrypt

COPIES = {
    'mpdb_1640': r'C:\dfir_research\copies\live\mpdb_1640',
    'mpdb_1637': r'C:\dfir_research\copies\live\mpdb_1637',
    'mpdb_1640b': r'C:\dfir_research\copies\live\mpdb_1640b',
    'mpdb_1642': r'C:\dfir_research\copies\live\mpdb_1642',
    'mpdb_explorer_live': r'C:\dfir_research\copies\live\mpdb_explorer_live',
    'Defender_now': r'C:\dfir_research\copies\live\Defender_now',
    'vss9_Defender_Scans': r'C:\dfir_research\copies\vss9\Defender_Scans',
}


def tables(c):
    # GLOB, not LIKE: LIKE is case-insensitive and '_' is a wildcard, which silently dropped 'SQLiteGlobals'.
    return [r[0] for r in c.execute("select name from sqlite_master where type='table' and (name not glob 'sqlite_*' or name in ('sqlite_sequence','sqlite_stat1'))")]


def rowids(c, t):
    try:
        return {r[0] for r in c.execute(f'select rowid from "{t}"')}
    except sqlite3.Error:
        return None


def main(scratch):
    out_dir = os.path.dirname(os.path.abspath(__file__))
    for name, d in COPIES.items():
        r = decrypt(os.path.join(d, 'mpenginedb.db'), workdir=os.path.join(scratch, name))
        nowal = sqlite3.connect(f'file:{os.path.join(r.workdir, "main_nowal.db")}?mode=ro', uri=True)
        merged = sqlite3.connect(f'file:{r.merged_db}?mode=ro', uri=True)
        res = {'db_only': {}, 'merged': {}, 'wal_only': {}}
        for t in tables(merged):
            res['merged'][t] = merged.execute(f'select count(*) from "{t}"').fetchone()[0]
        for t in tables(nowal):
            res['db_only'][t] = nowal.execute(f'select count(*) from "{t}"').fetchone()[0]
        for t in res['merged']:
            m, n = rowids(merged, t), rowids(nowal, t) if t in res['db_only'] else set()
            if m is not None and n is not None:
                res['wal_only'][t] = sorted(m - n)
        json.dump(res, open(os.path.join(out_dir, f'{name}.json'), 'w'), indent=0, sort_keys=True)
        print(name, 'tables', len(res['merged']), 'wal-only rows', sum(len(v) for v in res['wal_only'].values()), 'wal frames', r.wal_frames, 'commits', r.wal_commits)


if __name__ == '__main__':
    main(sys.argv[1])
