"""Edge-case checks for the Python and PowerShell editions (each reproduces a fixed bug).

    python ports/tests/edge_cases.py

Builds small synthetic Scans folders (plain SQLite in WAL mode with uncommitted-to-main changes, which every edition
accepts like a decrypted copy), runs ports/verify_ports.py on them (exe = reference), then checks specific behaviour of
both editions: export guards, search semantics and robustness on malformed input. Exit code 0 = all passed.
"""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PY = os.path.join(ROOT, 'ports', 'python', 'mpdbx.py')
PS = os.path.join(ROOT, 'ports', 'powershell', 'mpdbx.ps1')
FT = 134368986477715047  # 2026-10-19
FAILS = []


def check(name, cond, detail=''):
    print(('ok   ' if cond else 'FAIL ') + name + ('' if cond else f'  {detail}'))
    if not cond:
        FAILS.append(name)


def scans(root, name, base_sql, wal_sql, corrupt=None):
    """Folder with mpenginedb.db (base_sql checkpointed) + mpenginedb.db-wal (wal_sql, not checkpointed)."""
    d = os.path.join(root, name)
    os.makedirs(d)
    work = os.path.join(root, name + '_work.db')
    con = sqlite3.connect(work, isolation_level=None)
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA wal_autocheckpoint=0')
    con.executescript(base_sql)
    con.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    if wal_sql:
        con.executescript(wal_sql)
    shutil.copyfile(work, os.path.join(d, 'mpenginedb.db'))
    if os.path.exists(work + '-wal') and os.path.getsize(work + '-wal'):
        shutil.copyfile(work + '-wal', os.path.join(d, 'mpenginedb.db-wal'))
    con.close()
    if corrupt:
        corrupt(os.path.join(d, 'mpenginedb.db'))
    return d


def py_case(path):
    import importlib.util
    spec = importlib.util.spec_from_file_location('mpdbx_py', PY)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m, m.Case(path)


def ps(script):
    """Runs PowerShell with the edition's engine loaded (types only, no GUI); returns stdout lines."""
    eng = os.path.join(ROOT, 'ports', 'powershell', 'engine.cs')
    pre = f"Add-Type -TypeDefinition ([IO.File]::ReadAllText('{eng}')) -ReferencedAssemblies System.Core, System.Web.Extensions; "
    r = subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', pre + script],
                       capture_output=True, text=True, encoding='utf-8', errors='replace')
    return (r.stdout + r.stderr).strip().splitlines()


def main():
    t = tempfile.mkdtemp(prefix='mpdbx_edge_')
    try:
        bpi = 'CREATE TABLE BackupProcessInfo(ID INTEGER PRIMARY KEY, FilePath TEXT, FirstStartTime INTEGER, InstanceTimeStamp INTEGER, NextUSN INTEGER);'
        apc = 'CREATE TABLE AttributePersistContext(ID INTEGER PRIMARY KEY, FilePath TEXT, Context TEXT, InsertTime INTEGER, ExpireTime INTEGER, Key TEXT);'
        q = 'CREATE TABLE RollingQueuesValues(ID INTEGER PRIMARY KEY, EntryTable TEXT, EntryKey TEXT, EntryValue TEXT, InsertTime INTEGER, ExpireTime INTEGER);'
        folders = {}
        folders['utf8'] = scans(t, 'utf8', bpi + f"INSERT INTO BackupProcessInfo VALUES(1, CAST(x'433a5c54c0' AS TEXT), {FT}, {FT + 10}, 1);",
                                "UPDATE BackupProcessInfo SET FilePath = CAST(x'433a5c54c1' AS TEXT) WHERE ID=1;")
        folders['pk'] = scans(t, 'pk', "CREATE TABLE KV(k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID; INSERT INTO KV VALUES('x','before');",
                              "UPDATE KV SET v='after' WHERE k='x';")
        folders['types'] = scans(t, 'types', 'CREATE TABLE T(a); INSERT INTO T VALUES(1);', 'UPDATE T SET a=1.0;')
        folders['growth'] = scans(t, 'growth', "CREATE TABLE SQLiteGlobals(Version INTEGER); INSERT INTO SQLiteGlobals VALUES(7);"
                                  "CREATE TABLE FolderGuardPaths(ID INTEGER PRIMARY KEY, UserId TEXT); INSERT INTO FolderGuardPaths VALUES(1,'S-1');",
                                  "ALTER TABLE SQLiteGlobals ADD COLUMN Current INTEGER; DELETE FROM SQLiteGlobals;"
                                  "ALTER TABLE FolderGuardPaths ADD COLUMN GUID BLOB; ALTER TABLE FolderGuardPaths ADD COLUMN Path TEXT; DELETE FROM FolderGuardPaths;")
        rdp = [('{garbage}', 'garbage'), ('{"meta":{"Ip":"203.0.113.1"}}', 'nested'), ('{"Ip":"\\q"}', 'badescape'), ('{"LT":null}', 'ltnull'),
               ('{"LT":-1}', 'ltneg'), ('{"Ip":true}', 'bool'), (f'{{"Ip":"198.51.100.7","LT":{FT},"SLId":"S-1-5-21","Wsn":"WS","TSid":2}}', 'good')]
        rows = ''.join(f"INSERT INTO RollingQueuesValues VALUES({i + 1},'RDP-Event-Success','{k}','{v.replace(chr(39), chr(39) * 2)}',{FT},{FT});" for i, (v, k) in enumerate(rdp))
        rows += (f"INSERT INTO RollingQueuesValues VALUES(20,'domainInfo','10.0.0.1','²',{FT},{FT});"
                 f"INSERT INTO RollingQueuesValues VALUES(21,'domainInfo','10.0.0.2','+5',{FT},{FT});"
                 f"INSERT INTO RollingQueuesValues VALUES(22,'Tact-pid:+12,ProcessStart:{FT}-amsifrag','PS','3',{FT},{FT});"
                 f"INSERT INTO RollingQueuesValues VALUES(23,'RecentThreatsOnMachine','Behavior:Win32/Test.A','1',{FT},{FT});")
        folders['queues'] = scans(t, 'queues', q + rows, None)
        folders['values'] = scans(t, 'values',
                                  'CREATE TABLE AmsiFileCache(ID INTEGER PRIMARY KEY, PersistId TEXT, ExpirationDate TEXT);'
                                  "INSERT INTO AmsiFileCache VALUES(1,'A','2026-10-19+14:01'),(2,'B','1500-01-01'),(3,'C','1601-01-01+01:00'),(4,'D','2026-10-19 15:23:58');"
                                  'CREATE TABLE SystemRegistryCache(ID INTEGER PRIMARY KEY, RegPath TEXT, RegOperation INTEGER, NewRegType INTEGER, NewRegData BLOB,'
                                  ' OldRegType INTEGER, OldRegData BLOB, InstanceTimeStamp INTEGER, FileIDHash INTEGER);'
                                  f"INSERT INTO SystemRegistryCache VALUES(1,'K1',1,4,x'01000000ff',5,x'00000002',{FT},0),(2,'K2',NULL,1,x'610000006200',7,x'6100000062000000',{FT},0);"
                                  'CREATE TABLE BmProcessInfo(ID INTEGER PRIMARY KEY, ImageFileName TEXT, ProcessStartTime INTEGER, PID INTEGER, ProcessFlags INTEGER, RuleId BLOB);'
                                  f"INSERT INTO BmProcessInfo VALUES(1,'C:\\Tools\\evil.exe',{FT},4120,1179785,x'000102030405060708090a0b0c0d0e0f');"
                                  'CREATE TABLE FileHashes(ID INTEGER PRIMARY KEY, VSN INTEGER, FileID INTEGER, InstanceTimeStamp INTEGER, SHA1 BLOB, MD5 BLOB, SHA256 BLOB);'
                                  f"INSERT INTO FileHashes VALUES(1,-328604643,2533274790530311,{FT},NULL,NULL,x'ab'),(2,-328604643,NULL,{FT},NULL,NULL,NULL);"
                                  + bpi + f"INSERT INTO BackupProcessInfo VALUES(1,'\\Device\\HarddiskVolume٣\\T\\a.exe',{FT},{FT + 10},1),(2,'\\Device\\HarddiskVolume99999999999\\T\\b.exe',{FT},{FT + 10},1);"
                                  + apc + f"INSERT INTO AttributePersistContext VALUES(1,'ENG:OFNSET:C:\\Windows\\System32\\renamed.exe','cmd.exe',{FT},{FT},'k');",
                                  None)

        def corrupt_page1(p):
            with open(p, 'r+b') as fh:
                fh.seek(100)
                fh.write(b'\x01')
        folders['badbase'] = scans(t, 'badbase', bpi + f"INSERT INTO BackupProcessInfo VALUES(1,'C:\\T\\a.exe',{FT},{FT + 10},1);",
                                   'CREATE TABLE Extra(a); INSERT INTO Extra VALUES(1);', corrupt=corrupt_page1)
        with open(os.path.join(t, 'tiny.db'), 'wb') as fh:
            fh.write(b'SQLite format 3\x00' + b'\x02\x00' + b'\x00' * 82)

        # 1. every edition produces the exe's events on each synthetic case
        r = subprocess.run([sys.executable, os.path.join(ROOT, 'ports', 'verify_ports.py')] + list(folders.values()), capture_output=True, text=True, encoding='utf-8',
                           errors='replace', env=dict(os.environ, PYTHONIOENCODING='utf-8'))
        print(r.stdout.strip())
        check('all editions match the exe on the synthetic cases', r.returncode == 0)

        # 2. specific behaviour
        m, c = py_case(folders['utf8'])
        ev = c.events[0]
        check('invalid UTF-8 kept as \\xNN and the change is WAL-modified (py)', ev.status == 'WAL-modified' and '\\xc1' in c.path_of(ev), (ev.status, c.path_of(ev)))
        out = ps(f"$c = New-Object Mpdbx.Case -ArgumentList '{folders['utf8']}', 0; $c.Events[0].Status; $c.PathOf($c.Events[0])")
        check('invalid UTF-8 kept as \\xNN and the change is WAL-modified (ps)', out[:1] == ['WAL-modified'] and '\\xc1' in ''.join(out), out)
        for name, tbl in (('pk', 'KV'), ('types', 'T')):
            m, c = py_case(folders[name])
            st = [r[2] for r in c.tables[tbl]['rows']]
            check(f'{name}: one WAL-modified row (py)', st == ['WAL-modified'], st)
            out = ps(f"$c = New-Object Mpdbx.Case -ArgumentList '{folders[name]}', 0; ($c.Tables['{tbl}'].Rows | ForEach-Object {{ $_.Status }}) -join ','")
            check(f'{name}: one WAL-modified row (ps)', out == ['WAL-modified'], out)
        m, c = py_case(folders['growth'])
        check('schema growth + delete loads (py)', any(h[0] == 'SQLite schema version' for h in c.host))
        cols, rows = m.raw_view(c, 'SQLiteGlobals')
        check('removed short row padded in raw view (py)', rows and len(rows[0]) == len(cols) and rows[0][-1] == 'Removed by WAL', (cols, rows))
        out = ps(f"$c = New-Object Mpdbx.Case -ArgumentList '{folders['growth']}', 0; $v = $c.RawView('SQLiteGlobals'); $v.Rows[0].Count; $v.Columns.Count; $v.Rows[0][-1]")
        check('schema growth + delete loads, row padded (ps)', len(out) == 3 and out[0] == out[1] and out[2] == 'Removed by WAL', out)
        m, c = py_case(folders['queues'])
        logons = [e for e in c.events if e.kind == 'RdpLogon']
        # reference: malformed JSON, null/negative LT, boolean fields -> generic; an object without the fields is a logon with empty fields
        check('RDP records decoded as the reference does (py)', sorted(e.field('Source IP') for e in logons) == ['', '198.51.100.7'], [e.field('Source IP') for e in logons])
        hosts = [h[1] for h in c.host]
        check('domainInfo "²" stays generic, "+5" parses (py)', not any('10.0.0.1' in h for h in hosts) and any('10.0.0.2 (flags 0x5' in h for h in hosts), hosts)
        check('Tact with "+12" pid decodes (py)', any(e.field('Process') for e in c.events), [e.fields for e in c.events if 'Tact' in e.summary])
        out = ps(f"$c = New-Object Mpdbx.Case -ArgumentList '{folders['queues']}', 0; @($c.Events | Where-Object {{ $_.Kind -eq 'RdpLogon' }}).Count")
        check('RDP records decoded as the reference does (ps)', out == ['2'], out)
        det = [e for e in m.apply(c, m._f(special='detections'), [], False)]
        check('Detections quick view = threats + LowFi only (py)', [e.field('Threat') is not None for e in det] == [True], [e.summary for e in det])
        m, c = py_case(folders['values'])
        check('malformed text dates stay raw and untimed (py)', [e.time is None for e in c.events if e.kind == 'StoreExpiry'] == [True, True, True, False])
        regs = {e.field('RegPath'): e for e in c.events if e.kind == 'RegistryChange'}
        check('registry decoding follows the reference (py)', (regs['K1'].field('RegOperation'), regs['K1'].field('NewRegData'), regs['K1'].field('OldRegData'),
                                                              regs['K2'].field('NewRegData'), regs['K2'].field('OldRegData')) == ('0x1 (unknown)', '01000000ff', '2', 'a', 'a | b'),
              [(e.field('RegOperation'), e.field('NewRegData'), e.field('OldRegData')) for e in regs.values()])
        bm = [e for e in c.events if e.kind == 'BmRecord']
        check('behaviour-monitor rows become events with decoded flags/GUIDs (py)', len(bm) == 1 and bm[0].field('ProcessFlags') == '0x120089 = bits 0,3,7,17,20'
              and bm[0].field('RuleId') == '{03020100-0504-0706-0809-0A0B0C0D0E0F}', bm[0].fields if bm else None)
        check('Arabic-digit / overflowing volume numbers are not device paths (py)',
              [m.parse_path(c.path_of(e))[0] for e in c.events if e.kind == 'ProcessFirstStart'] == ['other', 'other'])
        hits = m.apply(c, m._f(), m.parse_search('sha256:ab'), False)
        check('digest search ignores invalid-length digests (py)', hits == [], [e.summary for e in hits])
        ren = m.apply(c, m._f(special='renamed_exe'), [], False)
        check('Renamed executables quick view includes system folders (py)', len(ren) == 1)
        card = next(k for k in m.findings(c) if k[1] == 'File hashes')
        check('File hashes card counts only records with an MFT reference (py)', len(card[3]) == 1, len(card[3]))
        out = ps(f"$c = New-Object Mpdbx.Case -ArgumentList '{folders['values']}', 0; $b = $c.Events | Where-Object {{ $_.Kind -eq 'BmRecord' }}; $b.F('ProcessFlags'); "
                 f"$c.Apply((New-Object Mpdbx.Facets), $c.ParseSearch('sha256:ab'), $false).Count; ($c.Findings() | Where-Object {{ $_.Title -eq 'File hashes' }}).Ids.Count")
        check('Bm events, digest search, File hashes card (ps)', out == ['0x120089 = bits 0,3,7,17,20', '0', '1'], out)
        m, c = py_case(folders['badbase'])
        check('unreadable DB-only image: merged rows load with unknown provenance (py)', c.events and all(e.status == 'unknown' for e in c.events)
              and any('DB-only image unreadable' in w for w in c.warnings), (len(c.events), c.warnings))
        out = ps(f"$c = New-Object Mpdbx.Case -ArgumentList '{folders['badbase']}', 0; $c.Events.Count; ($c.Warnings -join ';')")
        check('unreadable DB-only image (ps)', out[:1] == ['1'] and 'DB-only image unreadable' in ''.join(out), out)
        try:
            m.Case(os.path.join(t, 'tiny.db'))
            ok = False
        except ValueError as e:
            ok = 'empty or truncated' in str(e)
        check('header-only file: clean error (py)', ok)
        out = ps(f"try {{ New-Object Mpdbx.Case -ArgumentList '{os.path.join(t, 'tiny.db')}', 0 | Out-Null; 'loaded' }} catch {{ $_.Exception.InnerException.Message }}")
        check('header-only file: clean error (ps)', 'empty or truncated' in ''.join(out), out)

        # 3. export guards
        exp = os.path.join(t, 'exp')
        os.makedirs(exp)
        link = os.path.join(exp, 'Timeline.csv')
        os.link(os.path.join(folders['pk'], 'mpenginedb.db'), link)
        before = open(os.path.join(folders['pk'], 'mpenginedb.db'), 'rb').read()
        r1 = subprocess.run([sys.executable, PY, 'export', folders['pk'], '--out', exp], capture_output=True, text=True)
        r2 = subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', PS, folders['pk'], '-Export', exp], capture_output=True, text=True)
        after = open(os.path.join(folders['pk'], 'mpenginedb.db'), 'rb').read()
        check('export refuses a hard link to the evidence (py, ps)', r1.returncode != 0 and r2.returncode != 0 and before == after, (r1.returncode, r2.returncode, r1.stderr[-200:], r2.stderr[-200:]))
        ev = os.path.join(t, 'evcase')
        os.makedirs(ev)
        shutil.copyfile(os.path.join(folders['pk'], 'mpenginedb.db'), os.path.join(ev, 'evidence.txt'))
        before = open(os.path.join(ev, 'evidence.txt'), 'rb').read()
        r1 = subprocess.run([sys.executable, PY, 'export', os.path.join(ev, 'evidence.txt'), '--out', ev], capture_output=True, text=True)
        r2 = subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', PS, os.path.join(ev, 'evidence.txt'), '-Export', ev], capture_output=True, text=True)
        check('export never overwrites an input named evidence.txt (py, ps)', open(os.path.join(ev, 'evidence.txt'), 'rb').read() == before)
        check('refused export exits 5 and writes nothing (py, ps)', r1.returncode == 5 and r2.returncode == 5 and sorted(os.listdir(ev)) == ['evidence.txt'],
              (r1.returncode, r2.returncode, r1.stderr[-200:], sorted(os.listdir(ev))))
        bad = scans(t, 'badname', 'CREATE TABLE "x\\..\\..\\victim"(a); INSERT INTO "x\\..\\..\\victim" VALUES(1);', None)
        out2 = os.path.join(t, 'out2', 'inner')
        os.makedirs(out2)
        subprocess.run([sys.executable, PY, 'export', bad, '--out', out2], capture_output=True)
        subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', PS, bad, '-Export', out2], capture_output=True)
        escaped = [p for p in (os.path.join(t, 'victim.csv'), os.path.join(t, 'out2', 'victim.csv')) if os.path.exists(p)]
        check('table names cannot escape the export folder (py, ps)', not escaped, escaped)
        # review: alternate data streams, \.\ paths, WAL card, Files & processes search
        m, c = py_case(folders['pk'])
        try:
            m.write_csv(os.path.join(folders['pk'], 'mpenginedb.db') + ':out.csv', ['a'], [], [x[0] for x in c.inputs])
            ok = False
        except ValueError:
            ok = True
        check('export to an alternate data stream refused (py)', ok)
        out = ps(f"$c = New-Object Mpdbx.Case -ArgumentList '{folders['pk']}', 0; try {{ $c.WriteCsv('{os.path.join(folders['pk'], 'mpenginedb.db')}:out.csv', [string[]]@('a'), (New-Object 'System.Collections.Generic.List[string[]]')); 'written' }} catch {{ 'refused' }}")
        check('export to an alternate data stream refused (ps)', out[-1:] == ['refused'], out)
        check(r'\\.\C: is a drive path, not UNC (py)', m.parse_path(r'\\.\C:\Tools\a.exe')[0] == 'drive')
        m, c = py_case(folders['utf8'])
        card = next(k for k in m.findings(c) if k[1].startswith('Rows found only in the WAL'))
        check('WAL card follows the red-flag rule: modified rows are not counted (py)', len(card[3]) == 0, len(card[3]))
        m, c = py_case(folders['values'])
        cols, rows, evs = m.views(c)['Behaviour monitor']
        f = m.row_filter(c, r'path:*\tools\*', 0)
        check('Files & processes search uses the query language (py)', [f(r, e) for r, e in zip(rows, evs)] == [True])
        # search keys, quoting, digest prefix, Locations rows, raw Source column, export names, CLI
        mc = os.path.join(ROOT, 'tests', 'fixtures', 'multi_commit')
        m, c = py_case(mc)
        # a FileHashes row whose SHA256 is 000102...1f: a middle substring is not a prefix
        dg = scans(t, 'digest', 'CREATE TABLE FileHashes(ID INTEGER PRIMARY KEY, VSN INTEGER, FileID INTEGER, InstanceTimeStamp INTEGER, SHA1 BLOB, MD5 BLOB, SHA256 BLOB);'
                   f"INSERT INTO FileHashes VALUES(1,-328604643,2533274790530311,{FT},NULL,NULL,x'{bytes(range(32)).hex()}');", None)
        md, cd = py_case(dg)
        sha = bytes(range(32)).hex()
        dq = [f'sha256:{sha[:8]}', f'sha256:{sha[4:12]}', f'sha256:*{sha[4:12]}*']
        dn = [len(md.apply(cd, md._f(), md.parse_search(q), False)) for q in dq]
        dqs = ','.join("'" + q + "'" for q in dq)
        dps = ps(f"$c = New-Object Mpdbx.Case -ArgumentList '{dg}', 0; foreach ($q in @({dqs})) {{ $c.Apply((New-Object Mpdbx.Facets), $c.ParseSearch($q), $false).Count }}")
        check('digest without wildcard is a prefix, not a substring (py, ps)', dn == [1, 0, 1] and dps == ['1', '0', '1'], (dn, dps))
        leaf = c.locations[0].key.rsplit('\\', 1)[-1]
        queries = ['src:walonly', 'src:walmod', 'src:wal-only', 'pid:4120', 'nocert:yes', 'type:process*start', '"pid:4120"', 'loc:outside']
        pyn = [len(m.apply(c, m._f(), m.parse_search(q), False)) for q in queries]
        qs = ','.join("'" + q.replace("'", "''") + "'" for q in queries)
        psn = ps(f"$c = New-Object Mpdbx.Case -ArgumentList '{mc}', 0; foreach ($q in @({qs})) {{ $c.Apply((New-Object Mpdbx.Facets), $c.ParseSearch($q), $false).Count }}")
        check('search keys behave the same in both editions (py, ps)', [str(x) for x in pyn] == psn, (pyn, psn))
        d = dict(zip(queries, pyn))
        check('src:walonly / src:walmod find WAL rows (py)', d['src:walonly'] > 0 and d['src:walmod'] > 0 and d['src:wal-only'] == d['src:walonly'], d)
        check('pid: and nocert:yes are implemented (py)', d['pid:4120'] >= 1 and d['nocert:yes'] > 0, d)
        check('type: honours a middle wildcard (py)', d['type:process*start'] > 0, d)
        check('a quoted key:value is free text (py)', d['"pid:4120"'] >= 1, d)
        tok = m.search_tokens(r'path:"C:\Program Files\*" -"a b"')
        check('quoted value after key: stays one token (py)', tok == [(False, r'path:C:\Program Files\*', 'plain'), (True, 'a b', 'literal')], tok)
        out = ps(r"""[Mpdbx.Case]::SearchTokens('path:"C:\Program Files\*" -"a b"') | ForEach-Object { '{0}|{1}|{2}' -f $_.Neg, $_.Text, $_.Kind }""")
        check('quoted value after key: stays one token (ps)', out == [r'False|path:C:\Program Files\*|plain', 'True|a b|literal'], out)
        for bad in ('src:zz', 'pid:x', 'loc:q', 'nocert:no', '"open'):
            try:
                m.parse_search(bad)
                check(f'{bad} is rejected (py)', False)
            except ValueError:
                pass
        cols, rows, evs = m.views(c)['Locations']
        f = m.row_filter(c, f'name:{leaf}', 0)
        kept = [i for i, r in enumerate(rows) if f(r, m.row_events(c, 'Locations', evs, i))]
        check('Locations rows answer path:/name: searches (py)', 0 in kept, kept)
        f = m.row_filter(c, '"' + rows[0][1] + '"', 0)
        check('cell-only text finds Locations rows (py)', f(rows[0], m.row_events(c, 'Locations', evs, 0)))
        out = ps(f"$c = New-Object Mpdbx.Case -ArgumentList '{mc}', 0; $v = $c.Views() | Where-Object {{ $_.Name -eq 'Locations' }}; ($c.FilterView($v, 'name:{leaf}') -join ',')")
        check('Locations rows answer path:/name: searches (ps)', out[-1:] and '0' in out[-1].split(','), out)
        cols, rows = m.raw_view(c, 'BackupProcessInfo')
        f = m.row_filter(c, r'/\.exe/', 0)
        check('/regex/ matches raw table cells (py)', any(f(r, None) for r in rows))
        nm = scans(t, 'names', 'CREATE TABLE "a:b"(Source TEXT); INSERT INTO "a:b" VALUES(1); CREATE TABLE "a?b"(x); INSERT INTO "a?b" VALUES(2);', None)
        m2, c2 = py_case(nm)
        check('a table column named Source keeps its own name (py)', m2.raw_view(c2, 'a:b')[0] == ['Source', '[Source]'], m2.raw_view(c2, 'a:b')[0])
        out = ps(f"$c = New-Object Mpdbx.Case -ArgumentList '{nm}', 0; $c.RawView('a:b').Columns -join '|'")
        check('a table column named Source keeps its own name (ps)', out[-1:] == ['Source|[Source]'], out)
        for name, cmd in (('py', [sys.executable, PY, 'export', nm, '--out', os.path.join(t, 'names_py')]),
                          ('ps', ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', PS, nm, '-Export', os.path.join(t, 'names_ps')])):
            subprocess.run(cmd, capture_output=True)
            got = sorted(x for x in os.listdir(os.path.join(t, 'names_' + name)) if x.startswith('raw_'))
            check(f'colliding table names export to separate files ({name})', got == ['raw_a_b.csv', 'raw_a_b_2.csv'], got)
        r = subprocess.run([sys.executable, PY, '--help'], capture_output=True, text=True, timeout=60)
        check('--help prints usage, no GUI (py)', r.returncode == 0 and 'usage' in r.stdout, (r.returncode, r.stdout[:80]))
    finally:
        shutil.rmtree(t, ignore_errors=True)
    print(f'\n{len(FAILS)} failed' if FAILS else '\nall passed')
    return 1 if FAILS else 0


if __name__ == '__main__':
    sys.exit(main())
