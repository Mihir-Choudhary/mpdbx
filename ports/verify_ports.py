"""Checks that the Python and PowerShell editions produce the same events as mpdbx.exe.

    python ports/verify_ports.py <Scans folder> [<Scans folder> ...]

For each folder: runs `mpdbx export`, `python ports/python/mpdbx.py export` and `ports/powershell/mpdbx.ps1 -Export`
into a temporary folder, then compares Timeline.csv row by row (exe vs each port) and every other CSV between the two
ports. Events from Scans\\History Store/Results are read only by mpdbx.exe and are reported separately, not as failures.
Exit code 0 = all match.
"""
import collections
import csv
import os
import subprocess
import sys
import tempfile

csv.field_size_limit(2 ** 31 - 1)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(ROOT, 'target', 'release', 'mpdbx.exe')
PY = os.path.join(ROOT, 'ports', 'python', 'mpdbx.py')
PS = os.path.join(ROOT, 'ports', 'powershell', 'mpdbx.ps1')
HISTORY_KINDS = {'Process start (Store)', 'File scan (Store)', 'AMSI scan', 'Process start (AMSI)', 'Scan run'}


def table(p):
    """Header and data rows."""
    with open(p, encoding='utf-8-sig', newline='') as fh:
        t = [tuple(r) for r in csv.reader(fh)]
    return (t[0] if t else ()), t[1:]


def rows(p):
    return table(p)[1]


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
    return r.returncode, (r.stderr or r.stdout).strip()[-300:]


def main(folders):
    ok = True
    for f in folders:
        with tempfile.TemporaryDirectory(prefix='mpdbx_verify_') as t:
            o, p, s = (os.path.join(t, x) for x in ('exe', 'py', 'ps'))
            results = [run([EXE, 'export', f, '--out', o, '--format', 'csv']), run([sys.executable, PY, 'export', f, '--out', p]),
                       run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', PS, f, '-Export', s])]
            if any(rc != 0 for rc, _ in results):
                same = len({rc for rc, _ in results}) == 1
                print(f"{'SKIP' if same else 'FAIL'} {f}: exit codes {[rc for rc, _ in results]}")
                ok &= same
                continue
            ref = collections.Counter(r for r in rows(os.path.join(o, 'Timeline.csv')) if r[1] not in HISTORY_KINDS)
            hist = sum(1 for r in rows(os.path.join(o, 'Timeline.csv')) if r[1] in HISTORY_KINDS)
            msg = []
            ref_head = table(os.path.join(o, 'Timeline.csv'))[0]
            for name, d in (('python', p), ('powershell', s)):
                head, got = table(os.path.join(d, 'Timeline.csv'))
                got = collections.Counter(got)
                if got != ref:
                    ok = False
                    msg.append(f'{name}: {sum((ref - got).values())} missing, {sum((got - ref).values())} extra')
                # display columns must match; the exe names its raw_ columns from the rows, so an empty list has none
                disp = [x for x in head if not x.startswith(('raw_', 'prov_'))]
                if not disp or list(ref_head[:len(disp)]) != disp:
                    ok = False
                    msg.append(f'{name}: Timeline.csv header differs from the exe')
            # the two editions write the same set of files, each identical header included
            fp, fs = set(os.listdir(p)), set(os.listdir(s))
            for fn in sorted(fp ^ fs):
                ok = False
                msg.append(f"{fn} written only by {'python' if fn in fp else 'powershell'}")
            for fn in sorted(fp & fs):
                if fn.endswith('.csv') and table(os.path.join(p, fn)) != table(os.path.join(s, fn)):
                    ok = False
                    msg.append(f'python/powershell differ in {fn}')
                # raw tables and host context: displayed values must equal the exe's (the exe adds raw_/prov_ columns)
                if (fn.startswith('raw_') or fn == 'Host context.csv') and os.path.exists(os.path.join(o, fn)):
                    head = table(os.path.join(p, fn))[0]
                    n = len(head) - 1 if fn.startswith('raw_') else 2
                    if head[:n] != table(os.path.join(o, fn))[0][:n]:
                        ok = False
                        msg.append(f'{fn} header differs from the exe')
                    got = collections.Counter(r[:n] for r in rows(os.path.join(p, fn)))
                    want = collections.Counter(r[:n] for r in rows(os.path.join(o, fn))
                                               if not (len(r) > 2 and r[2].startswith(('Results ', 'Store '))))  # History facts: exe only
                    if got != want:
                        ok = False
                        msg.append(f'{fn} differs from the exe')
            print(f"{'OK  ' if not msg else 'FAIL'} {f}: {sum(ref.values())} events" + (f' (+{hist} History events, exe only)' if hist else '') +
                  (' — ' + '; '.join(msg) if msg else ''))
    return 0 if ok else 1


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1:]))
