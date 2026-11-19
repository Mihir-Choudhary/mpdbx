"""Builds the single-file mpdbx.ps1 from mpdbx.src.ps1 + engine.cs (UTF-8 with BOM so Windows PowerShell 5.1 reads it correctly)."""
import os

here = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(here, 'mpdbx.src.ps1'), encoding='utf-8').read()
eng = open(os.path.join(here, 'engine.cs'), encoding='utf-8').read()
assert "'@" not in eng, "engine.cs must not contain a here-string terminator"
assert src.count('#ENGINE#') == 1
out = src.replace('#ENGINE#', eng.rstrip('\n'))
out = out.replace('\r\n', '\n').replace('\n', '\r\n')
with open(os.path.join(here, 'mpdbx.ps1'), 'w', encoding='utf-8-sig', newline='') as fh:
    fh.write(out)
print('wrote mpdbx.ps1', len(out), 'chars')
