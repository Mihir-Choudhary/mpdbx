$exe = Join-Path $PSScriptRoot 'target\release\mpdbx.exe'
$limit = 8388608
if (-not (Test-Path $exe)) { Write-Output "missing $exe"; exit 1 }
$size = (Get-Item $exe).Length
if ($size -gt $limit) { Write-Output "$size bytes > $limit FAIL"; exit 1 }
Write-Output "$size bytes <= $limit OK"
exit 0
