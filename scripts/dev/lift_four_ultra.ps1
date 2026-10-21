param(
  [string]$LifterPath = '',
  [string]$OutDir = '',
  [string[]]$Only = @()
)

# Lift the four Ultra samples that already come back with correct IR:
# xor / add / branch @ 0x140007210, mix @ 0x140007450.
# Lifter stdout/stderr stay in lift.out / lift.err / lift.log.
# Console prints lift_time then the optimized output.ll.
#
#   cmd /c scripts\dev\lift_four_ultra.cmd
#   cmd /c scripts\dev\lift_four_ultra.cmd -Only mix
#   cmd /c scripts\dev\lift_four_ultra.cmd -LifterPath D:\repo\Mergen\build_msvc\lifter.exe

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $OutDir) {
  $OutDir = Join-Path $repo 'lift_four_out'
}

function Resolve-LifterPath {
  param([string]$Candidate)
  if ($Candidate) {
    if (-not (Test-Path -LiteralPath $Candidate)) {
      throw "Lifter not found at '$Candidate'"
    }
    return (Resolve-Path -LiteralPath $Candidate).Path
  }
  $preferred = @(
    (Join-Path $repo 'build_msvc\lifter.exe'),
    (Join-Path $repo 'build_msvc_dbg\lifter.exe'),
    (Join-Path $repo 'build_iced\lifter.exe'),
    (Join-Path $repo 'build_zydis\lifter.exe')
  )
  foreach ($path in $preferred) {
    if (Test-Path -LiteralPath $path) {
      return (Resolve-Path -LiteralPath $path).Path
    }
  }
  throw 'No lifter.exe found. Build first, or pass -LifterPath.'
}

$lifter = Resolve-LifterPath $LifterPath
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$samples = @(
  @{
    name  = 'xor'
    pe    = Join-Path $repo 'sample\xor\xor_test_fixed4.exe'
    entry = '0x140007210'
    dump  = Join-Path $repo 'sample\xor\entry_7210.dmp'
  }
  @{
    name  = 'add'
    pe    = Join-Path $repo 'sample\add\add_test_fixed4.exe'
    entry = '0x140007210'
    dump  = Join-Path $repo 'sample\add\entry_7210.dmp'
  }
  @{
    name  = 'branch'
    pe    = Join-Path $repo 'sample\branch\branch_test_fixed4.exe'
    entry = '0x140007210'
    dump  = Join-Path $repo 'sample\branch\entry_7210.dmp'
  }
  @{
    name  = 'mix'
    pe    = Join-Path $repo 'sample\mix\test_fixed4.exe'
    entry = '0x140007450'
    dump  = Join-Path $repo 'sample\mix\entry_7450.dmp'
  }
)

if ($Only.Count -gt 0) {
  $want = $Only | ForEach-Object { $_.ToLowerInvariant() }
  $samples = $samples | Where-Object { $want -contains $_.name }
  if (-not $samples) {
    throw "No matching samples for -Only $($Only -join ',')"
  }
}

$env:MERGEN_MAX_BLOCK_BUDGET = '131072'
Remove-Item Env:MERGEN_DIAG_LIFT_PROGRESS -ErrorAction SilentlyContinue
Remove-Item Env:MERGEN_INSN_STREAM_FILE -ErrorAction SilentlyContinue
Remove-Item Env:MERGEN_WRITE_STREAM_FILE -ErrorAction SilentlyContinue

$failed = 0
foreach ($s in $samples) {
  if (-not (Test-Path -LiteralPath $s.pe)) {
    throw "PE missing: $($s.pe)"
  }
  $work = Join-Path $OutDir $s.name
  New-Item -ItemType Directory -Force -Path $work | Out-Null
  $namedLl = Join-Path $work "$($s.name).ll"
  foreach ($n in @('output.ll', "$($s.name).ll", 'output_no_opts.ll',
                   'output_diagnostics.json', 'lift.out', 'lift.err', 'lift.log')) {
    Remove-Item -LiteralPath (Join-Path $work $n) -ErrorAction SilentlyContinue
  }
  Remove-Item -LiteralPath (Join-Path $OutDir "$($s.name).ll") -ErrorAction SilentlyContinue

  $args = @($s.pe, $s.entry)
  if ($s.dump -and (Test-Path -LiteralPath $s.dump)) {
    $args += "--mem-dump=$($s.dump)"
  } elseif ($s.dump) {
    throw "mem-dump missing: $($s.dump)"
  }

  $stdout = Join-Path $work 'lift.out'
  $stderr = Join-Path $work 'lift.err'
  $log = Join-Path $work 'lift.log'
  $rawLl = Join-Path $work 'output.ll'
  $ll = $namedLl

  Write-Host ''
  Write-Host ("=" * 72)
  Write-Host "LIFT $($s.name)  $($s.entry)  dump=$(Split-Path -Leaf $s.dump)"
  Write-Host ("=" * 72)

  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $proc = Start-Process -FilePath $lifter -ArgumentList $args -WorkingDirectory $work `
    -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
  $sw.Stop()
  $code = $proc.ExitCode
  $secs = $sw.Elapsed.TotalSeconds

  $logLines = New-Object System.Collections.Generic.List[string]
  [void]$logLines.Add("sample=$($s.name)")
  [void]$logLines.Add("entry=$($s.entry)")
  [void]$logLines.Add("pe=$($s.pe)")
  [void]$logLines.Add("dump=$($s.dump)")
  [void]$logLines.Add("lifter=$lifter")
  [void]$logLines.Add("exit=$code")
  [void]$logLines.Add(("lift_time_s={0:F3}" -f $secs))
  [void]$logLines.Add('')
  [void]$logLines.Add('===== stdout (lift.out) =====')
  if (Test-Path -LiteralPath $stdout) {
    Get-Content -LiteralPath $stdout | ForEach-Object { [void]$logLines.Add($_) }
  }
  [void]$logLines.Add('')
  [void]$logLines.Add('===== stderr (lift.err) =====')
  if (Test-Path -LiteralPath $stderr) {
    Get-Content -LiteralPath $stderr | ForEach-Object { [void]$logLines.Add($_) }
  }
  $diag = Join-Path $work 'output_diagnostics.json'
  if (Test-Path -LiteralPath $diag) {
    [void]$logLines.Add('')
    [void]$logLines.Add('===== output_diagnostics.json =====')
    Get-Content -LiteralPath $diag | ForEach-Object { [void]$logLines.Add($_) }
  }
  Set-Content -LiteralPath $log -Value $logLines -Encoding utf8

  if (Test-Path -LiteralPath $rawLl) {
    Move-Item -LiteralPath $rawLl -Destination $ll -Force
    Copy-Item -LiteralPath $ll -Destination (Join-Path $OutDir "$($s.name).ll") -Force
  }

  Write-Host ("{0} lift_time={1:F3}s  exit={2}" -f $s.name, $secs, $code)
  Write-Host "  log=$log"
  Write-Host "  err=$stderr"
  Write-Host "  ir=$ll"
  if (-not (Test-Path -LiteralPath $ll)) {
    Write-Host "  MISSING $($s.name).ll"
    $failed += 1
    continue
  }
  Write-Host ''
  Write-Host "----- $($s.name).ll -----"
  Get-Content -LiteralPath $ll | Write-Host
  if ($code -ne 0 -and $code -ne 0xC0000005) {
    # 0xC0000005 after a customer ret is expected (process tail); still a written IR.
    $failed += 1
  }
}

Write-Host ''
Write-Host "logs/IR under $OutDir"
if ($failed -ne 0) {
  exit 1
}
exit 0
