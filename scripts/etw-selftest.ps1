#Requires -Version 5.1
<#
.SYNOPSIS
  End-to-end check of netattrib's event-driven (ETW) path. Run from an ELEVATED prompt:
    powershell -ExecutionPolicy Bypass -File scripts\etw-selftest.ps1

.DESCRIPTION
  Starts netattrib filtered to powershell.exe, then a child powershell.exe that
    * resolves a host name in-process        -> expects a DNS-Client 'dns' record with its PID
    * opens 5 short TCP connections, sends an HTTP request and reads the reply
                                             -> expects exactly one source=etw open and one
                                                close per socket, exact local ports, and
                                                non-zero byte counters on close, even though
                                                a 250 ms table poll races ETW delivery
  Verdicts are printed and written to selftest-result.txt next to the project root.
#>
param(
    [string]$Exe = (Join-Path $PSScriptRoot '..\target\release\netattrib.exe'),
    [string]$TargetHost = 'example.com'
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$work = Join-Path $env:TEMP "netattrib-selftest-$PID"
New-Item -ItemType Directory -Force $work | Out-Null
$events = Join-Path $work 'events.jsonl'
$childReport = Join-Path $work 'child.json'
$childScript = Join-Path $work 'child.ps1'
$resultFile = Join-Path $root 'selftest-result.txt'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

@"
`$addrs = [System.Net.Dns]::GetHostAddresses('$TargetHost') | ForEach-Object { `$_.ToString() }
`$ports = @()
for (`$i = 0; `$i -lt 5; `$i++) {
    `$c = New-Object Net.Sockets.TcpClient('$TargetHost', 80)
    `$ports += `$c.Client.LocalEndPoint.Port
    `$s = `$c.GetStream()
    `$req = [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1``r``nHost: $TargetHost``r``nConnection: close``r``n``r``n")
    `$s.Write(`$req, 0, `$req.Length)
    `$buf = New-Object byte[] 65536
    while ((`$n = `$s.Read(`$buf, 0, `$buf.Length)) -gt 0) { }
    `$c.Close()
    Start-Sleep -Milliseconds 50
}
@{ pid = `$PID; ports = `$ports; addrs = `$addrs } | ConvertTo-Json | Set-Content -Encoding UTF8 '$childReport'
"@ | Set-Content -Encoding UTF8 $childScript

# --poll-ms 250 is deliberately aggressive: table polls then routinely see each socket before
# its ETW events are delivered, which exercises the poll/ETW de-duplication and promotion
# logic (every open must still come out exactly once, ETW-sourced).
$mon = Start-Process -FilePath $Exe -PassThru -NoNewWindow -RedirectStandardError (Join-Path $work 'stderr.txt') -ArgumentList @(
    '--filter-exe', 'powershell.exe', '--dns-events', '--json-lines', '--poll-ms', '250',
    '--duration', '14', '-o', $events)
Start-Sleep -Seconds 2
$child = Start-Process -FilePath powershell.exe -PassThru -WindowStyle Hidden -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $childScript)
$child.WaitForExit()
$mon.WaitForExit()

$lines = @()
$lines += "netattrib ETW self-test  $(Get-Date -Format o)"
$lines += "elevated: $isAdmin   os: $([Environment]::OSVersion.VersionString)"
$lines += "--- netattrib stderr"
$lines += Get-Content (Join-Path $work 'stderr.txt')
if (-not (Test-Path $childReport)) {
    $lines += "FAIL child did not complete (network/DNS problem?)"
    $lines | Tee-Object -FilePath $resultFile
    exit 1
}
$c = Get-Content $childReport -Raw | ConvertFrom-Json
$recs = @(Get-Content $events | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
$mine = @($recs | Where-Object { $_.pid -eq $c.pid })
$lines += "--- child pid $($c.pid), ports $($c.ports -join ','), $TargetHost -> $($c.addrs -join ',')"
$lines += "records total: $($recs.Count), for child: $($mine.Count)"

function Check($name, $ok, $detail) {
    $script:lines += ('{0} {1}  {2}' -f ($(if ($ok) { 'PASS' } else { 'FAIL' })), $name, $detail)
    if (-not $ok) { $script:failed = $true }
}
$failed = $false
$opens = @($mine | Where-Object { $_.event -eq 'open' -and $_.remote_port -eq 80 })
$closes = @($mine | Where-Object { $_.event -eq 'close' -and $_.remote_port -eq 80 })
$etwOpens = @($opens | Where-Object { $_.source -eq 'etw' })
$seenPorts = @($opens | ForEach-Object { [int]$_.local_port })
$missing = @($c.ports | Where-Object { $seenPorts -notcontains [int]$_ })
Check 'short-lived connections captured' ($missing.Count -eq 0) "expected $($c.ports.Count), missing local ports: $($missing -join ',')"
Check 'captured by ETW (not polling)' ($etwOpens.Count -ge $c.ports.Count) "$($etwOpens.Count) of $($opens.Count) opens have source=etw"
$dupes = @($c.ports | Where-Object {
    $p = [int]$_
    @($opens | Where-Object { [int]$_.local_port -eq $p }).Count -ne 1 -or
    @($closes | Where-Object { [int]$_.local_port -eq $p }).Count -ne 1
})
Check 'one open + one close per socket (poll/ETW de-duplicated)' ($dupes.Count -eq 0) "ports with duplicates or gaps: $($dupes -join ',')"
Check 'local/remote orientation' ($opens.Count -gt 0 -and @($opens | Where-Object { $c.addrs -contains $_.remote_ip }).Count -eq $opens.Count) 'remote_ip of every open is an address the child resolved'
Check 'byte counters' (@($closes | Where-Object { $_.bytes_recv -gt 0 -and $_.bytes_sent -gt 0 }).Count -ge $c.ports.Count) "$($closes.Count) closes; bytes_recv: $(($closes | ForEach-Object { $_.bytes_recv }) -join ',')"
Check 'attribution exact + path' ($opens.Count -gt 0 -and @($opens | Where-Object { $_.attribution -eq 'exact' -and $_.path -like '*\powershell.exe' }).Count -eq $opens.Count) ''
$dns = @($mine | Where-Object { $_.event -eq 'dns' -and $_.domain -eq $TargetHost })
Check 'DNS-Client query attributed to PID' ($dns.Count -ge 1) "$($dns.Count) dns records for $TargetHost"
Check 'domain filled on connections' (@($opens | Where-Object { $_.domain -eq $TargetHost }).Count -ge 1) "domains: $(($opens | ForEach-Object { $_.domain }) -join ',')"
$lines += "--- raw records for child"
$lines += $mine | ForEach-Object { $_ | ConvertTo-Json -Compress }
$lines | Tee-Object -FilePath $resultFile
"result written to $resultFile"
if ($failed) { exit 1 }
