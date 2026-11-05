#Requires -RunAsAdministrator
<#
.SYNOPSIS
    suricataChecker - deploys the Suricata configuration, the ET Open rules and the Suricata service.

.DESCRIPTION
    1. Downloads the current ET Open rules for Suricata 8, checks them against the published MD5 checksum and prepares
       the new rules folder in a temporary folder (rules removed by ET are dropped, built-in rules are kept).
       Rules with the file.magic keyword are commented out (the Windows build has no libmagic).
    2. Validates the new configuration and rules with suricata -T BEFORE anything is changed - Suricata keeps running.
    3. Backs up the current configuration and rules (<Suricata>\backup-before-update, and suricata.yaml.original once),
       stops the service, deploys config\suricata\suricata.yaml, threshold.config and the rules and checks them again.
       If anything fails, the backup is restored. The service is started again in every case.
    4. On the first run registers Suricata as a service (automatic start) on the active network interface.

    Running it again = rules update + service restart (the capture interface of the service is kept).

.PARAMETER SuricataDir
    Suricata installation folder (default C:\Program Files\Suricata).

.PARAMETER Interface
    Capture interface (\Device\NPF_{GUID} or an IP address). Default: the interface of the registered service, on the
    first run the physical adapter with the best default route (you are asked to confirm it).

.PARAMETER RulesOnly
    Only update the rules and restart the service (do not overwrite the configuration).

.PARAMETER Yes
    Do not ask (unattended run): the detected interface is used and a configuration that standard users can change
    is not deployed.

.PARAMETER AllowWritableSource
    With -Yes: deploy the configuration even when standard users can change it (the warning was confirmed elsewhere,
    e.g. in the setup window of suricataChecker).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Install-SuricataConfig.ps1
#>
[CmdletBinding()]
param(
    [string]$SuricataDir = "$env:ProgramFiles\Suricata",
    [string]$Interface,
    [switch]$RulesOnly,
    [switch]$Yes,
    [switch]$AllowWritableSource
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # the progress bar of Invoke-WebRequest slows the download down a lot
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $SuricataDir 'suricata.exe'
$yaml = Join-Path $SuricataDir 'suricata.yaml'
$threshold = Join-Path $SuricataDir 'threshold.config'
$rulesDir = Join-Path $SuricataDir 'rules'
$backupDir = Join-Path $SuricataDir 'backup-before-update'
$etUrl = 'https://rules.emergingthreats.net/open/suricata-8.0.0/emerging.rules.tar.gz'
$srcYaml = Join-Path $here 'suricata\suricata.yaml'
$srcThreshold = Join-Path $here 'suricata\threshold.config'

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Confirm($question) {
    if ($Yes) { return $false }
    return (Read-Host "$question [y/N]") -match '^(y|yes|a|ano)$'
}
function FindService { Get-Service | Where-Object { $_.Name -like '*suricata*' } | Select-Object -First 1 }

# Can a standard user change the file or its folder? (Everyone, Users, Authenticated Users, INTERACTIVE and the signed-in
# user's own account - malware running unelevated under the same account could change it.) Same rules as suricataChecker:
# the file and its folder - any write right; every folder above up to the root - a right to delete / rename a subfolder
# or to take the folder over (whoever has it can put a folder of his own in place of ours).
function WritableByStandardUsers($path) {
    $sids = @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-11', 'S-1-5-4', [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    $write = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteAttributes, WriteExtendedAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    $above = [Security.AccessControl.FileSystemRights]'Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    function Grants($p, $rights) {
        foreach ($r in (Get-Acl -LiteralPath $p).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($r.AccessControlType -eq 'Allow' -and ($r.FileSystemRights -band $rights) -and -not ($r.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
                $sids -contains $r.IdentityReference.Value) { return $true }
        }
        return $false
    }
    try {
        $full = [IO.Path]::GetFullPath($path)
        $dir = [IO.Path]::GetDirectoryName($full)
        if ((Grants $full $write) -or (Grants $dir $write)) { return $true }
        for ($d = [IO.Directory]::GetParent($dir); $d; $d = $d.Parent) { if (Grants $d.FullName $above) { return $true } }
        return $false
    }
    catch { return $true }   # unknown = writable
}

# Runs suricata -T; returns $true when the configuration and the rules load.
function TestConfig($configFile, [string[]]$extra) {
    $testLog = Join-Path $env:TEMP ('suricataChecker_suricata_test_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $testLog | Out-Null
    try {
        $out = & $exe -T -c $configFile -l $testLog @extra 2>&1
        $ok = $LASTEXITCODE -eq 0
        $out | Where-Object { "$_" -match '^E: ' } | ForEach-Object { Write-Host "$_" -ForegroundColor Red }
        return $ok
    }
    finally { Remove-Item $testLog -Recurse -Force -ErrorAction SilentlyContinue }
}

if (-not (Test-Path $exe)) { throw "Suricata was not found in '$SuricataDir'." }
# suricata.exe runs here with administrator rights (-V, -T) and as the LocalSystem service - never one standard users can replace
if (WritableByStandardUsers $exe) {
    throw "Standard users can change $exe or its folder - it is not run with administrator rights. Allow writing there to administrators only (e.g. install Suricata to C:\Program Files), then run this script again."
}
# suricata.exe is linked against wpcap.dll: Npcap puts it into System32 only in the "WinPcap API-compatible Mode"
# (otherwise only into System32\Npcap) - without it neither suricata -T nor the service can start
if (-not (Test-Path (Join-Path ([Environment]::SystemDirectory) 'wpcap.dll'))) {
    throw ('wpcap.dll is missing in ' + [Environment]::SystemDirectory + ' - Npcap is not installed, or not in the "WinPcap API-compatible Mode". ' +
           'Install Npcap (suricataChecker: Settings > Set up Suricata) and keep "Install Npcap in WinPcap API-compatible Mode" ticked, then run this script again.')
}
Write-Host (& $exe -V 2>&1 | Select-String 'version')

# The configuration is loaded by the service running as LocalSystem (it can name plugins and Lua scripts): it must come
# from a folder only administrators can change.
if (-not $RulesOnly) {
    foreach ($f in $srcYaml, $srcThreshold) {
        Write-Host ("{0}  SHA256 {1}" -f $f, (Get-FileHash $f -Algorithm SHA256).Hash)
        if (WritableByStandardUsers $f) {
            Write-Host "WARNING: standard users can change $f (or its folder)." -ForegroundColor Yellow
            if (-not $AllowWritableSource -and -not (Confirm 'Deploy it anyway?')) { throw 'Stopped - make the application folder writable for administrators only, then run the script again.' }
        }
    }
}

# under C:\Windows\Temp: no spaces in the path (a quoted argument ending with \ would be passed wrongly to suricata.exe)
$tmp = Join-Path $env:SystemRoot ('Temp\suricataChecker_rules_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$svc = FindService
$stopped = $false
try {
    # --- 1: download and prepare the rules (Suricata keeps running)
    Step 'Downloading the ET Open rules'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $tgz = Join-Path $tmp 'emerging.rules.tar.gz'
    Invoke-WebRequest -UseBasicParsing $etUrl -OutFile $tgz
    # MD5 from the same server: detects an incomplete or damaged download (HTTPS protects the transfer itself)
    $md5 = (Invoke-WebRequest -UseBasicParsing "$etUrl.md5").Content
    if ($md5 -is [byte[]]) { $md5 = [Text.Encoding]::ASCII.GetString($md5) }
    $expected = "$md5".Trim().Split(' ')[0].ToLowerInvariant()
    $actual = (Get-FileHash $tgz -Algorithm MD5).Hash.ToLowerInvariant()
    if ($expected -notmatch '^[0-9a-f]{32}$' -or $actual -ne $expected) {
        throw "The downloaded rules do not match the published checksum ($actual / $expected) - nothing was changed. Run the script again."
    }
    Write-Host "Checksum OK ($actual)"
    $extract = Join-Path $tmp 'extract'
    New-Item -ItemType Directory -Path $extract | Out-Null
    tar -xzf $tgz -C $extract rules   # only the rules\ folder of the archive
    if ($LASTEXITCODE -ne 0) { throw 'Extracting the rules failed - nothing was changed.' }

    # the future rules folder: the current one (built-in rules of the installation) without the old ET files + the new ET files
    $stageRules = Join-Path $tmp 'rules'
    New-Item -ItemType Directory -Path $stageRules | Out-Null
    if (Test-Path $rulesDir) { Copy-Item (Join-Path $rulesDir '*') $stageRules -Recurse -Force }
    Get-ChildItem $stageRules -Filter 'emerging-*.rules' | Remove-Item -Force   # rules ET removed must not stay
    Copy-Item (Join-Path $extract 'rules\*') $stageRules -Recurse -Force
    $disabled = 0
    foreach ($f in Get-ChildItem $stageRules -Filter *.rules) {
        $lines = [IO.File]::ReadAllLines($f.FullName)
        $changed = $false
        for ($i = 0; $i -lt $lines.Length; $i++) {
            if ($lines[$i] -match '^\s*(alert|drop|pass|reject)\b.*\bfile\.magic;') {
                $lines[$i] = '# [suricataChecker: file.magic is not available in the Windows build] ' + $lines[$i]
                $disabled++; $changed = $true
            }
        }
        if ($changed) { [IO.File]::WriteAllLines($f.FullName, $lines) }
    }
    Write-Host ("Prepared: {0} emerging-*.rules files, rules with file.magic commented out: {1}" -f (Get-ChildItem $stageRules -Filter 'emerging-*.rules').Count, $disabled)

    # --- 2: test the new configuration with the new rules before anything is changed
    Step 'Validating the new configuration and rules (suricata -T)'
    $testYaml = if ($RulesOnly) { $yaml } else { $srcYaml }
    $testThreshold = if ($RulesOnly) { $threshold } else { $srcThreshold }
    if (-not (TestConfig $testYaml @('--set', "default-rule-path=$stageRules\", '--set', "threshold-file=$testThreshold"))) {
        throw 'The configuration test failed - nothing was changed, Suricata keeps running with the current configuration.'
    }
    Write-Host 'The configuration is OK.' -ForegroundColor Green

    # --- 3: back up, stop, deploy
    Step "Backing up the current configuration to $backupDir"
    if ((Test-Path $yaml) -and -not (Test-Path "$yaml.original")) { Copy-Item $yaml "$yaml.original" }
    if (Test-Path $backupDir) { Remove-Item $backupDir -Recurse -Force }
    New-Item -ItemType Directory -Path $backupDir | Out-Null
    foreach ($f in $yaml, $threshold) { if (Test-Path $f) { Copy-Item $f $backupDir } }
    if (Test-Path $rulesDir) { Copy-Item $rulesDir (Join-Path $backupDir 'rules') -Recurse }

    if ($svc -and $svc.Status -eq 'Running') { Step "Stopping the service $($svc.Name)"; Stop-Service $svc.Name -Force; $stopped = $true }
    try {
        Step 'Deploying'
        if (-not $RulesOnly) {
            Copy-Item $srcYaml $yaml -Force
            Copy-Item $srcThreshold $threshold -Force
            Write-Host 'Copied: suricata.yaml, threshold.config'
        }
        if (Test-Path $rulesDir) { Remove-Item (Join-Path $rulesDir '*') -Recurse -Force } else { New-Item -ItemType Directory -Path $rulesDir | Out-Null }
        Copy-Item (Join-Path $stageRules '*') $rulesDir -Recurse -Force
        Write-Host "Rules: $rulesDir"
        if (-not (TestConfig $yaml @())) { throw 'The deployed configuration does not pass suricata -T.' }
    }
    catch {
        Write-Host "Deployment failed: $($_.Exception.Message) - restoring the backup." -ForegroundColor Red
        foreach ($f in 'suricata.yaml', 'threshold.config') {
            $b = Join-Path $backupDir $f
            if (Test-Path $b) { Copy-Item $b (Join-Path $SuricataDir $f) -Force }
        }
        if (Test-Path (Join-Path $backupDir 'rules')) {
            if (Test-Path $rulesDir) { Remove-Item (Join-Path $rulesDir '*') -Recurse -Force }
            Copy-Item (Join-Path $backupDir 'rules\*') $rulesDir -Recurse -Force
        }
        throw
    }

    # --- 4: service
    if (-not $Interface -and $svc) {
        # keep the capture interface of the registered service
        $image = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)").ImagePath
        if ($image -match '\s-i\s+("[^"]+"|\S+)') { $Interface = $Matches[1].Trim('"') }
    }
    if (-not $Interface) {
        # best default route by route + interface metric, physical adapters first (not Hyper-V vEthernet, VPN, loopback)
        $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | ForEach-Object {
            $ip = Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            $ad = Get-NetAdapter -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue
            if ($ad -and $ad.Status -eq 'Up') { [pscustomobject]@{ Adapter = $ad; Metric = $_.RouteMetric + $ip.InterfaceMetric } }
        } | Sort-Object Metric)
        $best = $routes | Where-Object { -not $_.Adapter.Virtual } | Select-Object -First 1
        if (-not $best -and -not $Yes) {
            # a virtual machine can report its only network adapter as virtual
            $best = $routes | Select-Object -First 1
            if ($best) { Write-Host 'No physical adapter with a default route - offering the active virtual adapter (e.g. in a virtual machine).' -ForegroundColor Yellow }
        }
        if (-not $best) { throw 'The active network adapter could not be determined - use the -Interface parameter (\Device\NPF_{GUID}).' }
        $Interface = "\Device\NPF_$($best.Adapter.InterfaceGuid)"
        Write-Host "Interface: $($best.Adapter.Name) ($($best.Adapter.InterfaceDescription)) -> $Interface"
        if (-not $Yes -and -not (Confirm 'Capture on this adapter?')) { throw 'Stopped - run the script again with -Interface \Device\NPF_{GUID}.' }
    }

    if (-not $svc) {
        Step 'Registering the Suricata service'
        & $exe --service-install -c $yaml -i $Interface 2>&1 | ForEach-Object { Write-Host "$_" }
        $svc = FindService
        if (-not $svc) { throw 'Registering the service failed.' }
    }
    # --service-install does not quote paths with spaces ("-c C:\Program Files\..." then fails),
    # so the command line of the service is written here.
    $binPath = "`"$exe`" -c `"$yaml`" -i $Interface"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)" -Name ImagePath -Value $binPath
    Write-Host "Service command: $binPath"
    Set-Service $svc.Name -StartupType Automatic
    $stopped = $true   # start it below (also a newly registered service)
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    # the IDS must not stay off: whatever happened, a service stopped by this script is started again
    if ($stopped -and $svc) {
        Step "Starting the service $($svc.Name)"
        try {
            Start-Service $svc.Name
            Start-Sleep -Seconds 5
            $svc.Refresh()
            Write-Host "Service state: $($svc.Status)" -ForegroundColor $(if ($svc.Status -eq 'Running') { 'Green' } else { 'Red' })
        }
        catch { Write-Host "The service could not be started: $($_.Exception.Message)" -ForegroundColor Red }
    }
}
Write-Host "Event log: $(Join-Path $SuricataDir 'log\eve.json')"
# SIG # Begin signature block
# MIIdnQYJKoZIhvcNAQcCoIIdjjCCHYoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD1ZE5eTJihRFOP
# zbOcCi2/KdVxq8Kl+QQ2Mfi0wyeEv6CCF1wwggQeMIIChqADAgECAhA7bF30z/iP
# r08MbKLtqoDfMA0GCSqGSIb3DQEBCwUAMCcxJTAjBgNVBAMMHFN1cmljYXRhQ2hl
# Y2tlciBDb2RlIFNpZ25pbmcwHhcNMjYxMTAzMjIyMjUyWhcNMzExMTAzMjIzMjUy
# WjAnMSUwIwYDVQQDDBxTdXJpY2F0YUNoZWNrZXIgQ29kZSBTaWduaW5nMIIBojAN
# BgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAzqRcVJ/U5rB3nkAUODQrR2uJA/fx
# DkieUl1LOo+YYVAo/35/tuxKBct+ZA5jHzraNrxYz5SGZ3WXhKifjYgV8E4SvNWP
# O2jzmUxtQ7BNIXKkH8O4fiJPKyi07uhuCvrjogQyX1DPjWgFBn/3o1WMCXzqov1m
# sB7j9sHWiVTKRYrivkTmEeaECQ4cFmr54AqdpxTKvsTm47A0O/J+BrWggKLyjKjz
# lPyrnst4buGGUrKa1yzaAwHUv313zbGGiqV/yoCNSxxGCgKUxJ9eqHqYWQWzpgIC
# o5/Y+KFlrgxHA8qrB7qAstPOSoSSZL3chZGB0io28gSbbOnezeDfolQBbUjcL6yh
# ESqU0LdoOb88b93HfdJw7zttZSZap+j2bOxPbqhDJvArJp8iu98FwRGazTTSbEYd
# AYSbAxOiYRXMHGOcGVdxNT0EHhzCuKKUvdgHYquGttMJSQe8AS3jPofPoP2L2krg
# OcVGewyZeq506bkTtxIBB6D3iMUL/qV73m4BAgMBAAGjRjBEMA4GA1UdDwEB/wQE
# AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUAbGe9HF+RSIlF3qy
# 6elZW6+jXxswDQYJKoZIhvcNAQELBQADggGBAKdymNqLh5LMfMxETvUTGcqTCjKj
# t3mnFAOuzrFX0nyHF/wFTNGR9AoeVSaMebvAdcSJsQf05uCXC9vrs2PI4s/xnyD9
# aeVJDTrMB+6B4i5+XLUsfUD+QmH9EQMNavYbWpOq6lMZE5qSDsnIjE1qjefUB1+k
# 6GicWpMrX5bdkCMzzwr5lHUbkJZnhNHOMEU9ZoHQURJtfoKHld3inNYXYk7HxvrJ
# MFe1I6R5dBj8Wy+YXvKII4pB5rh0jWImIqiwkwHkp/bGcrzUZVZumLVucksTL/Ov
# +xvV6owkGHCZLWuCpyi+Bpwl/xcQq79Hh/y94+02h2hJ5Bts21zNykf462qq5wft
# HDWIRmthETqxmSqKONAP5c/EfGBMhK6joi9vwrpDLzDOs4GqE9N4VqZfJaxiqDBx
# ICn33TNPI7Ct4V/hb+AGaBCM9w7HASIiZHPZ1so1XpKwAQ1tpDrl3G4d412G3HxH
# 5vLgbzF11hj2M4Lu3RpOBhrKYL6UmcVjfv7JsDCCBY0wggR1oAMCAQICEA6bGI75
# 0C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTATBgNV
# BAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIG
# A1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAwMDAw
# MFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGln
# aUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2uexuE
# DcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNw
# wrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs0
# 6wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e
# 5TXnMcvak17cjo+A2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtV
# gkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8oU85
# tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m1O+S
# kjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y1Yxw
# LEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkliWzl
# DlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFr
# b7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOCATow
# ggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiu
# HA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQE
# AwIBhjB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2
# hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290
# Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/
# Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNK
# ei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je1M/RQ0SbQyHr
# lnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4
# oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxYoA5A
# Y8WYIsGyWfVVa88nq2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0VysGMNN
# n3O3AamfV6peKOK5lDCCBrQwggScoAMCAQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJ
# KoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IElu
# YzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQg
# VHJ1c3RlZCBSb290IEc0MB4XDTI1MDUwNzAwMDAwMFoXDTM4MDExNDIzNTk1OVow
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1
# NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALR4MdMK
# mEFyvjxGwBysddujRmh0tFEXnU2tjQ2UtZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh
# /qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWCWgzbNfiR+2fkHUiljNOqnIVD/gG3SYDE
# Ad4dg2dDGpeZGKe+42DFUF0mR/vtLa4+gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8y
# AR2CQWIM1iI5PHg62IVwxKSpO0XaF9DPfNBKS7Zazch8NF5vp7eaZ2CVNxpqumzT
# CNSOxm+SAWSuIr21Qomb+zzQWKhxKTVVgtmUPAW35xUUFREmDrMxSNlr/NsJyUXz
# dtFUUt4aS4CEeIY8y9IaaGBpPNXKFifinT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ
# 55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJ
# khU1JrPsFfxW1gaou30yZ46t4Y9F20HHfIY4/6vHespYMQmUiote8ladjS/nJ0+k
# 6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQyogxG9QEPHrPV6/7umw052AkyiLA6tQb
# Zl1KhBtTasySkuJDpsZGKdlsjg4u70EwgWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x
# 0VR4RjSpWM8o5a6D8bpfm4CLKczsG7ZrIGNTAgMBAAGjggFdMIIBWTASBgNVHRMB
# Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBTvb1NK6eQGfHrK4pBW9i/USezLTjAfBgNV
# HSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYD
# VR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwH
# ATANBgkqhkiG9w0BAQsFAAOCAgEAF877FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYga
# MH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4h
# CFATuNT+ReOPK0mCefSG+tXqGpYZ3essBS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJ
# v2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qKtntujB71WPYAgwPyWLKu6RnaID/B0ba2
# H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I+ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX
# +DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q17r0z0noDjs6+BFo+z7bKSBwZXTRNivYu
# ve3L2oiKNqetRHdqfMTCW/NmKLJ9M+MtucVGyOxiDf06VXxyKkOirv6o02OoXN4b
# FzK0vlNMsvhlqgF2puE6FndlENSmE+9JGYxOGLS/D284NHNboDGcmWXfwXRy4kbu
# 4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlHqhpB/8MluDezooIs8CVnrpHMiD2wL40m
# m53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7GELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN6
# 2JK4S1C8uw3PdBunvAZapsiI5YKdvlarEvf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ
# 9k+5t1wwggbtMIIE1aADAgECAhAIT9wzT35FTtvDD4/5khg1MA0GCSqGSIb3DQEB
# CwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8G
# A1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBT
# SEEyNTYgMjAyNSBDQTEwHhcNMjYwODA1MDAwMDAwWhcNMzcxMTA0MjM1OTU5WjBj
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMT
# MkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAy
# NiAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtnum8sn+zUr41JtM
# ZbP9OMYw+HwJDpG5xkIu/lqcfNYmMX81YmsUiHLbh9ykpeWBGKTLhYBrAN9Tdg/Q
# EzG32XcObmgIblnr0CoQ3WSAeDZ6nH6X6VkFyYkJw3QBJREwvm4UhLzSxmwPA7cF
# KRTEOMsmEEj6qJk/dqLEAL+oQYuOwE2UuiX1Vnul8YReIyWd4kgLn9gq6LNXM0Up
# lkR6jL/QHxmb6fMoGBJYbnaUI7XD6cKDpekK2SVMld4iDbzeHDtOaaxldH5IxuNu
# sQ69nd8/ZXEiB5Hbxj3RlK13cX1W4DlFXKdv/CEhM8Cj1vvlmvhNroyPdRGbbpBl
# gyf8Wdu5N6ByhFwURn0U6ozlPoxN22v+fviUhP+6DR547OZnpBMWDfei1f5sVGwi
# iW/KQTWOK97g+4RJpPzPNV4VYMAwO2jM2Aty2QYPVmOQTJm0msuXnJrSbl2gf9Jy
# lpkJlWXqk1Q4LJsxz+TELoQCZIljbgvTJgoPU2R12ydv8i1UqL/adelA0y7U9Pmm
# tbze9Xx3rtajC5SzQd1jgfwAwsa90v9YcSPdmeoyoBBA/27cCL237l5DTYYPDLQ4
# ON3OLTGWnvRb6jDrf/T75gMRfUzSLCBQfBusm9+mSWRlC/Df6S/e9Q8i13CuhzOT
# 2Jx+V/nlbXM4QoBwlUAhelwwJT0CAwEAAaOCAZUwggGRMAwGA1UdEwEB/wQCMAAw
# HQYDVR0OBBYEFBTJY4owLtRK+26U8+bjQH717M3iMB8GA1UdIwQYMBaAFO9vU0rp
# 5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggr
# BgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcwAoZRaHR0cDovL2NhY2VydHMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNI
# QTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZT
# SEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1s
# BwEwDQYJKoZIhvcNAQELBQADggIBAI3FOmEenVIK35msCYB+fShAsWvSYvLBItoN
# dAgQ2jIqrGsVsluXMJU/+mRebBc52s6lbKAvOVPXaizmKkMLLflEEKDZQx4CkS2t
# 8aHPjkXha3hYZ010htFa3dhNgmalH5vuWvh3tTCf4frTS7gPtGc4Z/xaPhQ2AB1m
# R8eEe/WbH0RWHvVIl6VwQ3+g5FKNfN2N/DWJkf13w2H+2GfqEfbd35Ww8CvoYBjL
# NIDTadcPWdgsjsiOaK/7EsKJgLjUNIVgvcaFOLLQ/GlrA+0ZHJoFUbOr5SJN8zyk
# PspXIXlpDJY/gqFUZRROeab9GVgmhbdOJcD/63RhxPahFUGbckRONqMe6DYAv6/m
# OG0pWd3cPStsdcS7buj5DyniwRY8yooMH6ptx5vpP/pZzBPBeZD2U4IsthyxB5Ja
# a8qrOkB5z160TXiM5ADMspZ0TfD9MJoq0tFpFPssKRFhWeEDYPvcUuN7U7lvcdHl
# 4ezQ3NT/7Ffs1sR1yh/LRbdZ3B3Vc6q2WmD8mDC0p9kzl2o73iVtS946IkEj7FkR
# sZGww1teYxERROC745xrtjvcw9ZyyUjHZWGRIpJeMNsPquCDf0fkyHtB+J4AiNZq
# CQk23rxh+KbpyMTNVKItJ5l92Svl20U9NbqMBOVYl1h54NEYLJq1/xHWFKPNK903
# zJZA9P2DMYIFlzCCBZMCAQEwOzAnMSUwIwYDVQQDDBxTdXJpY2F0YUNoZWNrZXIg
# Q29kZSBTaWduaW5nAhA7bF30z/iPr08MbKLtqoDfMA0GCWCGSAFlAwQCAQUAoIGE
# MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkE
# MSIEIEHXYuF+SOmvlKve0H5anYMA4gLlRUyWs8sA9U/lSh/UMA0GCSqGSIb3DQEB
# AQUABIIBgEt3ZmfRDhBD6V3/rt8m1iK6SKS17Tg+jkmMlvUk1UFYjlVKRcxXXmo1
# YIFeFOyI8+BE2bfoA+DEt2YSk2KTsIgyJCOUBlASnp2/Kq6zH3/7ybifbXT1Uva/
# xTg9lRiaIZrfwUFVHdZsZrhs+iw/Tj6jdtFmAPcwNwZ2BK0CxUBEtuupomsAcgBy
# UBnhtCuYkgiT4fQ77NZWBez00fhs2bv5nYiCP9gDvl6D8dz2ADNkl9ea+R/cKEkN
# FKw7Kfeyusoc/mdKs8dQNeGkaK+6uxPoIVe1c17z/FZjpCeKhBDYjWiioD2AH+j/
# ixmLFb4y49zBZrLUtqCkjHoWQDnu0/gCTucJRgKHzY5dhF6GSvvKnbaiHhIndpoo
# v/9ydHUgxJMPV5W40rf/ptJ+zIKXWd1Li18YNtSGn/637sKLIq9jnmrxLsRK0+Ff
# ggiuioRql+HLiMIaFeTwiLidSUPgK+Km//4kcyNjfu4lVAPGRo2OxDShs+k3Sj3a
# AOU+S1G3MaGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjExMDUxNTAyMjBaMC8G
# CSqGSIb3DQEJBDEiBCCrea96JisivOe84/X77AsvW6a5ZN5bBRZrO/1iyqu3SDAN
# BgkqhkiG9w0BAQEFAASCAgCIUTnwhBix1jnBJuxe9H6+kmcpLBFMDZ6LvZS4N34e
# rIuGASwgNobbnQNnIembVWcGza7//8d8Rajd7443AFvmCIK4ulnzw2693GvCEvjU
# k8M1nwFSvRCfRgEqzRjkQXpuTpD+CeToEc24nnxObXhIgutO+PsLWxknm3GQyqhv
# z3YckEZIioM1FHK/LYWeXvnfEhSexfBRe0iIPLxXj1sAKQLCLdUk+sIFUprrvJHw
# nuHg4vz5qrezMj6lUDIqL9aI6RQGDONCotp/qVOzjMkFk5oBYcafd1qCsW2TTVSe
# jlcd7GfxSSJ0TMGldhGenDK7l2MwiNyprMlpXnhTk9HYlIBbreOuDgD17NW1PQNp
# hQjsAUeok1EyhZoSdN/ot4/7e8i0ZcOqO6C/WJQ00TLz5yCu9Nohx3bbNSbFe4Ip
# 1WBCkXiw/yIrHr71zD9GrsWzu1WE5pEQ+UTrzRHJKMbnzsCKqzg7KHhqW7Kazi4X
# CqUiOOU4ZIUoQ6ahTWwYQLYX0HDgfqs60r+cPvSnoh/8pbzZePixU8uB1agjg1J5
# GDgN4vqFed4uVBGeoqB1JVHbmp8pz2DijcI7FhQaJsO+2Nt63Idgo0t3RVm19pPt
# ZZrh2py2CFpDt4SNi8YTFgj6i+AOCcT4hN9NUiKSkBuNu0yjfpWsiL0EM9EKjort
# +Q==
# SIG # End signature block
