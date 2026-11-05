# Builds a clean distribution package dist\SuricataChecker-<version>.zip (+ .sha256) from the built and signed files:
# app, README, configuration, docs, assets and the public certificate.
# Local data is left out on purpose: suricataChecker.settings.xml (settings of the computers), marks.json (false
# positive marks and the knowledge base of this computer), docs\Code-Review-*.md (internal), src\ and dist\.
# Run after src\build.cmd:  powershell -ExecutionPolicy Bypass -File src\make_dist.ps1
param([string]$OutDir)
$ErrorActionPreference = 'Stop'
$app = 'SuricataChecker'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $root 'dist' }

# version from the project; the exe in the application folder must be this build (not an older copy)
$m = Select-String -LiteralPath (Join-Path $PSScriptRoot "$app.csproj") -Pattern '<Version>([\d.]+)</Version>' | Select-Object -First 1
if (-not $m) { throw "Version not found in src\$app.csproj" }
$version = $m.Matches[0].Groups[1].Value
$exeName = "$app-$version.exe"   # the exe carries the version in its name (build.cmd)
$exe = Join-Path $root $exeName
if (-not (Test-Path -LiteralPath $exe)) { throw "$exeName not found in the application folder - run src\build.cmd first" }
$exeVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($exe).ProductVersion
if ($exeVersion -notlike "$version*") { throw "$exeName is $exeVersion, the project is $version - run src\build.cmd first" }
$newest = Get-ChildItem -LiteralPath $PSScriptRoot -Filter *.cs | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ((Get-Item -LiteralPath $exe).LastWriteTime -lt $newest.LastWriteTime) {
    throw "$exeName is older than src\$($newest.Name) - close the application and run src\build.cmd" }

# the install script must parse (a syntax error = the script does not run at all, also not from the setup window)
$ps1 = Join-Path $root 'config\Install-SuricataConfig.ps1'
$errs = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($ps1, [ref]$null, [ref]$errs)
if ($errs) { throw "Syntax errors in config\Install-SuricataConfig.ps1:`n" + (($errs | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join "`n") }

# signed with the certificate shipped in cert\ (UnknownError = valid signature, certificate not imported on this PC)
$cer = New-Object Security.Cryptography.X509Certificates.X509Certificate2 (Join-Path $root "cert\$app.cer")
foreach ($f in $exeName, 'config\Install-SuricataConfig.ps1') {
    $sig = Get-AuthenticodeSignature -LiteralPath (Join-Path $root $f)
    if ("$($sig.Status)" -notin 'Valid', 'UnknownError' -or -not $sig.SignerCertificate -or $sig.SignerCertificate.Thumbprint -ne $cer.Thumbprint) {
        throw "$f is not signed with cert\$app.cer ($($sig.Status)) - run src\build.cmd first" }
}

$name = "$app-$version"
$stage = Join-Path $OutDir $name
$zip = Join-Path $OutDir "$name.zip"
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
foreach ($i in $exeName, "$exeName.config", 'README.md', 'LICENSE', 'config', 'docs', 'assets', 'cert') {
    Copy-Item -LiteralPath (Join-Path $root $i) -Destination $stage -Recurse
}
Get-ChildItem -LiteralPath (Join-Path $stage 'docs') -Filter 'Code-Review-*' | Remove-Item -Force

# nothing of this computer may get into the package
$bad = Get-ChildItem -LiteralPath $stage -Recurse -File |
    Where-Object { $_.Name -match '\.settings\.xml$|^marks\.json|\.pfx$|\.p12$|\.log$|\.tmp$|unreadable' }
if ($bad) { throw "Local data in the package: $($bad.Name -join ', ')" }

# Entry names with "/" (ZipFile.CreateFromDirectory in .NET Framework writes "\", which other unzip tools misread)
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::Open($zip, [IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($file in Get-ChildItem -LiteralPath $stage -Recurse -File) {
        $entry = $name + '/' + $file.FullName.Substring($stage.Length + 1).Replace('\', '/')
        [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file.FullName, $entry, [IO.Compression.CompressionLevel]::Optimal)
    }
}
finally { $archive.Dispose() }
$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
[IO.File]::WriteAllText("$zip.sha256", "$hash  $name.zip`r`n", (New-Object Text.UTF8Encoding($false)))
Remove-Item -LiteralPath $stage -Recurse -Force

"Package: $zip"
"SHA-256: $hash"
