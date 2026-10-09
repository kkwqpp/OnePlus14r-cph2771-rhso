[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$BackendPath,
  [string]$OutputPath = (Join-Path $PSScriptRoot '..\dist\wallet-diagnostic-v0.1.1.zip')
)
$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskModule = Join-Path $taskRoot 'module'
$taskBackend = (Resolve-Path -LiteralPath $BackendPath).Path
$taskOutput = [IO.Path]::GetFullPath($OutputPath)
$taskElf = [IO.File]::ReadAllBytes($taskBackend)
if ($taskElf.Length -lt 64 -or $taskElf[0] -ne 0x7f -or $taskElf[1] -ne 0x45 -or $taskElf[2] -ne 0x4c -or $taskElf[3] -ne 0x46 -or $taskElf[4] -ne 2 -or $taskElf[5] -ne 1 -or $taskElf[18] -ne 0xb7 -or $taskElf[19] -ne 0) {
  throw 'Backend must be a 64-bit little-endian AArch64 ELF binary. Build the Android arm64 backend first.'
}
$taskRequired = @('module.prop','customize.sh','action.sh','uninstall.sh','skip_mount','webroot\index.html','webroot\app.js','webroot\ui-core.js','webroot\style.css','webroot\ksu.js','licenses\KernelSU-SDK-Apache-2.0.txt','licenses\Go-BSD-3-Clause.txt','licenses\WalletDiagnostic-MIT.txt','licenses\Android-NDK-r30-NOTICE.txt','licenses\LLVM-r30-NOTICE.txt')
foreach ($taskRelative in $taskRequired) {
  if (-not (Test-Path -LiteralPath (Join-Path $taskModule $taskRelative) -PathType Leaf)) { throw "Required package asset is missing: $taskRelative" }
}
New-Item -ItemType Directory -Force -Path (Join-Path $taskModule 'bin') | Out-Null
Copy-Item -LiteralPath $taskBackend -Destination (Join-Path $taskModule 'bin\walletdiag') -Force
foreach ($taskFile in Get-ChildItem -LiteralPath $taskModule -Recurse -Force) {
  if (($taskFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Package contains a symlink/reparse point: $($taskFile.Name)" }
  if (-not $taskFile.PSIsContainer -and ($taskFile.Extension -eq '.sh' -or $taskFile.Name -eq 'module.prop')) {
    if ([IO.File]::ReadAllText($taskFile.FullName).Contains("`r")) { throw "Android text asset must use LF line endings: $($taskFile.Name)" }
  }
}
New-Item -ItemType Directory -Force -Path ([IO.Path]::GetDirectoryName($taskOutput)) | Out-Null
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$taskFiles = @((Get-ChildItem -LiteralPath $taskModule -Recurse -File -Force).FullName)
[Array]::Sort($taskFiles, [StringComparer]::Ordinal)
$taskArchiveStream = [IO.File]::Open($taskOutput,[IO.FileMode]::Create,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try {
  $taskArchive = New-Object IO.Compression.ZipArchive($taskArchiveStream,[IO.Compression.ZipArchiveMode]::Create,$true)
  try {
    foreach ($taskPath in $taskFiles) {
      $taskName = $taskPath.Substring($taskModule.Length + 1).Replace('\','/')
      $taskEntry = $taskArchive.CreateEntry($taskName,[IO.Compression.CompressionLevel]::Optimal)
      $taskEntry.LastWriteTime = [DateTimeOffset]::new(2000,1,1,0,0,0,[TimeSpan]::Zero)
      $taskMode = if ($taskName -eq 'bin/walletdiag' -or $taskName.EndsWith('.sh')) { 33261 } else { 33188 }
      $taskEntry.ExternalAttributes = $taskMode -shl 16
      $taskSource = [IO.File]::OpenRead($taskPath)
      $taskTarget = $taskEntry.Open()
      try { $taskSource.CopyTo($taskTarget) } finally { $taskTarget.Dispose(); $taskSource.Dispose() }
    }
  } finally { $taskArchive.Dispose() }
} finally { $taskArchiveStream.Dispose() }
$taskHash = (Get-FileHash -LiteralPath $taskOutput -Algorithm SHA256).Hash.ToLowerInvariant()
$taskHashPath = "$taskOutput.sha256"
[IO.File]::WriteAllText($taskHashPath,"$taskHash  $([IO.Path]::GetFileName($taskOutput))`n",[Text.Encoding]::ASCII)
Write-Output "Package: $taskOutput"
Write-Output "SHA-256: $taskHash"
