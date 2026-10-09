[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$BackendPath,
  [string]$OutputPath = (Join-Path $PSScriptRoot '..\dist\rhso-v0.3.0.zip'),
  [string]$ModulePath = (Join-Path $PSScriptRoot '..\module')
)
$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskBackend = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BackendPath)
$taskOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$taskModule = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ModulePath)
& cargo run --locked --manifest-path (Join-Path $taskRoot 'Cargo.toml') -p rhso-packager -- --backend $taskBackend --output $taskOutput --module $taskModule
if ($LASTEXITCODE -ne 0) { throw 'Rust release packaging failed' }
