# Build and test

This guide builds the helper and its local assets. It does not install a module, alter active phone configuration, clear app data or run the reset ritual. All fixtures are synthetic. Copied/decompiled Android/vendor code and external build tools are development inputs outside the repository; do not redistribute them in the ZIP.

The tested development toolchain is official Go 1.27.2, Node.js 24.18.0, Playwright 1.62.1, Git Bash and headless Google Chrome. `go.mod` declares a Go 1.25 minimum. Version 0.1.1 uses Android NDK r30 with `GOOS=android`, `GOARCH=arm64`, `CGO_ENABLED=1` and external linking for Android native DNS. The arm64 executable uses Android's system linker/libraries; it is not fully static. Android needs no Python, curl, OpenSSL, Node.js, compiler or local web server for this module.

## Prerequisites

The examples below use Windows PowerShell 7 from the repository root. Install Go and Node.js/npm and make `go`, `node` and `npm` available on PATH. Make Git Bash available as `bash`; on Windows, ensure this resolves to Git Bash rather than a WSL launcher. Browser fixtures require Google Chrome and the Playwright Node package. Packaging uses the checked-in PowerShell script. For Android builds, separately acquire and verify the official NDK r30, then set `ANDROID_NDK_HOME` to its extracted directory outside the repository.

The browser fixture can resolve Playwright from local `node_modules` or the development-only directory named by `WALLETDIAG_NODE_MODULES`. For example, prepare an external dependency directory explicitly:

```powershell
$uiToolsPath = Join-Path $env:LOCALAPPDATA 'walletdiag-development'
New-Item -ItemType Directory -Force -Path $uiToolsPath | Out-Null
& npm install --prefix $uiToolsPath --no-save --package-lock=false playwright@1.62.1
if ($LASTEXITCODE -ne 0) { throw 'Development Playwright installation failed' }
$env:WALLETDIAG_NODE_MODULES = Join-Path $uiToolsPath 'node_modules'
```

This optional preparation downloads development dependencies. It is not part of a phone installation, and those files must not enter the module ZIP. Install Google Chrome separately; the fixture defaults to its `chrome` channel. Set `WALLETDIAG_BROWSER_CHANNEL` only when intentionally using another installed, supported channel. Other PC operating systems need equivalent shell syntax and their NDK host directory; the Android target and validation boundaries remain the same.

## PC backend checks

Run from the repository root. These commands resolve tools from PATH and make no assumptions about the checkout directory. Do not copy tools into `module/`.

```powershell
$goExecutable = (Get-Command go -CommandType Application).Source
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'
& $goExecutable version
if ($LASTEXITCODE -ne 0) { throw 'Go toolchain check failed' }
& $goExecutable test ./... -count=1
if ($LASTEXITCODE -ne 0) { throw 'Go tests failed' }
& $goExecutable vet ./...
if ($LASTEXITCODE -ne 0) { throw 'Go vet failed' }
```

The suite exercises XML/private-key/X.509 validation, deliberate selection/merge and metadata handling, plan freshness, backup validation, interrupted-set recovery, concurrency/external edits, redaction, reset guards, numeric-user binding and strict CLI request parsing. Consult [validation and limits](validation.md) for recorded results; fixture tests cannot model every root writer, storage-controller failure, real signing identity or remote Google decision.

## WebUI and shell fixtures

Use these exact commands from the project directory. The browser test launches headless Chrome with an inert mock KSU bridge and an ephemeral loopback server on the PC. It never connects to a phone. The shell test substitutes inert Android-command stubs and cleans only its checked fixture directory under `build/`.

```powershell
$nodeExecutable = (Get-Command node -CommandType Application).Source
& $nodeExecutable --version
if ($LASTEXITCODE -ne 0) { throw 'Node.js toolchain check failed' }
& $nodeExecutable --check module/webroot/app.js
if ($LASTEXITCODE -ne 0) { throw 'WebUI syntax check failed' }
& $nodeExecutable --test tests/webui.test.mjs
if ($LASTEXITCODE -ne 0) { throw 'WebUI core tests failed' }
# Use the prerequisite Playwright directory or a local node_modules installation.
& $nodeExecutable tests/webui-browser.mjs
if ($LASTEXITCODE -ne 0) { throw 'Offline browser integration failed' }
$bashExecutable = (Get-Command bash -CommandType Application).Source
& $bashExecutable tests/module-shell-test.sh
if ($LASTEXITCODE -ne 0) { throw 'Offline module-shell fixtures failed' }
```

Core tests cover bounded base64url requests, response-schema gating, defensive redaction and explicit selection tuples. Browser fixtures cover the import/review/apply/verify sequence, explicit confirmation, duplicate submissions, inert untrusted HTML, unavailable bridge/API, reset preview gating, long-ID/hash wrapping at 390px and enlarged text at 320px. Screenshots under `build/` contain mock data. They are not real Wallet evidence. Module-shell fixtures check syntax, the exact standalone activity/extra contract, status/CLI fallback, module-only installer permissions and uninstall preservation. They do not prove an Android host launch.

## Android build

Use the verified official NDK r30 (revision `30.0.16248370`) outside the repository. The verified Windows archive is 727,980,788 bytes, with official SHA-1 `9bf167a1985fa7d4a036186b78f702eab9179408`; record its local SHA-256 as well when acquiring it. Source: [official NDK downloads](https://developer.android.com/ndk/downloads?hl=en). Do not package the archive, compiler, sysroot or SDK. The build commands below require an already acquired toolchain and do not download or install it.

Run after the checks pass. The quoted `CC` value preserves the compiler path and supplies its Android API/architecture target; API 28 is the chosen minimum for this build, not a statement that older Android devices were tested.

```powershell
New-Item -ItemType Directory -Force -Path '.\dist' | Out-Null
$goExecutable = (Get-Command go -CommandType Application).Source
if ([string]::IsNullOrWhiteSpace($env:ANDROID_NDK_HOME)) { throw 'Set ANDROID_NDK_HOME to the verified NDK r30 directory' }
$ndkPath = [IO.Path]::GetFullPath($env:ANDROID_NDK_HOME)
$clangExecutable = Join-Path $ndkPath 'toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe'
if (-not (Test-Path -LiteralPath $clangExecutable -PathType Leaf)) { throw 'Verified Android NDK compiler is missing' }
Get-Content -LiteralPath (Join-Path $ndkPath 'source.properties')
& $clangExecutable --version
if ($LASTEXITCODE -ne 0) { throw 'Android compiler check failed' }
$env:GOOS = 'android'
$env:GOARCH = 'arm64'
$env:CGO_ENABLED = '1'
$env:CC = '"' + $clangExecutable.Replace('\','/') + '" --target=aarch64-linux-android28'
& $goExecutable build -trimpath -buildvcs=false -ldflags '-s -w -buildid= -linkmode=external' -o '.\dist\walletdiag' './cmd/walletdiag'
if ($LASTEXITCODE -ne 0) { throw 'Android backend build failed' }
$readElfExecutable = Join-Path $ndkPath 'toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe'
& $readElfExecutable -h -l -d '.\dist\walletdiag'
if ($LASTEXITCODE -ne 0) { throw 'Android ELF inspection failed' }
Get-FileHash -LiteralPath '.\dist\walletdiag' -Algorithm SHA256
```

Inspect the final ELF for AArch64, `/system/bin/linker64`, load-segment alignment and system-library dependencies. On a new target device, native DNS and HTTPS require an actual explicit public-feed refresh; a successful PC link is not a phone transport result. Development device results are recorded separately in [validation and limits](validation.md). The helper keeps certificate verification enabled and classifies DNS/TLS failures separately. Avoid `netgo`, `GODEBUG=netdns=go` or a `PreferGo` resolver for this Android native build.

The NDK's [other build systems guide](https://developer.android.com/ndk/guides/other_build_systems) documents the `windows-x86_64` host toolchain and direct Clang target flag. [Go's cgo documentation](https://pkg.go.dev/cmd/cgo) documents enabling cgo while cross-compiling and supplying a target C compiler through `CC`.

### Historical 0.1.0 DNS limitation

The original 0.1.0 backend used `CGO_ENABLED=0`. Its local Android validation/storage tests and diagnostic calls ran successfully, but the later explicit public-feed refresh failed with the redacted `E_PUBLIC_DNS` class. That build omitted Android's native resolver; its earlier local test results do not prove HTTPS functionality.

The acquired Go 1.27.2 source explains the distinction: `src/net/conf.go` prefers the native resolver on Android; `cgo_stub.go` sets `cgoAvailable=false` when cgo is excluded; `dnsconfig_unix.go` and `dnsconfig.go` fall back to localhost DNS when conventional resolver configuration is absent. Setting `GODEBUG=netdns=cgo` cannot restore a resolver that was not compiled in. This diagnosis is specific to the observed DNS failure and does not establish a TLS/server failure or a Wallet cause.

Optional isolated Android test executables can be cross-compiled with `go test -c -o .\dist\core-android.test ./internal/core`, and similarly for `internal/keybox` and `cmd/walletdiag`, under the same Android environment. These are test artifacts, not the module backend. Keep them out of `module/`. Any device execution must use an isolated writable sandbox and synthetic fixtures, with no active-set Apply/reset/rollback. Report Android sandbox execution separately from read-only production inspection and real configuration changes. This guide does not perform or require a phone installation to build the ZIP.

## Package and verify

The script checks an AArch64 ELF header, required local assets/licenses, LF shell/property files, and rejects symlinks/reparse points. It copies only the selected backend into `module/bin/walletdiag`, sorts ZIP entries, fixes entry timestamps and writes a package SHA-256 file. A ZIP includes no decompiler, copied APK/firmware, fixture key, provider credential, or recovery state.

```powershell
& .\scripts\package.ps1 -BackendPath '.\dist\walletdiag' -OutputPath '.\dist\wallet-diagnostic-v0.1.1.zip'
Get-FileHash -LiteralPath '.\dist\wallet-diagnostic-v0.1.1.zip' -Algorithm SHA256
Get-Content -LiteralPath '.\dist\wallet-diagnostic-v0.1.1.zip.sha256'
```

For a reproducibility check with unchanged binary/assets and the same compression runtime:

```powershell
& .\scripts\package.ps1 -BackendPath '.\dist\walletdiag' -OutputPath '.\build\package-check-1.zip'
& .\scripts\package.ps1 -BackendPath '.\dist\walletdiag' -OutputPath '.\build\package-check-2.zip'
$packageHash1 = (Get-FileHash -LiteralPath '.\build\package-check-1.zip' -Algorithm SHA256).Hash
$packageHash2 = (Get-FileHash -LiteralPath '.\build\package-check-2.zip' -Algorithm SHA256).Hash
if ($packageHash1 -ne $packageHash2) { throw 'Package hashes differ' }
```

Rebuild/repackage after any final source or asset change. The delivered ZIP hash must describe the final archive, not an earlier test package. Source is MIT; the vendored KernelSU JavaScript SDK and linked Go runtime retain their Apache-2.0 and BSD notices. The native build can incorporate NDK CRT objects, compiler-rt builtins and libunwind, so unmodified NDK and LLVM aggregate notices are retained in `module/licenses/Android-NDK-r30-NOTICE.txt` and `LLVM-r30-NOTICE.txt`. These notice collections cover more components than this executable uses; they do not mean the full SDK/toolchain or every named library is shipped. Android's shared system libraries are not copied into the ZIP. KernelSU installation is supported; no custom-recovery flashing path is supplied.
