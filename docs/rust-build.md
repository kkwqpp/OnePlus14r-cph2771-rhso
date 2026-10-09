# Rust build and package: RHSO 0.3.0

This describes an unfinished migration candidate after the critical audit of checkpoint `6647086` and local [audit corrections](rust-audit-fixes.md). Compile/fixture checks and Android ELF inspection are partial evidence. Full parity, native Android execution, installed host compatibility and install/update preservation remain pending. Go source is retained as the comparison baseline. These commands describe the candidate build route; they do not assert that a complete reviewed Rust release has been delivered.

The 0.3.0 build selects the Rust backend, keybox library, browser controller and release packager. HTML/CSS stay declarative. The small JavaScript loader, wasm-bindgen glue and unmodified KernelSU SDK connect Rust to the Android WebUI host. Android lifecycle shell files and the PowerShell packaging launcher remain minimal adapters. Third-party HMA, BreZygisk, TrickyStore and PIF engines are separate installed components; this build does not rewrite or distribute them.

Building does not install a module, touch phone configuration, fetch a keybox, clear app data or reboot a device. The packager does not install tools or perform network requests. Cargo can access its registry while preparing/building dependencies; use the committed lockfile and an already populated cache for offline builds. The historical Go build guide describes earlier releases and is not the 0.3.0 build route.

## Prerequisites

Use the repository's `rust-toolchain.toml`: Rust 1.90.0, `rustfmt`, `clippy`, `aarch64-linux-android` and `wasm32-unknown-unknown`. The browser crate pins wasm-bindgen 0.2.108, js-sys/web-sys 0.3.85 and wasm-bindgen-futures 0.4.58; the installed `wasm-bindgen-cli` must be exactly 0.2.108. Prepare these tools deliberately before building. The matching CLI can be installed separately with `cargo install --locked wasm-bindgen-cli --version 0.2.108`; no build or packaging command installs it automatically. See the [official wasm-bindgen CLI guide](https://wasm-bindgen.github.io/wasm-bindgen/reference/cli.html).

Use Android NDK r30, revision `30.0.16248370`, outside the repository. Set `ANDROID_NDK_HOME` to that local directory. Android API 28 is the selected minimum for this arm64 build; it does not assert that all API 28 devices were tested. Rust's [Android target documentation](https://doc.rust-lang.org/rustc/platform-support/android.html) and the NDK's [other build systems guide](https://developer.android.com/ndk/guides/other_build_systems) describe the supported target and direct Clang invocation. Do not include an SDK, NDK, compiler, copied APK, decompiled firmware or sysroot in `module/`.

On Windows, run native Cargo commands from a Visual Studio Developer PowerShell configured for x64 MSVC, with a working Windows SDK/UCRT. A linker executable alone is insufficient: SDK import libraries and headers must also be available. The tested native setup uses Windows SDK `10.0.28000.0`; an equivalent supported local installation must be checked independently. Microsoft's [command-line build guide](https://learn.microsoft.com/en-us/cpp/build/building-on-the-command-line?view=msvc-170) describes developer-shell initialization. No PC-specific setup helper is required by the source tree.

Optional browser checks need Node.js, Playwright and an installed Chrome channel. The recorded UI checks used Node.js 24.18.0 and headless Chrome. Set `WALLETDIAG_NODE_MODULES` to an existing directory containing `playwright` if normal Node resolution cannot find it. `WALLETDIAG_BROWSER_CHANNEL` defaults to `chrome`. Shell fixture checks need Bash. These tools run on the PC, not Android.

## Publication path privacy

Stripping symbols does not remove source locations from panic messages. Before publishing native/WASM artifacts, remap the source root to `/rhso`, Cargo home to `/cargo` and the remaining local home prefix to `/host`, then scan the final artifacts for local owner paths. The audit candidate publication build uses these mappings; the earlier phone Downloads copy predates them. Paths and artifact hashes can differ without a behavior change.

For Windows PowerShell, construct individual arguments so spaces in source paths remain part of one argument. Set this encoded flag list only around the relevant target build, restoring the previous environment afterward:

```powershell
$taskSource = (Get-Location).Path
$taskCargo = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
$taskRemaps = @()
foreach ($pair in @(@($taskSource, '/rhso'), @($taskCargo, '/cargo'), @($env:USERPROFILE, '/host'))) {
    $taskRemaps += "--remap-path-prefix=$($pair[0])=$($pair[1])"
    $taskRemaps += "--remap-path-prefix=$($pair[0].Replace('\', '/'))=$($pair[1])"
}
$taskPreviousFlags = $env:CARGO_ENCODED_RUSTFLAGS
try {
    $env:CARGO_ENCODED_RUSTFLAGS = $taskRemaps -join [char]31
    cargo build --offline --locked --release -p rhso-webui --target wasm32-unknown-unknown
    if ($LASTEXITCODE -ne 0) { throw 'Remapped WASM build failed' }
} finally {
    $env:CARGO_ENCODED_RUSTFLAGS = $taskPreviousFlags
}
```

For the Android build, append `'-C', 'link-arg=--target=aarch64-linux-android28', '-C', 'link-arg=-Wl,-z,max-page-size=16384', '-C', 'link-arg=-Wl,-z,common-page-size=16384'` to the remap argument array before joining it. The target flag is for the direct `clang.exe` example below; the API-28 driver already selects that target. Set matching Clang `-ffile-prefix-map=SOURCE=/rhso`, `-ffile-prefix-map=CARGO_HOME=/cargo` and `-ffile-prefix-map=LOCAL_HOME=/host` arguments for incorporated C sources, with appropriate argument quoting. Encoded flags override other Cargo rustflags, so retain the Android target and both page-size settings. Linux/macOS equivalents require their corresponding source/cache/home prefixes and separate verification. Re-run ELF, WASM contracts, browser and package checks on the final remapped artifacts.

## Native checks

Run from the repository root after preparing the host environment:

```powershell
rustc --version
cargo --version
cargo test --locked --workspace
if ($LASTEXITCODE -ne 0) { throw 'Rust workspace tests failed' }
cargo clippy --locked --workspace --all-targets -- -D warnings
if ($LASTEXITCODE -ne 0) { throw 'Rust lint checks failed' }
cargo fmt --all -- --check
if ($LASTEXITCODE -ne 0) { throw 'Rust format check failed' }
```

Fixture results do not prove real signing identity, trust, runtime adoption, payment acceptance or every possible storage failure. Consult [Rust validation](rust-validation.md) for the recorded matrix and outstanding live checks.

## Browser WASM

Build and generate the exact matching local assets:

```powershell
cargo build --locked --release -p rhso-webui --target wasm32-unknown-unknown
if ($LASTEXITCODE -ne 0) { throw 'Rust WebUI build failed' }
wasm-bindgen --version
wasm-bindgen --target web --out-name rhso_webui --out-dir module/webroot target/wasm32-unknown-unknown/release/rhso_webui.wasm
if ($LASTEXITCODE -ne 0) { throw 'WASM binding generation failed' }
cargo run --locked -p rhso-packager --bin rhso-embed-wasm -- --input module/webroot/rhso_webui_bg.wasm --output module/webroot/rhso_webui_bytes.js
if ($LASTEXITCODE -ne 0) { throw 'WASM byte asset generation failed' }
node --test crates/webui/tests/parity.mjs
if ($LASTEXITCODE -ne 0) { throw 'WASM core parity checks failed' }
node crates/webui/tests/browser.mjs
if ($LASTEXITCODE -ne 0) { throw 'Mocked browser workflows failed' }
bash tests/module-shell-test.sh
if ($LASTEXITCODE -ne 0) { throw 'Module lifecycle fixtures failed' }
```

The Rust embedding helper and ZIP packager share the byte generator. The browser supplies explicit WASM bytes, avoiding a `.wasm` fetch from Android file origins. CSP permits self scripts and WebAssembly compilation while retaining `connect-src 'none'`. Only the backend performs separately requested HTTPS operations. Browser tests use an inert root bridge and loopback test server; screenshots contain mock evidence. They do not connect to a phone.

## Android arm64 backend

The repository includes 16KiB linker settings. The following Windows example uses portable environment variables and explicitly retains these flags when overriding target compiler settings:

```powershell
if (-not $env:ANDROID_NDK_HOME) { throw 'Set ANDROID_NDK_HOME to the verified local NDK r30 directory' }
$ndkTools = Join-Path $env:ANDROID_NDK_HOME 'toolchains/llvm/prebuilt/windows-x86_64/bin'
$clang = Join-Path $ndkTools 'clang.exe'
if (-not (Test-Path -LiteralPath $clang -PathType Leaf)) { throw 'Android Clang is unavailable' }
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = $clang
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS = '-C link-arg=--target=aarch64-linux-android28 -C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384'
$env:CC_aarch64_linux_android = $clang
$env:CFLAGS_aarch64_linux_android = '--target=aarch64-linux-android28'
$env:AR_aarch64_linux_android = Join-Path $ndkTools 'llvm-ar.exe'
cargo build --locked --release -p rhso-backend --target aarch64-linux-android
if ($LASTEXITCODE -ne 0) { throw 'Android Rust backend build failed' }
New-Item -ItemType Directory -Force -Path dist | Out-Null
Copy-Item -LiteralPath target/aarch64-linux-android/release/walletdiag -Destination dist/walletdiag
& (Join-Path $ndkTools 'llvm-readelf.exe') -h -l -d dist/walletdiag
if ($LASTEXITCODE -ne 0) { throw 'Android ELF inspection failed' }
```

For Linux or macOS, use the corresponding NDK host directory and its `aarch64-linux-android28-clang` driver; configure `CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER`, `CC_aarch64_linux_android` and `AR_aarch64_linux_android` accordingly. Preserve both 16KiB linker flags if overriding the repository configuration. Those host variants are portability guidance, not recorded test results.

The executable must be ELF64 little-endian AArch64 PIE with `/system/bin/linker64`, an executable entry, the PIE dynamic flag, and every load segment aligned/congruent at 16KiB or more. Android's [16KiB page-size guidance](https://developer.android.com/guide/practices/page-sizes) explains why each load segment matters. Android shared system libraries are not copied into the ZIP. Native DNS and verified HTTPS need a separate real-device test; a PC build alone does not establish transport success.

## Deterministic release assembly

After source/build review, generate the Rust dependency notice files from the frozen dependency set. The checked-in collection and [provenance inventory](rust-licenses.md) cover the current selected graphs and toolchain; regenerate after input changes. Required notices are the project's MIT license, KernelSU SDK Apache-2.0 license, NDK/LLVM aggregate notices, `NOTICE.txt`, `Rust-THIRD-PARTY-NOTICES.txt` and `Rust-STD-MIT-APACHE-2.0.txt`. The packager refuses missing notices. Historical Go-runtime notices are omitted from the Rust ZIP. Notice collections do not assert that every upstream component named in them is linked into the executable. `skip_mount` must be a zero-byte marker.

```powershell
cargo run --locked -p rhso-packager -- --backend dist/walletdiag --output dist/rhso-v0.3.0.zip --module module
if ($LASTEXITCODE -ne 0) { throw 'Rust packaging failed' }
Get-FileHash -LiteralPath dist/rhso-v0.3.0.zip -Algorithm SHA256
Get-Content -LiteralPath dist/rhso-v0.3.0.zip.sha256
```

`scripts/package.ps1 -BackendPath dist/walletdiag -OutputPath dist/rhso-v0.3.0.zip` is only a launcher for the same Rust command. It does not contain archive logic. The packager takes `--backend PATH --output PATH [--module PATH]`; its default module directory is `./module`. It accepts only bounded regular files, refuses symlinks/reparse points and unknown module entries, verifies Android ELF layout, checks LF shell/property files and module identity/version, and packages a fixed asset allowlist. Generated TypeScript declarations, stale source byte assets and source `bin/walletdiag` are excluded. The requested backend and newly derived WASM byte asset enter the archive directly; module source files are not altered during release assembly.

ZIP entries have fixed ordinal ordering, timestamp `2000-01-01 00:00:00`, file modes 0755 for lifecycle scripts/backend and 0644 for other assets, and fixed compression settings. With unchanged input bytes and the same locked packager, two archives must match:

```powershell
cargo run --locked -p rhso-packager -- --backend dist/walletdiag --output build/repro-1.zip
cargo run --locked -p rhso-packager -- --backend dist/walletdiag --output build/repro-2.zip
$firstHash = (Get-FileHash -LiteralPath build/repro-1.zip -Algorithm SHA256).Hash
$secondHash = (Get-FileHash -LiteralPath build/repro-2.zip -Algorithm SHA256).Hash
if ($firstHash -ne $secondHash) { throw 'Archive bytes differ' }
```

This guarantees archive assembly from fixed inputs; it does not claim that changing the compiler, toolchain or source location always reproduces the same executable bytes. Rebuild, rerun the applicable checks and repackage after a final source change. The published checksum must refer to that final ZIP. No secret input, recovery state, credential, copied APK or decompiler belongs in a release.
