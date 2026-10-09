# Portable build entry point

This is an unfinished Rust migration after the critical audit and its [local corrections](rust-audit-fixes.md). Go source remains retained; full parity, Android runtime/host checks, clean-checkout reproduction and install/update preservation are pending. Compile, ELF and fixture checks do not establish a completed release.

The current RHSO 0.3.0 build uses the Rust workspace. Follow [Rust build](rust-build.md) for native prerequisites, Android NDK/API 28 configuration, the pinned wasm-bindgen toolchain, mock-browser tests and deterministic release assembly. All project-owned backend/keybox policy, browser workflows and package generation run in Rust. Minimal KernelSU lifecycle scripts, a browser loader, generated interoperability glue and the vendored SDK remain adapters.

Portable source paths are `crates/backend/`, `crates/keybox/`, `crates/webui/`, `crates/packager/` and `module/`. Toolchains stay outside the repository. Set `ANDROID_NDK_HOME` to the verified local NDK; use a working x64 MSVC/Windows SDK developer shell for Windows host tests. No PC-specific absolute paths or setup script are required. The packager never installs tools or performs network requests.

Current checks and pending final release/phone gates are in [validation](validation.md) and the [Rust subsystem matrix](rust-validation.md). The [component map](rust-component-map.md) explains why external engines, OS/kernel code, obfuscated programs and hardware/server behavior remain separate from this rewrite. Decompilation is not equivalent original source or a Rust translation.

## Historical Go route

The earlier [Go build guide](build.md) and the historical section of [validation](validation.md) describe releases through 0.2.0. Their command lines and results are preserved for historical reconstruction; they are not the current implementation/build instructions. Historical Android DNS, validation and packaging evidence does not establish the Rust candidate's runtime behavior or its final ZIP identity.

Tap-to-Pay remains unproved. A completed build, passing fixture suite or language migration does not establish Wallet approval.
