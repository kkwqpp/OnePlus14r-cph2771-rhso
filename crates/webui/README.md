# Rust browser interface

`src/core.rs` contains native-testable request, redaction, selection and freshness policy. `src/browser.rs` owns the DOM, application state, confirmations and asynchronous workflows. HTML and CSS remain declarative. The KernelSU SDK and generated wasm-bindgen JavaScript are interoperability glue.

Build with Rust 1.90 and `wasm32-unknown-unknown`, then run the exact matching `wasm-bindgen-cli 0.2.108`:

```text
cargo test -p rhso-webui
cargo build --release -p rhso-webui --target wasm32-unknown-unknown
wasm-bindgen --target web --out-name rhso_webui --out-dir module/webroot target/wasm32-unknown-unknown/release/rhso_webui.wasm
```

The Rust packager emits `rhso_webui_bytes.js` with one `wasmBase64` export containing the generated WASM bytes. The loader supplies explicit bytes to initialization: Android file-origin WebViews do not need a WASM fetch, and the page keeps `connect-src 'none'`. CSP permits only self scripts plus WebAssembly compilation.

`tests/parity.mjs` checks the prior core contract through WASM. `tests/browser.mjs` exercises all prior workflows in Chrome through a mocked root bridge, without connecting to a phone. It uses Playwright, with optional `WALLETDIAG_NODE_MODULES` pointing to its installed module directory and `WALLETDIAG_BROWSER_CHANNEL` selecting a installed browser channel. Screenshots are test artifacts in the ignored build directory.

```text
node --test crates/webui/tests/parity.mjs
node crates/webui/tests/browser.mjs
```

These checks establish mock-browser behavior, not Android bridge behavior, component adoption or payment acceptance.
