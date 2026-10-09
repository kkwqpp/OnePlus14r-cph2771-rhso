# Rust license notice provenance

These notices record the frozen selected dependency graphs. They do not certify runtime linkage or payment behavior.

- Dependency input: Cargo.lock, SHA-256 5f1905025bdc751b73b706f1ae51a0ddf25eaadf3525d8e89eae78a9c991f45a.
- Toolchain: Rust 1.90.0, commit 1159e78c4747b02ef996e55082b704c09b970588.
- Enumeration: locked offline Cargo trees with default features and normal/build edges for Android backend, browser WASM and Windows packager.
- Every cached manifest and included notice was compared byte-for-byte to its published .crate archive. Each archive SHA-256 matches Cargo.lock. Original workspace packages retain the separate project MIT notice.
- 156 third-party package/version identities and 298 notice files are included. Build-only edges, proc macros and packaging provenance are marked. Dev-only, disabled optional and unrelated-target packages are outside this scope.
- Full workspace metadata required uncached arbitrary 1.5.0; Android-filtered metadata required uncached bitflags 2.13.2. Both failed offline. The selected Cargo tree inventories succeed offline and include neither package, so those failures do not prevent this selected notice scope.
- asn1-rs-impl 0.2.0 omits license files. Its published .cargo_vcs_info.json identifies commit a20e5f7319c896737ad0f2557037817b91ad854f, path impl. Only the two static license texts from that exact commit were retrieved after explicit coordination authorization. No executable, dependency or provider download was made.
- The standard-library notice uses installed share/doc/rust/COPYRIGHT-library.html, SHA-256 025c0dd1236493fcd5b6386b68453852e6528722bd5f8dce5949e94d225e7a60. Its complete text and all 61 preformatted notice blocks are retained after HTML decoding and trailing-whitespace normalization, with the installed toolchain's complete MIT/Apache texts. Platform/build extras are included; this is not a target linkage inventory.
- Other upstream component notices, KernelSU SDK, Android NDK/LLVM and project licensing remain separate.
- Re-enumerate and regenerate after changing the lockfile, enabled features, release targets or toolchain. Legal review and final packaging/update checks remain separate.

## Recheck selected dependency graphs

~~~powershell
cargo tree --offline --locked -p rhso-backend --target aarch64-linux-android -e normal,build --prefix none --format '{p}|{l}|{r}'
cargo tree --offline --locked -p rhso-webui --target wasm32-unknown-unknown -e normal,build --prefix none --format '{p}|{l}|{r}'
cargo tree --offline --locked -p rhso-packager --target x86_64-pc-windows-msvc -e normal,build --prefix none --format '{p}|{l}|{r}'
~~~

For cached crates, paths below are relative to the exact published crate directory. All matching LICENSE*, COPYING*, COPYRIGHT*, NOTICE*, UNLICENSE* and AUTHORS* files were included recursively, including ring's nested licenses and regex's Unicode notice. Upstream/ entries denote the asn1-rs-impl exception.

## Exact upstream exception

- [MIT text](https://raw.githubusercontent.com/rusticata/asn1-rs/a20e5f7319c896737ad0f2557037817b91ad854f/LICENSE-MIT), SHA-256 a5c61b93b6ee1d104af9920cf020ff3c7efe818e31fe562c72261847a728f513.
- [Apache text](https://raw.githubusercontent.com/rusticata/asn1-rs/a20e5f7319c896737ad0f2557037817b91ad854f/LICENSE-APACHE), SHA-256 a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2.

## Selected package inventory

| Package/version | Cargo license declaration | Selected graphs | Included source notice files |
| --- | --- | --- | --- |
| adler2 2.0.1 | 0BSD OR MIT OR Apache-2.0 | windows-packager | LICENSE-0BSD, LICENSE-APACHE, LICENSE-MIT |
| aho-corasick 1.1.5 | Unlicense OR MIT | android-backend, wasm-webui | COPYING, LICENSE-MIT, UNLICENSE |
| asn1-rs 0.7.2 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| asn1-rs-derive 0.6.0 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| asn1-rs-impl 0.2.0 | MIT/Apache-2.0 | android-backend | upstream/LICENSE-APACHE, upstream/LICENSE-MIT |
| autocfg 1.5.1 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| base16ct 0.2.0 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| base64 0.22.1 | MIT OR Apache-2.0 | android-backend, wasm-webui, windows-packager | LICENSE-APACHE, LICENSE-MIT |
| base64ct 1.8.3 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| block-buffer 0.10.4 | MIT OR Apache-2.0 | android-backend, windows-packager | LICENSE-APACHE, LICENSE-MIT |
| bumpalo 3.20.3 | MIT OR Apache-2.0 | wasm-webui, windows-packager | LICENSE-APACHE, LICENSE-MIT |
| cc 1.6.0 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| cfg-if 1.0.5 | MIT OR Apache-2.0 | android-backend, wasm-webui, windows-packager | LICENSE-APACHE, LICENSE-MIT |
| const-oid 0.9.6 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| cpufeatures 0.2.17 | MIT OR Apache-2.0 | android-backend, windows-packager | LICENSE-APACHE, LICENSE-MIT |
| crc32fast 1.5.2 | MIT OR Apache-2.0 | windows-packager | LICENSE-APACHE, LICENSE-MIT |
| crypto-bigint 0.5.5 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| crypto-common 0.1.6 | MIT OR Apache-2.0 | android-backend, windows-packager | LICENSE-APACHE, LICENSE-MIT |
| data-encoding 2.11.1 | MIT | android-backend | LICENSE |
| der 0.7.10 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| der-parser 10.0.0 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| deranged 0.5.8 | MIT OR Apache-2.0 | android-backend | LICENSE-Apache, LICENSE-MIT |
| digest 0.10.7 | MIT OR Apache-2.0 | android-backend, windows-packager | LICENSE-APACHE, LICENSE-MIT |
| displaydoc 0.2.7 | MIT OR Apache-2.0 | android-backend, windows-packager | LICENSE-APACHE, LICENSE-MIT |
| ecdsa 0.16.9 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| elliptic-curve 0.13.8 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| equivalent 1.0.2 | Apache-2.0 OR MIT | windows-packager | LICENSE-APACHE, LICENSE-MIT |
| ff 0.13.1 | MIT/Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| find-msvc-tools 0.1.14 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| flate2 1.1.10 | MIT OR Apache-2.0 | windows-packager | LICENSE-APACHE, LICENSE-MIT |
| form_urlencoded 1.2.2 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| futures-core 0.3.34 | MIT OR Apache-2.0 | wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| futures-task 0.3.34 | MIT OR Apache-2.0 | wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| futures-util 0.3.34 | MIT OR Apache-2.0 | wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| generic-array 0.14.9 | MIT | android-backend, windows-packager | LICENSE |
| getrandom 0.2.17 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| group 0.13.0 | MIT/Apache-2.0 | android-backend | COPYRIGHT, LICENSE-APACHE, LICENSE-MIT |
| hashbrown 0.17.1 | MIT OR Apache-2.0 | windows-packager | LICENSE-APACHE, LICENSE-MIT |
| hex 0.4.3 | MIT OR Apache-2.0 | android-backend, windows-packager | LICENSE-APACHE, LICENSE-MIT |
| hkdf 0.12.4 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| hmac 0.12.1 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| httpdate 1.0.3 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| icu_collections 2.3.0 | Unicode-3.0 | android-backend | LICENSE |
| icu_locale_core 2.3.0 | Unicode-3.0 | android-backend | LICENSE |
| icu_normalizer 2.3.0 | Unicode-3.0 | android-backend | LICENSE |
| icu_normalizer_data 2.3.0 | Unicode-3.0 | android-backend | LICENSE |
| icu_properties 2.3.0 | Unicode-3.0 | android-backend | LICENSE |
| icu_properties_data 2.3.0 | Unicode-3.0 | android-backend | LICENSE |
| icu_provider 2.3.1 | Unicode-3.0 | android-backend | LICENSE |
| idna 1.1.0 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| idna_adapter 1.2.2 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| indexmap 2.14.2 | Apache-2.0 OR MIT | windows-packager | LICENSE-APACHE, LICENSE-MIT |
| itoa 1.0.18 | MIT OR Apache-2.0 | android-backend, wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| js-sys 0.3.85 | MIT OR Apache-2.0 | wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| lazy_static 1.5.1 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| libc 0.2.190 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| libm 0.2.16 | MIT | android-backend | LICENSE.txt |
| litemap 0.8.3 | Unicode-3.0 | android-backend | LICENSE |
| log 0.4.34 | MIT OR Apache-2.0 | windows-packager | LICENSE-APACHE, LICENSE-MIT |
| memchr 2.8.3 | Unlicense OR MIT | android-backend, wasm-webui, windows-packager | COPYING, LICENSE-MIT, UNLICENSE |
| mime 0.3.17 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| minimal-lexical 0.2.1 | MIT/Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT, LICENSE.md |
| miniz_oxide 0.9.1 | MIT OR Zlib OR Apache-2.0 | windows-packager | LICENSE, LICENSE-APACHE.md, LICENSE-MIT.md, LICENSE-ZLIB.md |
| nom 7.1.3 | MIT | android-backend | LICENSE |
| num-bigint 0.4.8 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| num-bigint-dig 0.8.6 | MIT/Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| num-conv 0.2.2 | MIT OR Apache-2.0 | android-backend | LICENSE-Apache, LICENSE-MIT |
| num-integer 0.1.47 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| num-iter 0.1.46 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| num-traits 0.2.19 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| oid-registry 0.8.1 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| once_cell 1.21.4 | MIT OR Apache-2.0 | android-backend, wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| p256 0.13.2 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| p384 0.13.1 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| p521 0.13.3 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| pem 3.0.6 | MIT | android-backend | LICENSE.md |
| pem-rfc7468 0.7.0 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| percent-encoding 2.3.2 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| pin-project-lite 0.2.17 | Apache-2.0 OR MIT | wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| pkcs1 0.7.5 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| pkcs8 0.10.2 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| potential_utf 0.1.6 | Unicode-3.0 | android-backend | LICENSE |
| powerfmt 0.2.1 | MIT OR Apache-2.0 | android-backend | LICENSE-Apache, LICENSE-MIT |
| ppv-lite86 0.2.21 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| primeorder 0.13.6 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| proc-macro2 1.0.107 | MIT OR Apache-2.0 | android-backend, wasm-webui, windows-packager | LICENSE-APACHE, LICENSE-MIT |
| quick-xml 0.38.4 | MIT | android-backend | LICENSE-MIT.md |
| quote 1.0.47 | MIT OR Apache-2.0 | android-backend, wasm-webui, windows-packager | LICENSE-APACHE, LICENSE-MIT |
| rand 0.8.8 | MIT OR Apache-2.0 | android-backend | COPYRIGHT, LICENSE-APACHE, LICENSE-MIT |
| rand_chacha 0.3.1 | MIT OR Apache-2.0 | android-backend | COPYRIGHT, LICENSE-APACHE, LICENSE-MIT |
| rand_core 0.6.4 | MIT OR Apache-2.0 | android-backend | COPYRIGHT, LICENSE-APACHE, LICENSE-MIT |
| regex 1.13.1 | MIT OR Apache-2.0 | android-backend, wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| regex-automata 0.4.18 | MIT OR Apache-2.0 | android-backend, wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| regex-syntax 0.8.11 | MIT OR Apache-2.0 | android-backend, wasm-webui | LICENSE-APACHE, LICENSE-MIT, src/unicode_tables/LICENSE-UNICODE |
| rfc6979 0.4.0 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| ring 0.17.14 | Apache-2.0 AND ISC | android-backend | LICENSE, LICENSE-BoringSSL, LICENSE-other-bits, src/polyfill/once_cell/LICENSE-APACHE, src/polyfill/once_cell/LICENSE-MIT, third_party/fiat/LICENSE |
| rsa 0.9.10 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| rusticata-macros 4.1.0 | MIT/Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| rustls 0.23.45 | Apache-2.0 OR ISC OR MIT | android-backend | LICENSE-APACHE, LICENSE-ISC, LICENSE-MIT |
| rustls-pemfile 2.2.0 | Apache-2.0 OR ISC OR MIT | android-backend | LICENSE, LICENSE-APACHE, LICENSE-ISC, LICENSE-MIT |
| rustls-pki-types 1.15.1 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| rustls-webpki 0.103.15 | ISC | android-backend | LICENSE |
| rustversion 1.0.23 | MIT OR Apache-2.0 | wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| sec1 0.7.3 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| serde 1.0.229 | MIT OR Apache-2.0 | android-backend, wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| serde_core 1.0.229 | MIT OR Apache-2.0 | android-backend, wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| serde_derive 1.0.229 | MIT OR Apache-2.0 | android-backend, wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| serde_json 1.0.151 | MIT OR Apache-2.0 | android-backend, wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| sha1 0.10.7 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| sha2 0.10.9 | MIT OR Apache-2.0 | android-backend, windows-packager | LICENSE-APACHE, LICENSE-MIT |
| shlex 2.0.1 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| signature 2.2.0 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| simd-adler32 0.3.10 | MIT | windows-packager | LICENSE.md |
| slab 0.4.12 | MIT | wasm-webui | LICENSE |
| smallvec 1.16.2 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| spin 0.9.9 | MIT | android-backend | LICENSE |
| spki 0.7.3 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| stable_deref_trait 1.2.1 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| subtle 2.6.1 | BSD-3-Clause | android-backend | LICENSE |
| syn 2.0.119 | MIT OR Apache-2.0 | android-backend, wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| syn 3.0.6 | MIT OR Apache-2.0 | android-backend, wasm-webui, windows-packager | LICENSE-APACHE, LICENSE-MIT |
| synstructure 0.13.2 | MIT | android-backend | LICENSE |
| synstructure 0.14.0 | MIT | android-backend | LICENSE |
| thiserror 2.0.21 | MIT OR Apache-2.0 | android-backend, windows-packager | LICENSE-APACHE, LICENSE-MIT |
| thiserror-impl 2.0.21 | MIT OR Apache-2.0 | android-backend, windows-packager | LICENSE-APACHE, LICENSE-MIT |
| time 0.3.55 | MIT OR Apache-2.0 | android-backend | LICENSE-Apache, LICENSE-MIT |
| time-core 0.1.9 | MIT OR Apache-2.0 | android-backend | LICENSE-Apache, LICENSE-MIT |
| time-macros 0.2.32 | MIT OR Apache-2.0 | android-backend | LICENSE-Apache, LICENSE-MIT |
| tinystr 0.8.4 | Unicode-3.0 | android-backend | LICENSE |
| typenum 1.20.1 | MIT OR Apache-2.0 | android-backend, windows-packager | LICENSE, LICENSE-APACHE, LICENSE-MIT |
| unicode-ident 1.0.26 | (MIT OR Apache-2.0) AND Unicode-3.0 | android-backend, wasm-webui, windows-packager | LICENSE-APACHE, LICENSE-MIT, LICENSE-UNICODE |
| untrusted 0.9.0 | ISC | android-backend | LICENSE.txt |
| url 2.5.8 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| utf8_iter 1.0.4 | Apache-2.0 OR MIT | android-backend | COPYRIGHT, LICENSE-APACHE, LICENSE-MIT |
| version_check 0.9.5 | MIT/Apache-2.0 | android-backend, windows-packager | LICENSE-APACHE, LICENSE-MIT |
| wasm-bindgen 0.2.108 | MIT OR Apache-2.0 | wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| wasm-bindgen-futures 0.4.58 | MIT OR Apache-2.0 | wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| wasm-bindgen-macro 0.2.108 | MIT OR Apache-2.0 | wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| wasm-bindgen-macro-support 0.2.108 | MIT OR Apache-2.0 | wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| wasm-bindgen-shared 0.2.108 | MIT OR Apache-2.0 | wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| web-sys 0.3.85 | MIT OR Apache-2.0 | wasm-webui | LICENSE-APACHE, LICENSE-MIT |
| webpki-roots 1.0.9 | CDLA-Permissive-2.0 | android-backend | LICENSE |
| writeable 0.6.4 | Unicode-3.0 | android-backend | LICENSE |
| x509-parser 0.18.1 | MIT OR Apache-2.0 | android-backend | LICENSE-APACHE, LICENSE-MIT |
| yoke 0.8.3 | Unicode-3.0 | android-backend | LICENSE |
| yoke-derive 0.8.4 | Unicode-3.0 | android-backend | LICENSE |
| zerocopy 0.8.62 | BSD-2-Clause OR Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-BSD, LICENSE-MIT |
| zerofrom 0.1.8 | Unicode-3.0 | android-backend | LICENSE |
| zerofrom-derive 0.1.8 | Unicode-3.0 | android-backend | LICENSE |
| zeroize 1.9.1 | Apache-2.0 OR MIT | android-backend | LICENSE-APACHE, LICENSE-MIT |
| zerotrie 0.2.5 | Unicode-3.0 | android-backend | LICENSE |
| zerovec 0.11.8 | Unicode-3.0 | android-backend | LICENSE |
| zerovec-derive 0.11.6 | Unicode-3.0 | android-backend | LICENSE |
| zip 2.4.2 | MIT | windows-packager | LICENSE |
| zmij 1.0.23 | MIT | android-backend, wasm-webui | LICENSE-MIT |
| zopfli 0.8.3 | Apache-2.0 | windows-packager | COPYING |
