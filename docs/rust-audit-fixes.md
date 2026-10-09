# Rust audit corrections

These corrections follow the read-only audit of checkpoint `6647086` and remain an audit candidate. They do not establish Android runtime compatibility, a completed release or Wallet/payment approval. The retained Go source is the comparison baseline.

| Audit finding | Candidate correction |
| --- | --- |
| F-01 stack rollback wedge | Refused restoration before a resource write preserves the previous journal state and conflict evidence. Actual write attempts retain recovery-required behavior. A separately confirmed, hash-bound keep-current resolution preserves the resource and prior journal before recording superseded. |
| F-02 incomplete reset wedge | A separately confirmed, hash-bound close-out preserves the original attempted-step ledger and records closed-incomplete. It never dispatches or repeats a clear, restores app data or claims successful manual completion. |
| F-03 RSA CRT normalization | Both PKCS1 and PKCS8 reject coefficients outside the canonical range or unequal to the calculated CRT coefficient. |
| F-04 Android TLS roots | Android starts with an empty trust pool and reads only bounded, approved Conscrypt APEX and legacy system stores. Unusable individual certificates are skipped and counted; unsafe store paths/ownership/bounds or no usable roots fail closed. Mozilla remains a non-Android build dependency only. Real Android TLS is pending. |
| F-05 weak RSA issuers | Both signature paths reject RSA issuers below 1024 bits. Supported issuer verification through the existing 8192-bit profile is retained; private import keeps its separate 2048–4096 two-prime policy. |
| F-06 XML staging | Structural inspection rejects malformed comments, references, control characters, unsupported declarations, outside-root CDATA and malformed/duplicate nested attributes. Mandatory cryptographic validation remains separate. |
| F-07 MIME parity | Shared bounded parsing accepts identical duplicate parameters, rejects conflicting duplicates, and handles case, SP/HTAB and ordinary quoted escaping. RFC2231 extended/continued parameters deliberately fail closed; full Go MIME parity is not claimed. |
| F-08 recovery concurrency | Restoration rechecks the inspected journal after taking the operation lock. Stale release quarantines the directory and verifies moved owner bytes/metadata before deletion; changed evidence remains preserved and blocked for manual inspection. Privileged races remain outside the proven guarantees. |
| F-09 result parity | Failed engine adoption after recovery returns E_RECOVERY/exit 7 with engine data. Unavailable current-user readiness returns the unverified data object and records no verification. |
| F-10 process maps | Engine identification searches raw mapping bytes and tolerates unrelated non-UTF8 mappings. |
| F-11 old documentation | Architecture/advanced guides are explicitly historical; current build and limits point to the Rust docs. |
| F-12 external writer outcome | Failed Apply identifies the evidence backup and reports restoration of the previous three-file set. File drift is distinguished from capability-only drift; external PIF/module/engine changes are not claimed as reverted. |

Additional narrow validation rejects malformed known SAN/name-constraint encodings. Complete domain, mailbox and URI semantic parity remains unverified. The packager rejects an explicitly executable GNU_STACK; this is artifact hardening, not proof of Android execution. Actual candidate assembly also exposed a newline in the inherited `skip_mount` file; the source marker is now empty as required by the packager.

The selected Rust dependency and standard-library notices are complete with [provenance](rust-licenses.md). The Android binary builds and passes ELF inspection; two actual candidate ZIPs match byte-for-byte and all 21 entry hashes, modes and fixed timestamps match their reviewed inputs. The candidate has not been installed. [Validation](validation.md) records counts and artifact hashes.

## Explicit close-out workflow

Inspect `stack --action status --json` first. The matching operation exposes `can_resolve` and `resolution_review_hash` when current resource evidence can be safely preserved. Submit that exact ID/hash and phrase:

```sh
walletdiag stack --action resolve --id OPERATION_ID --confirmation 'KEEP CURRENT STACK FILE' --review-hash RESOLUTION_REVIEW_HASH --json
```

This keeps the current file or absence, including any externally changed configuration. It does not restore the old resource. A changed journal, resource or parent invalidates review. Existing rollback capability/PIF/module/protected-file guards are retained; no policy has been loosened. A new plan is required after superseding a transaction.

Inspect `reset --action status --json`. Only clearing, attempting-clear and failed-do-not-repeat ledgers expose `can_close` and `close_review_hash`:

```sh
walletdiag reset --action close --confirmation 'CLOSE INCOMPLETE RESET WITHOUT REPEATING' --review-hash CLOSE_REVIEW_HASH --json
```

The step and preparation backup remain associated. Reviewed and awaiting-manual-reboot states cannot be closed this way. Both close-outs support matching idempotent replay and preserve evidence before the terminal marker; neither bypasses another unfinished transaction. Old Go binaries reject the new terminal states/fields and fail closed, so downgrades require explicit compatibility review. Do not delete journals to bypass these checks.

The Rust/WASM interface requires the same explicit phrases and fresh reviewed hashes, clears stale reviews, and refreshes status after closure. No close-out, reset, restore or reboot runs automatically.

## Remaining release gates

Final Android native tests and ownership/SELinux/fsync/symlink checks, real Rust DNS/TLS, installed KernelSU WASM/bridge behavior, clean-checkout reproduction and install/update preservation still need separate verification. Test count, notices and artifact records are maintained in [validation](validation.md). Mock-browser and Windows fixture results cannot satisfy those platform gates. Public feeds remain optional unsigned evidence authenticated by acquisition TLS; privileged TOCTOU and power-loss certification remain limitations.
