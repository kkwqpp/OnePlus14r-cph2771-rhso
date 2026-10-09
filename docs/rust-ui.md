# RHSO Rust WebUI guide

RHSO opens on **Overview**. Use **Check phone** to collect a read-only report, then read **Needs attention** and **Next step**. **Current setup and file checks** expands the technical evidence when needed. Opening a page or explanation does not apply changes.

The current UI is an audit candidate. PC browser checks use an inert root bridge; the installed Android WebUI/WASM host still needs verification. See [validation](rust-validation.md).

| Page | Purpose |
| --- | --- |
| Overview | Check the phone and follow the suggested next step. |
| Keyboxes | Stage authorized files, validate them, choose signing keys, review a plan, then explicitly apply it. |
| Root settings | Review the supported HMA and BreZygisk settings. Advanced recovery controls stay collapsed. |
| Phone checks | Read diagnostics and separate findings from hypotheses. |
| Backups | Inspect prior changes. Open restoration controls only when intending to restore. |
| Advanced | Optional public-feed checks, private source configuration, recovery and reset tools. |

A keybox is a private file containing a signing key and its certificate chain. ECDSA and RSA are signing-key types. **Input 1**, **Input 2** and similar labels identify staged choices without showing private storage IDs. A replacement contains only the signing keys deliberately selected; omitting a type removes it from that replacement. A repair-only plan keeps the current keybox.

Optional target and patch repairs are separate choices under a collapsed panel. Preview the resulting files and warnings before confirming Apply. The helper checks whether the reviewed inputs, phone user or relevant configuration changed; stale reviews require a fresh plan. Confirmation phrases, backups and recovery protections remain in force.

HMA means Hide My Applist, an external app-hiding component. BreZygisk is the external Zygisk implementation used by the supported configuration. RHSO explains these terms in the relevant pages and exposes only the reviewed, compatible settings. Saving a configuration does not prove that either component has activated it; follow its stated manual activation instructions.

Private HTTPS source configuration and fetching stay under Advanced. Fetching only stages an input. **Validate**, key selection, Plan and Apply remain separate steps. Endpoint credentials and provider bodies are excluded from rendered results.

Results distinguish **Files saved**, **Engine using this configuration** and Wallet evidence. A successful local check or file write does not prove Google/issuer approval. Retry Wallet setup privately and record readiness or an actual payment only after observing it yourself.

Restoration and interrupted-operation recovery require deliberate confirmation. Keeping a current stack file and closing an incomplete reset preserve their evidence; neither repeats an app clear or claims a successful reset. The reset preview displays the numeric Android user, planned steps and consequences before confirmation. App-data clearing cannot be undone by restoring configuration backups. Reboot and the reviewed PIF action remain manual.

The charcoal interface supports narrow screens, visible keyboard focus and enlarged text. Advanced panels begin closed; action results remain available after a panel closes. A missing root bridge or malformed WASM disables the unsupported workflow and displays the CLI fallback.
