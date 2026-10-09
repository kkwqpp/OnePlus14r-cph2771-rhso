package core

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"walletdiagnostic/internal/keybox"
)

const fingerprint = "google/frankel_beta/frankel:CANARY/ZP11.260918.007/16484274:user/release-keys"

var patchDateRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

type cappedOutput struct {
	b   bytes.Buffer
	max int
}

func (c *cappedOutput) Write(b []byte) (int, error) {
	n := len(b)
	if c.b.Len()+n > c.max {
		return 0, fail("E_LIMIT", "Diagnostic command exceeded its output bound.")
	}
	return c.b.Write(b)
}
func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out := &cappedOutput{max: 2 << 20}
	cmd.Stdout = out
	cmd.Stderr = &cappedOutput{max: 64 << 10}
	e := cmd.Run()
	return out.b.String(), e
}
func (a *App) pif() (map[string]string, error) {
	b, e := bounded(filepath.Join(a.Modules, "playintegrityfix", "custom.pif.prop"), 64<<10)
	if e != nil {
		return nil, e
	}
	allowed := map[string]bool{"FINGERPRINT": true, "SECURITY_PATCH": true, "spoofBuild": true, "spoofProps": true, "spoofProvider": true, "spoofSignature": true, "spoofVendingFinger": true, "spoofVendingSdk": true}
	r := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		v := strings.SplitN(strings.TrimSpace(l), "=", 2)
		if len(v) == 2 && allowed[v[0]] {
			if _, exists := r[v[0]]; exists {
				return nil, fail("E_CAPABILITY", "Duplicate PIF setting requires review.")
			}
			r[v[0]] = v[1]
		}
	}
	return r, nil
}
func (a *App) capabilities() (map[string]string, error) {
	if a.Fake {
		return map[string]string{"mode": "offline-fake-engine", "xml_x509": "bundled-go", "reload": "fake"}, nil
	}
	if os.Geteuid() != 0 {
		return nil, fail("E_ROOT", "KernelSU root permission is required.")
	}
	if e := noLinks(a.Active); e != nil {
		return nil, e
	}
	m, e := getMetadata(a.Active)
	if e != nil {
		return nil, e
	}
	if m.UID != 0 || m.Mode&0077 != 0 || m.SELinux == "" {
		return nil, fail("E_CAPABILITY", "Active directory ownership, private access or SELinux metadata is not verified.")
	}
	out := map[string]string{"xml_x509": "bundled-go-standard-library", "reload": "installed-1.4.1-per-file-FileObserver", "filesystem": "same-directory-rename-fsync"}
	pinned := map[string]string{"service.sh": "d1b1813d7bfe66ed58b357d2c6f247fe7e8d698a3aa79c722769ff0c0da6e508", "daemon": "6ec6ec3f88c8b126d7935e5482d485ed8b37219ce26dbc16be5168ffd95658ed", "service.apk": "75a78b56d7c6615cf49dfad8c7b3ed22b966ce506c99e4d664dacb4298c5e54d", "libtricky_store.so": "6d729980d400d656e5f2908dc86c69104f49e7067961f3fc43dec4b30804cc91"}
	for name, want := range pinned {
		b, e := bounded(filepath.Join(a.Modules, "tricky_store", name), 8<<20)
		if e != nil {
			return nil, fail("E_CAPABILITY", "The inspected TrickyStore installation is unavailable.")
		}
		got := hash(b)
		if got != want {
			return nil, fail("E_CAPABILITY", "TrickyStore program files changed. Read-only diagnostics remain available; review compatibility before Apply.")
		}
		out["tricky_store/"+name] = got
	}
	pif, e := bounded(filepath.Join(a.Modules, "playintegrityfix", "custom.pif.prop"), 64<<10)
	if e != nil {
		return nil, e
	}
	out["pif_hash"] = hash(pif)
	for _, marker := range []string{"target_from_denylist", "security_patch_auto_config"} {
		p := filepath.Join(a.Active, marker)
		_, e = os.Lstat(p)
		if e == nil {
			return nil, fail("E_WRITER", "TA_utl has an enabled configuration writer marker. Review its behavior before Apply; no module was changed.")
		}
		if !os.IsNotExist(e) {
			return nil, e
		}
		out[marker] = "absent"
	}
	for _, mod := range []string{"TA_utl", ".TA_utl"} {
		p := filepath.Join(a.Modules, mod, "service.sh")
		b, e := bounded(p, 1<<20)
		if e == nil {
			out[mod+"_script_hash"] = hash(b)
		} else if !os.IsNotExist(e) {
			return nil, e
		}
	}
	engines, e := a.engineHealth()
	if e != nil {
		return nil, e
	}
	if engines != 1 {
		return nil, fail("E_CAPABILITY", "Exactly one verified TrickyStore executable/argument instance is required. Inspect Diagnostics; no process was stopped.")
	}
	out["engine_count"] = "1"
	return out, nil
}
func (a *App) engineHealth() (int, error) {
	if a.Fake {
		return 1, nil
	}
	list, e := os.ReadDir("/proc")
	if e != nil {
		return 0, e
	}
	count := 0
	for _, entry := range list {
		if _, e := strconv.Atoi(entry.Name()); e != nil {
			continue
		}
		dir := filepath.Join("/proc", entry.Name())
		b, e := os.ReadFile(filepath.Join(dir, "cmdline"))
		if e != nil {
			continue
		}
		args := strings.Split(string(b), "\x00")
		// app_process changes its command line to nice-name. Confirm its mapped APK/native module too.
		candidate := false
		for _, v := range args {
			if v == "TrickyStore" || v == "io.github.a13e300.tricky_store.MainKt" {
				candidate = true
			}
		}
		if !candidate {
			continue
		}
		exe, e := os.Readlink(filepath.Join(dir, "exe"))
		if e != nil || !(strings.HasSuffix(exe, "/app_process64") || strings.HasSuffix(exe, "/app_process")) {
			continue
		}
		maps, e := os.ReadFile(filepath.Join(dir, "maps"))
		if e != nil {
			continue
		}
		if !bytes.Contains(maps, []byte(filepath.Join(a.Modules, "tricky_store", "service.apk"))) && !bytes.Contains(maps, []byte(filepath.Join(a.Modules, "tricky_store", "libtricky_store.so"))) {
			continue
		}
		count++
	}
	return count, nil
}
func (a *App) adoption() (map[string]any, error) {
	if a.Adoption != nil {
		return a.Adoption()
	}
	n, e := a.engineHealth()
	v := map[string]any{"verified_engine_instances": n, "health": "healthy", "adoption": "pending", "identity_evidence": "No freshly observed signer identity is available. Historical chain counts are insufficient.", "wallet_acceptance": "unverified", "manual_reboot_required": false}
	if e != nil || n != 1 {
		v["health"] = "failed"
		return v, fail("E_ADOPTION", "Verified TrickyStore process health failed. Restore the configuration set; do not kill unrelated processes.")
	}
	return v, nil
}

type Finding struct {
	ID             string               `json:"id"`
	Kind           string               `json:"kind"`
	Title          string               `json:"title"`
	Evidence       string               `json:"evidence"`
	Time           string               `json:"time"`
	Stale          bool                 `json:"stale"`
	Config         map[string]FileState `json:"configuration"`
	Repair         string               `json:"repair"`
	ExpectedEffect string               `json:"expected_effect"`
	Risk           string               `json:"risk"`
	Rollback       string               `json:"rollback"`
	Verification   string               `json:"verification"`
	Dependency     string               `json:"dependency"`
}

func (a *App) finding(id, kind, title, evidence, repair, verify string, config map[string]FileState) Finding {
	return Finding{id, kind, title, evidence, a.time(), false, config, repair, "A scoped repair can address this finding; it does not establish Wallet acceptance.", "Review a plan; ordinary Apply never clears data or reboots.", "Complete three-file snapshot before change; named rollback available.", verify, "User/external service evidence may still be required."}
}
func (a *App) Watch(days int) (any, error) {
	if days < 1 || days > 365 {
		return nil, fail("E_INPUT", "Warning horizon must be between 1 and 365 days.")
	}
	p, e := a.pif()
	if e != nil {
		return nil, e
	}
	state := "estimate-valid-for-supplied-fingerprint"
	if p["FINGERPRINT"] != fingerprint {
		state = "estimate-invalid-fingerprint-changed"
	}
	expiry, _ := time.Parse("2006-01-02", "2026-11-18")
	remaining := int(expiry.Sub(a.Now().UTC()).Hours() / 24)
	warnings := []string{}
	if state != "estimate-valid-for-supplied-fingerprint" {
		warnings = append(warnings, "Fingerprint changed. Supply a newly justified expiry estimate.")
	} else if remaining <= days {
		warnings = append(warnings, "Supplied estimated canary expiry is approaching or has passed; eligibility is not established.")
	}
	patch, e := bounded(filepath.Join(a.Active, "security_patch.txt"), 64<<10)
	alignment := patchAlignment(p["SECURITY_PATCH"], patch, e)
	if alignment != "aligned" {
		message := "Global TrickyStore patch differs from the inspected PIF patch; review Diagnostics."
		if alignment == "unknown" {
			message = "Patch alignment is unknown: a readable, valid PIF date and one supported global TrickyStore date are required."
		} else if alignment == "ambiguous" {
			message = "Patch alignment is ambiguous: duplicate, invalid or overriding patch settings require explicit review."
		}
		warnings = append(warnings, message)
	}
	result := map[string]any{"estimate": "2026-11-18", "estimate_source": "owner-supplied; not a Google guarantee", "fingerprint_estimate_state": state, "fingerprint_hash": hash([]byte(p["FINGERPRINT"])), "days_remaining": remaining, "warning_horizon_days": days, "patch_aligned": alignment == "aligned", "patch_alignment_state": alignment, "pif_settings_hash": hashPIF(p), "warnings": warnings, "scheduled_watch": "disabled; no daemon or boot-time fetching"}
	if e == nil {
		result["patch_sha256"] = hash(patch)
	}
	return result, nil
}

// Alignment is a comparison of one supported global setting, not a substring
// search or a claim that the engine adopted it. Overrides remain explicit.
func patchAlignment(pifPatch string, body []byte, readErr error) string {
	if readErr != nil || !validPatchDate(pifPatch) {
		return "unknown"
	}
	global := ""
	count := 0
	ambiguous := false
	for _, line := range strings.Split(string(body), "\n") {
		v := strings.TrimSpace(line)
		if v == "" || strings.HasPrefix(v, "#") {
			continue
		}
		pair := strings.SplitN(v, "=", 2)
		if len(pair) == 2 && pair[0] == "all" {
			count++
			global = pair[1]
			if !validPatchDate(global) {
				ambiguous = true
			}
			continue
		}
		// Per-partition settings and unsupported non-comment syntax cannot be
		// silently interpreted as a single aligned global configuration.
		ambiguous = true
	}
	if ambiguous || count > 1 {
		return "ambiguous"
	}
	if count == 0 {
		return "unknown"
	}
	if global == pifPatch {
		return "aligned"
	}
	return "different"
}

func validPatchDate(value string) bool {
	if !patchDateRE.MatchString(value) {
		return false
	}
	_, err := time.Parse("2006-01-02", value)
	return err == nil
}

// Only allowlisted PIF settings participate; no raw settings enter the report.
func hashPIF(p map[string]string) string {
	keys := make([]string, 0, len(p))
	for key := range p {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for _, key := range keys {
		canonical.WriteString(key + "=" + p[key] + "\n")
	}
	return hash([]byte(canonical.String()))
}

func inventoryAlgorithms(values []string) []string {
	seen := map[string]bool{}
	for _, v := range values {
		if v == "ecdsa" || v == "rsa" || v == "unsupported" {
			seen[v] = true
		}
	}
	out := []string{}
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func summaryAlgorithms(summary keybox.RedactedSummary) []string {
	values := []string{}
	for _, box := range summary.Keyboxes {
		for _, key := range box.Keys {
			values = append(values, key.Algorithm)
		}
	}
	return inventoryAlgorithms(values)
}

func targetStates(body []byte) map[string]string {
	states := map[string]string{}
	for _, pkg := range requiredPackages {
		count := 0
		state := "missing"
		for _, line := range strings.Split(string(body), "\n") {
			v := strings.TrimSpace(line)
			if v == "" || strings.HasPrefix(v, "#") || strings.TrimRight(v, "!?") != pkg {
				continue
			}
			count++
			switch v {
			case pkg + "!":
				state = "generate"
			case pkg + "?":
				state = "leaf"
			case pkg:
				state = "unflagged"
			default:
				state = "invalid_flags"
			}
		}
		if count > 1 {
			state = "duplicate"
		}
		states[pkg] = state
	}
	return states
}

func (a *App) resetDiagnostic() (any, bool, string) {
	var r resetJournal
	if err := readJSON(filepath.Join(a.Root, "reset-journal.json"), &r); err != nil {
		if os.IsNotExist(err) {
			return map[string]string{"state": "none"}, false, ""
		}
		return map[string]string{"state": "unreadable"}, true, "Inspect the one-shot reset journal. Preserve unreadable evidence; never repeat app-data clearing automatically."
	}
	if err := a.validateReset(r, false); err != nil {
		return map[string]string{"state": "invalid"}, true, "Inspect the one-shot reset journal. Preserve corrupt evidence; never repeat app-data clearing automatically."
	}
	view := map[string]any{"state": r.State, "user": r.User, "completed_steps": r.Step, "time": r.Time}
	if r.State == "completed" {
		return view, false, ""
	}
	if r.State == "awaiting-manual-reboot" {
		return view, true, "Follow the one-shot reset's manual reboot, reset resume and separately reviewed manual completion steps. Do not repeat the clears; configuration rollback cannot restore app data."
	}
	return view, true, "Inspect the unfinished one-shot reset before any other change. Some app-data clears may have happened; do not repeat them. Configuration rollback cannot restore app data."
}

var versionRE = regexp.MustCompile(`(?m)^\s*versionName=([^\r\n]{1,100})`)
var uidRE = regexp.MustCompile(`uid:([0-9]+)`)

func (a *App) Status() (any, error) {
	config, e := a.snapshot()
	if e != nil {
		return nil, e
	}
	findings := []Finding{}
	summaries := map[string]any{}
	algorithms := []string{}
	declaredAlgorithms := []string{}
	activeValidation := "missing"
	for _, n := range []string{"keybox.xml", "keybox.xml.sw_default"} {
		body, e := bounded(filepath.Join(a.Active, n), keybox.MaxInput)
		if os.IsNotExist(e) {
			if n == "keybox.xml" {
				findings = append(findings, a.finding("INPUT_"+n, "confirmed", "The active keybox file is missing", "The active configuration contains no keybox.xml. Signing-key availability cannot be established.", "Validate an authorized local replacement before planning any change.", "Check local validation, public trust/revocation and fresh signer adoption separately.", config))
			}
			continue
		}
		if e != nil {
			if n == "keybox.xml" {
				activeValidation = "unreadable"
			}
			findings = append(findings, a.finding("INPUT_"+n, "confirmed", "Keybox input could not be read safely", "Input missing, oversized, symbolic or unreadable.", "Import a safe local input for review.", "Validate staged input.", config))
			continue
		}
		m, me := getMetadata(filepath.Join(a.Active, n))
		if me == nil && m.Mode&0077 != 0 {
			findings = append(findings, a.finding("PERMISSIONS_"+n, "confirmed", "Key material has broad file permissions", "Group or other permission bits are present. Parent-directory access also matters.", "Review permissions separately; this helper preserved the existing material.", "Inspect ownership, permissions and SELinux from root.", config))
		}
		d, e := keybox.Parse(body, a.Now())
		if e != nil {
			audit := keybox.Audit(body, a.Now())
			summaries[n] = audit
			if n == "keybox.xml" {
				activeValidation = "invalid"
				if inventory, ok := audit.(map[string]any); ok {
					if v, ok := inventory["algorithms"].([]string); ok {
						declaredAlgorithms = inventoryAlgorithms(v)
					}
				}
			}
			findings = append(findings, a.finding("VALIDATION_"+n, "confirmed", "Keybox validation failed", e.Error()+". Bundled validation rejected this input; secret content is withheld.", "Review a supplied replacement; the existing file was preserved.", "Use Validate on a private staged copy.", config))
			continue
		}
		summaries[n] = d.Summary()
		if n == "keybox.xml" {
			activeValidation = "validated"
			algorithms = summaryAlgorithms(d.Summary().(keybox.RedactedSummary))
			declaredAlgorithms = append([]string{}, algorithms...)
		}
	}
	hasRSA := false
	for _, x := range algorithms {
		if x == "rsa" {
			hasRSA = true
		}
	}
	if !hasRSA {
		declaredRSA := false
		for _, v := range declaredAlgorithms {
			declaredRSA = declaredRSA || v == "rsa"
		}
		if declaredRSA {
			findings = append(findings, a.finding("RSA_UNVALIDATED", "confirmed", "A declared RSA entry did not pass mandatory validation", "Structural inventory found an RSA label, but the active document failed mandatory XML/key/certificate validation. Labels do not establish a usable signing key.", "Review the validation failure before considering signing-material changes.", "Check public trust/revocation and freshly observed signer adoption.", config))
		} else {
			findings = append(findings, a.finding("RSA_MISSING", "hypothesis", "RSA absence does not establish a Wallet fault", "No validated RSA entry was found. This alone does not establish a failed attestation or Wallet provisioning path.", "Investigate trust, revocation and fresh signer selection before considering supplied RSA material.", "Check Wallet security/readiness and a real tap; RSA presence alone is not proof.", config))
		}
	}
	target, e := bounded(filepath.Join(a.Active, "target.txt"), 1<<20)
	if e == nil {
		states := targetStates(target)
		for _, pkg := range requiredPackages {
			if states[pkg] != "generate" {
				findings = append(findings, a.finding("TARGET_"+pkg, "confirmed", "A required generate-mode target needs review", "Required package has missing, duplicate or conflicting generate-mode entries.", "Select required-target repair in a plan; unrelated entries and comments stay intact.", "Review exact target changes, then obtain fresh attestation traffic.", config))
			}
		}
	} else {
		findings = append(findings, a.finding("INPUT_target.txt", "confirmed", "Required target configuration is unavailable", "target.txt is missing or could not be read safely. Required package modes cannot be established.", "Review a scoped required-target repair after keybox validation.", "Review exact target changes and obtain fresh attestation traffic.", config))
	}
	caps, capErr := a.capabilities()
	if capErr != nil {
		findings = append(findings, a.finding("CAPABILITY", "confirmed", "Apply is currently blocked", Response(nil, capErr).Message, "Review the stated capability; read-only diagnostics remain available.", "Re-run Diagnostics after an authorized resolution.", config))
	}
	watch, we := a.Watch(14)
	if we == nil {
		if w, ok := watch.(map[string]any); ok {
			for _, s := range w["warnings"].([]string) {
				findings = append(findings, a.finding("WATCH", "confirmed", "Patch or canary warning", s, "Review a backed-up patch plan or update the stored estimate only with supporting evidence.", "Compare current hashes and patch settings.", config))
			}
		}
	} else {
		watch = map[string]any{"patch_aligned": false, "patch_alignment_state": "unknown", "fingerprint_estimate_state": "unavailable", "warnings": []string{"PIF/watch inputs could not be evaluated safely."}}
		findings = append(findings, a.finding("WATCH_INPUT", "confirmed", "Patch and canary evidence is unavailable", "PIF/watch inputs could not be evaluated safely; no patch alignment or canary eligibility was established.", "Inspect the supported PIF settings before any patch repair.", "Re-run Watch after an authorized input correction.", config))
	}
	apps := []map[string]any{}
	device := map[string]any{"real_bootloader": "owner-reported unlocked; spoofed properties are not evidence", "wallet_error": "owner-reported security rejection after card-number submission", "wallet_stage": "card provisioning", "generic_integrity": "supplied BASIC/DEVICE/STRONG pass; not rechecked by this helper", "wallet_acceptance": "unverified"}
	currentUser, userErr := a.currentUser()
	device["current_android_user"] = "unavailable"
	if userErr == nil {
		device["current_android_user"] = currentUser
	}
	if !a.Fake {
		if userErr == nil {
			role, re := run("/system/bin/cmd", "role", "get-role-holders", "--user", currentUser, "android.app.role.WALLET")
			if re == nil {
				holder := strings.TrimSpace(role)
				if holder == "com.google.android.apps.walletnfcrel" {
					device["wallet_role"] = "Google Wallet"
				} else if holder == "com.google.android.gms" {
					device["wallet_role"] = "Google Play services TapAndPay"
				} else if holder == "" {
					device["wallet_role"] = "unset"
				} else {
					device["wallet_role"] = "other holder; inspect settings"
				}
			} else {
				device["wallet_role"] = "unavailable"
			}
		} else {
			currentUser = ""
		}
		for _, pkg := range requiredPackages {
			row := map[string]any{"package": pkg, "uid": "unavailable", "version": "unavailable"}
			u, ue := "", userErr
			if currentUser != "" {
				u, ue = run("/system/bin/pm", "list", "packages", "--user", currentUser, "-U", pkg)
			}
			if ue == nil && currentUser != "" {
				for _, l := range strings.Split(u, "\n") {
					if strings.HasPrefix(l, "package:"+pkg+" ") {
						m := uidRE.FindStringSubmatch(l)
						if len(m) > 1 {
							row["uid"] = m[1]
						}
					}
				}
			}
			v, ve := run("/system/bin/dumpsys", "package", pkg)
			if ve == nil || v != "" {
				m := versionRE.FindStringSubmatch(v)
				if len(m) > 1 {
					row["version"] = m[1]
				}
			}
			apps = append(apps, row)
		}
		nfc, ne := run("/system/bin/cmd", "nfc", "status")
		if ne == nil {
			if strings.Contains(nfc, "disabled") {
				device["nfc"] = "disabled"
				findings = append(findings, a.finding("NFC", "confirmed", "NFC is disabled", "NFC service reports disabled. This affects tapping, not proof of the provisioning rejection cause.", "Enable NFC manually when ready for a tap test.", "Check Wallet readiness and then a real tap.", config))
			} else if strings.Contains(nfc, "enabled") {
				device["nfc"] = "enabled"
			}
		} else {
			device["nfc"] = "unavailable"
		}
		device["default_payment"] = "unavailable"
		if currentUser != "" {
			component, ce := run("/system/bin/settings", "--user", currentUser, "get", "secure", "nfc_payment_default_component")
			if ce == nil {
				s := strings.TrimSpace(component)
				if s == "com.google.android.gms/com.google.android.gms.tapandpay.hce.service.TpHceService" {
					device["default_payment"] = "Google TapAndPay"
				} else {
					device["default_payment"] = "other-or-unset; inspect phone settings"
				}
			}
		}
		auto, ae := run("/system/bin/settings", "get", "global", "auto_time")
		if ae == nil {
			device["automatic_time"] = strings.TrimSpace(auto) == "1"
		}
		device["device_time"] = a.time()
		connectivity, co := run("/system/bin/dumpsys", "connectivity")
		if co == nil {
			device["validated_connectivity"] = strings.Contains(connectivity, "IS_VALIDATED")
		} // Never expose raw network output.
	}
	count := 0
	if entries, e := os.ReadDir(filepath.Join(a.Active, "persistent_keys")); e == nil {
		count = len(entries)
	}
	device["persistent_alias_count"] = count
	device["persistent_alias_warning"] = "Aliases were counted, never opened or removed. Stale app results remain a hypothesis."
	device["certification"] = "Check Play Store Settings > About on the phone; unavailable through a trusted root API."
	device["issuer_region_account"] = "Not inspected; user/provider action only if Wallet evidence indicates it."
	network := a.hostChecks()
	device["network_checks"] = network
	hist, invalidHistory := a.publicHistory()
	if invalidHistory > 0 {
		findings = append(findings, a.finding("HISTORY", "confirmed", "History metadata needs review", "Unsupported or corrupt history records were omitted from this redacted report.", "Keep the private records and inspect only a redacted schema projection.", "Recheck trusted metadata format before further reporting.", config))
	}
	last := any(nil)
	if len(hist) > 0 {
		last = hist[len(hist)-1]
	}
	recovery, _ := a.Recovery("status")
	backupView, _ := a.Backups()
	inventory := []Stage{}
	entries, _ := os.ReadDir(filepath.Join(a.Root, "staged"))
	for _, en := range entries {
		if !en.IsDir() || !validID.MatchString(en.Name()) {
			continue
		}
		var st Stage
		if readJSON(filepath.Join(a.Root, "staged", en.Name(), "stage.json"), &st) == nil && validStage(st, en.Name()) {
			inventory = append(inventory, st)
		}
	}
	resetView, resetPending, resetNext := a.resetDiagnostic()
	publicView := a.publicTrustView()
	if publicView["available"] == true {
		for _, check := range publicView["keys"].([]keybox.PublicKeyCheck) {
			if check.Revocation == "listed-revoked" || check.Revocation == "listed-suspended" {
				findings = append(findings, a.finding("PUBLIC_LISTED", "confirmed", "Google lists a certificate in the current chain", "A certificate within a Google-anchored chain matches the freshly fetched full public status snapshot. Only redacted flags are shown; no local serial was uploaded.", "Preserve the current files and review authorized replacement material before any change.", "Refresh the public status snapshot and check a separately supplied input locally. Wallet acceptance remains a separate test.", config))
			} else if !check.GoogleRootKey {
				findings = append(findings, a.finding("PUBLIC_ROOT_UNKNOWN", "confirmed", "The current anchor is absent from Google's root-key catalog", "The locally consistent chain does not match a published Google root key. Public revocation status is unknown outside that issuing hierarchy.", "Review authorized material and fresh signer evidence; local consistency alone does not establish Google trust.", "Check the complete public root catalog and a fresh app-requested attestation independently.", config))
			}
		}
	}
	if resetPending {
		findings = append(findings, a.finding("RESET_PENDING", "confirmed", "A one-shot reset needs manual attention", "The reset journal is unfinished or unreadable. App-data changes cannot be reversed by configuration backups.", resetNext, "Inspect reset status; never repeat destructive clears automatically.", config))
	}
	next := "Establish public trust/revocation and fresh signer adoption evidence, then check the owner's Wallet security/readiness and a real tap. An RSA label alone is not a requirement or success proof."
	if capErr != nil {
		next = "Resolve the stated capability blocker before reviewing an Apply plan."
	} else if activeValidation != "validated" {
		next = "Review the active keybox's mandatory validation failure or missing input. Validate any authorized replacement, then establish public trust/revocation and fresh signer adoption."
	} else {
		next = toString(publicView["next_step"])
	}
	if a.unfinished() {
		next = "Open Recovery and restore the interrupted transaction before other changes."
	}
	if resetPending {
		next = resetNext
	}
	stackBinding, stackErr := a.stackEvidenceBinding()
	if stackErr != nil {
		stackBinding = "unavailable"
	}
	stackPending := a.stackUnfinished()
	if stackPending && !resetPending {
		next = "Inspect the stack journal and restore its checked resource backup through Stack rollback. Release an interrupted lock only through verified Recovery."
	}
	return map[string]any{"version": Version, "public_attestation": publicView, "active": config, "algorithms": algorithms, "declared_algorithms": declaredAlgorithms, "active_keybox_validation": activeValidation, "keybox_summaries": summaries, "findings": findings, "evidence_time": a.time(), "freshness": "fresh snapshot; findings become stale after relevant hashes/settings change", "last_operation": last, "rollback": backupView, "recovery": recovery, "reset": resetView, "next_step": next, "history": hist, "inventory": inventory, "device": device, "applications": apps, "watch": watch, "capabilities": caps, "apply_available": capErr == nil && stackErr == nil && !a.unfinished(), "api": a.apiSourceStatus(), "stack": a.stackStatus(), "stack_pending": stackPending, "stack_evidence_binding": stackBinding}, nil
}
func (a *App) hostChecks() any {
	out := map[string]any{"failure_evidence": "not observed; static matches do not establish a network failure", "blocked_service_domains": []string{}}
	if a.Fake {
		return out
	}
	b, e := bounded("/system/etc/hosts", 32<<20)
	if e != nil {
		out["inventory"] = "unavailable (mount/symlink/size); no blocklist was changed"
		return out
	}
	domains := []string{"wallet.google.com", "payments.google.com", "android.clients.google.com", "play.googleapis.com", "www.googleapis.com", "mtalk.google.com"}
	blocked := []string{}
	for _, l := range strings.Split(string(b), "\n") {
		v := strings.Fields(l)
		if len(v) < 2 || !(v[0] == "0.0.0.0" || v[0] == "127.0.0.1" || v[0] == "::") {
			continue
		}
		for _, h := range v[1:] {
			for _, d := range domains {
				if h == d {
					blocked = append(blocked, d)
				}
			}
		}
	}
	out["blocked_service_domains"] = blocked
	out["hosts_hash"] = hash(b)
	return out
}
func (a *App) Diagnose() (any, error) {
	return a.withLock(func() (any, error) {
		v, e := a.Status()
		if e != nil {
			return nil, e
		}
		if e = writeJSON(filepath.Join(a.Root, "diagnosis.json"), v); e != nil {
			return nil, e
		}
		return v, nil
	})
}
func (a *App) Verify(walletReady, tap bool, reviewedUser ...string) (any, error) {
	return a.withLock(func() (any, error) {
		if err := a.requireRecovered(); err != nil {
			return nil, err
		}
		var j Journal
		e := readJSON(filepath.Join(a.Root, "journal.json"), &j)
		if e != nil {
			return nil, fail("E_VERIFY", "No committed operation is recorded. Run Diagnostics first.")
		}
		if e = a.validateJournal(j); e != nil {
			return nil, e
		}
		if j.State != "committed" {
			return nil, fail("E_RECOVERY", "Complete recovery before verification.")
		}
		state, e := a.snapshot()
		if e != nil {
			return nil, e
		}
		if !equal(state, j.Intended) {
			return nil, fail("E_STALE", "Active files changed after commit. Verification is stale.")
		}
		stackBinding, e := a.stackEvidenceBinding()
		if e != nil {
			return nil, e
		}
		user, userErr := a.currentUser()
		declaresReadiness := walletReady || tap
		if declaresReadiness {
			if len(reviewedUser) == 0 && a.Fake {
				reviewedUser = []string{"0"} // Existing internal fake tests never invoke Android.
			}
			if len(reviewedUser) != 1 || !validUser.MatchString(reviewedUser[0]) {
				return nil, fail("E_CONFIRM", "Readiness declarations require the numeric Android user from a fresh reviewed status.")
			}
			if userErr != nil {
				return map[string]string{"current_android_user": "unavailable", "wallet_readiness": "unverified", "tap_to_pay": "unverified"}, fail("E_CAPABILITY", "The current Android user could not be verified; readiness declarations were not recorded.")
			}
			if reviewedUser[0] != user {
				return nil, fail("E_STALE", "The Android user changed since readiness review. Refresh status and confirm the current user's evidence again.")
			}
		}
		out, e := a.adoption()
		if e != nil {
			return out, e
		}
		out["files_committed"] = true
		out["configuration"] = state
		out["stack_evidence_binding"] = stackBinding
		out["time"] = a.time()
		out["current_android_user"] = "unavailable"
		if userErr == nil {
			out["current_android_user"] = user
		} else if out["adoption"] == "verified" {
			out["adoption"] = "pending"
		}
		out["wallet_readiness"] = "unverified"
		out["tap_to_pay"] = "unverified"
		if walletReady {
			out["wallet_readiness"] = "user-confirmed"
		}
		if tap {
			out["tap_to_pay"] = "user-confirmed"
		}
		if err := a.checkpoint("before-verification-persist"); err != nil {
			return nil, err
		}
		reconfirm := func() error {
			current, err := a.snapshot()
			if err != nil {
				return err
			}
			if !equal(current, state) {
				return fail("E_STALE", "Active configuration changed during verification. No readiness report was recorded; collect fresh evidence.")
			}
			freshStack, err := a.stackEvidenceBinding()
			if err != nil || freshStack != stackBinding {
				return fail("E_STALE", "Stack settings changed during verification. No readiness report was recorded; collect fresh evidence.")
			}
			if userErr == nil {
				freshUser, err := a.currentUser()
				if err != nil || freshUser != user {
					return fail("E_STALE", "The Android user could not be reconfirmed before recording verification. Refresh status and review the current user's evidence again.")
				}
			}
			return nil
		}
		if err := reconfirm(); err != nil {
			return nil, err
		}
		// Only a trusted internal identity-verification implementation may create
		// this checkpoint. User Wallet/Tap declarations never upgrade adoption.
		if out["adoption"] == "verified" {
			b, err := a.backup("verified-configuration", state)
			if err != nil {
				return nil, err
			}
			if err = reconfirm(); err != nil {
				return nil, err
			}
			b.Verified, b.Adoption = true, "verified"
			if err = writeJSON(filepath.Join(a.Root, "backups", b.ID, "backup.json"), b); err != nil {
				return nil, err
			}
			if err = writeJSON(filepath.Join(a.Root, "last-verified.json"), map[string]string{"backup": b.ID}); err != nil {
				return nil, err
			}
			out["verified_backup"] = b.ID
		}
		if e = writeJSON(filepath.Join(a.Root, "verification.json"), out); e != nil {
			return nil, e
		}
		return out, nil
	})
}
