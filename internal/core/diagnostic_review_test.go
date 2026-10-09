package core

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"walletdiagnostic/internal/keybox"
)

// Diagnostic evidence uses generated signing material in temporary directories.
// Fake mode must keep Android commands, accounts and real device data out of it.
func diagnosticStatus(t *testing.T, a *App) map[string]any {
	t.Helper()
	v, err := a.Status()
	if err != nil {
		t.Fatal(Response(nil, err).Code)
	}
	requireRedacted(t, Response(v, nil))
	return v.(map[string]any)
}

func diagnosticFinding(view map[string]any, id string) (Finding, bool) {
	for _, finding := range view["findings"].([]Finding) {
		if finding.ID == id {
			return finding, true
		}
	}
	return Finding{}, false
}

func diagnosticNoVerification(t *testing.T, a *App) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(a.Root, "verification.json")); !os.IsNotExist(err) {
		t.Fatal("rejected verification created a report")
	}
}

func TestDiagnosticWatchRequiresExactSupportedPatchEvidence(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	patchPath := filepath.Join(s.app.Active, "security_patch.txt")
	pifPath := filepath.Join(s.app.Modules, "playintegrityfix", "custom.pif.prop")
	for _, tc := range []struct {
		name, pif, patch, state string
		missingPatch            bool
	}{
		{name: "missing-pif-date", patch: "all=2026-09-05\n", state: "unknown"},
		{name: "empty-pif-date", pif: "SECURITY_PATCH=\n", patch: "all=2026-09-05\n", state: "unknown"},
		{name: "invalid-pif-date", pif: "SECURITY_PATCH=2026-02-30\n", patch: "all=2026-09-05\n", state: "unknown"},
		{name: "commented-global", pif: "SECURITY_PATCH=2026-09-05\n", patch: "# all=2026-09-05\n", state: "unknown"},
		{name: "suffix-is-not-date", pif: "SECURITY_PATCH=2026-09-05\n", patch: "all=2026-09-05-unrelated\n", state: "ambiguous"},
		{name: "duplicate-matching-globals", pif: "SECURITY_PATCH=2026-09-05\n", patch: "all=2026-09-05\nall=2026-09-05\n", state: "ambiguous"},
		{name: "conflicting-globals", pif: "SECURITY_PATCH=2026-09-05\n", patch: "all=2026-08-05\nall=2026-09-05\n", state: "ambiguous"},
		{name: "partition-override", pif: "SECURITY_PATCH=2026-09-05\n", patch: "all=2026-09-05\nvendor=2026-08-05\n", state: "ambiguous"},
		{name: "unknown-syntax", pif: "SECURITY_PATCH=2026-09-05\n", patch: "all=2026-09-05\nunsupported-value\n", state: "ambiguous"},
		{name: "missing-patch-file", pif: "SECURITY_PATCH=2026-09-05\n", state: "unknown", missingPatch: true},
		{name: "exact-global-with-comments", pif: "SECURITY_PATCH=2026-09-05\n", patch: " # all=2026-01-01\n\n  all=2026-09-05 \r\n", state: "aligned"},
		{name: "exact-different-date", pif: "SECURITY_PATCH=2026-09-05\n", patch: "all=2026-08-05\n", state: "different"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testWrite(t, pifPath, []byte("FINGERPRINT="+fingerprint+"\n"+tc.pif))
			if tc.missingPatch {
				if err := os.Remove(patchPath); err != nil {
					t.Fatal("could not prepare missing patch fixture")
				}
			} else {
				testWrite(t, patchPath, []byte(tc.patch))
			}
			v, err := s.app.Watch(14)
			if err != nil {
				t.Fatal("supported Watch fixture failed")
			}
			view := v.(map[string]any)
			if view["patch_alignment_state"] != tc.state || view["patch_aligned"] != (tc.state == "aligned") {
				t.Fatal("Watch inferred alignment without exact, supported evidence")
			}
			if !validHash.MatchString(view["pif_settings_hash"].(string)) {
				t.Fatal("Watch omitted its PIF evidence binding")
			}
			if _, exists := view["patch_sha256"]; exists == tc.missingPatch {
				t.Fatal("Watch patch evidence binding disagrees with availability")
			}
			requireRedacted(t, Response(v, nil))
		})
	}
}

func TestDiagnosticDeclaredAlgorithmsNeverImplyValidation(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	valid := diagnosticStatus(t, s.app)
	if valid["active_keybox_validation"] != "validated" || !reflect.DeepEqual(valid["algorithms"], []string{"ecdsa", "rsa"}) {
		t.Fatal("valid active fixture lost its validated algorithm evidence")
	}
	summary := valid["keybox_summaries"].(map[string]any)["keybox.xml"].(keybox.RedactedSummary)
	if summary.Trust != "unknown" || summary.Revocation != "unknown" {
		t.Fatal("local signature validity was promoted to public trust or revocation evidence")
	}
	// The same structurally declared algorithms remain present after expiry,
	// while neither becomes a usable validated entry.
	s.app.Now = func() time.Time { return coreTestNow.Add(25 * time.Hour) }
	expired := diagnosticStatus(t, s.app)
	if expired["active_keybox_validation"] != "invalid" || len(expired["algorithms"].([]string)) != 0 || !reflect.DeepEqual(expired["declared_algorithms"], []string{"ecdsa", "rsa"}) {
		t.Fatal("expired algorithm labels were treated as validated signing material")
	}
	if _, ok := diagnosticFinding(expired, "RSA_UNVALIDATED"); !ok {
		t.Fatal("declared RSA suppressed the active mandatory validation failure")
	}
	if _, ok := diagnosticFinding(expired, "VALIDATION_keybox.xml"); !ok {
		t.Fatal("active expiry was not reported")
	}
	if !strings.Contains(expired["next_step"].(string), "mandatory validation") {
		t.Fatal("invalid input did not take diagnostic priority")
	}
}

func TestDiagnosticMissingInputsRemainExplicit(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	for _, name := range []string{"keybox.xml", "target.txt"} {
		if err := os.Remove(filepath.Join(s.app.Active, name)); err != nil {
			t.Fatal("could not prepare absent input fixture")
		}
	}
	view := diagnosticStatus(t, s.app)
	if view["active_keybox_validation"] != "missing" || len(view["algorithms"].([]string)) != 0 {
		t.Fatal("absent active keybox implied validation")
	}
	for _, id := range []string{"INPUT_keybox.xml", "INPUT_target.txt"} {
		if finding, ok := diagnosticFinding(view, id); !ok || finding.Kind != "confirmed" {
			t.Fatal("missing required input disappeared from diagnostics")
		}
	}
	// Optional software default is absent in this fixture; its absence is normal.
	if _, ok := diagnosticFinding(view, "INPUT_keybox.xml.sw_default"); ok {
		t.Fatal("optional absent software default became a required-input fault")
	}
	if err := os.Remove(filepath.Join(s.app.Modules, "playintegrityfix", "custom.pif.prop")); err != nil {
		t.Fatal("could not prepare absent watch fixture")
	}
	view = diagnosticStatus(t, s.app)
	if _, ok := diagnosticFinding(view, "WATCH_INPUT"); !ok || view["watch"].(map[string]any)["patch_alignment_state"] != "unknown" {
		t.Fatal("unavailable PIF input retained an alignment claim")
	}
}

func TestDiagnosticRSAAbsenceIsNotARequirementProof(t *testing.T) {
	fixture := syntheticKeybox(t)
	s := newSandbox(t, fixture)
	doc, err := keybox.Parse(fixture, coreTestNow)
	if err != nil {
		t.Fatal("synthetic source parse failed")
	}
	selected, err := keybox.Merge([]*keybox.Document{doc}, []keybox.Selection{{Source: 0, Keybox: 0, Key: 0, Algorithm: "ecdsa"}}, coreTestNow)
	if err != nil {
		t.Fatal("explicit ECDSA selection failed")
	}
	body, err := selected.XML()
	if err != nil {
		t.Fatal("synthetic selected XML output failed")
	}
	testWrite(t, filepath.Join(s.app.Active, "keybox.xml"), body)
	view := diagnosticStatus(t, s.app)
	if view["active_keybox_validation"] != "validated" || !reflect.DeepEqual(view["algorithms"], []string{"ecdsa"}) {
		t.Fatal("ECDSA-only input was treated as a mandatory validation fault")
	}
	finding, ok := diagnosticFinding(view, "RSA_MISSING")
	if !ok || finding.Kind != "hypothesis" || !strings.Contains(finding.Title, "does not establish") {
		t.Fatal("RSA absence was promoted into a demonstrated Wallet requirement")
	}
	next := view["next_step"].(string)
	if view["public_attestation"].(map[string]any)["state"] != "no-cache" || !strings.Contains(next, "public-feed refresh") || strings.Contains(next, "missing RSA") {
		t.Fatal("RSA acquisition displaced the missing public-evidence prerequisite")
	}
}

func TestDiagnosticRequiredTargetsRejectConflictingFlags(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	pkg := "com.google.android.gms"
	var baseline strings.Builder
	for _, required := range requiredPackages {
		if required != pkg {
			baseline.WriteString(required + "!\n")
		}
	}
	for _, tc := range []struct {
		name, declarations string
		fault              bool
	}{
		{"generate-and-leaf", pkg + "!\n" + pkg + "?\n", true},
		{"generate-and-bare", pkg + "!\n" + pkg + "\n", true},
		{"duplicate-generate", pkg + "!\n" + pkg + "!\n", true},
		{"double-flag", pkg + "!!\n", true},
		{"mixed-flag", pkg + "!?\n", true},
		{"bare", pkg + "\n", true},
		{"leaf", pkg + "?\n", true},
		{"missing", "", true},
		{"single-generate-with-comments", " # " + pkg + "?\n  " + pkg + "!  \norg.example.unrelated?\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testWrite(t, filepath.Join(s.app.Active, "target.txt"), []byte(baseline.String()+tc.declarations))
			view := diagnosticStatus(t, s.app)
			if _, present := diagnosticFinding(view, "TARGET_"+pkg); present != tc.fault {
				t.Fatal("required target flags or duplicates were misclassified")
			}
			for _, required := range requiredPackages {
				if required != pkg {
					if _, present := diagnosticFinding(view, "TARGET_"+required); present {
						t.Fatal("unrelated valid required entry was misclassified")
					}
				}
			}
		})
	}
}

func TestDiagnosticPendingResetBlocksVerificationAndUsesManualGuidance(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	if _, err := s.app.Apply(s.planID); err != nil {
		t.Fatal("committed verification fixture failed")
	}
	if err := writeJSON(filepath.Join(s.app.Root, "reset-journal.json"), finalResetFixture()); err != nil {
		t.Fatal("pending reset fixture failed")
	}
	view := diagnosticStatus(t, s.app)
	if _, ok := diagnosticFinding(view, "RESET_PENDING"); !ok || view["reset"].(map[string]any)["state"] != "awaiting-manual-reboot" {
		t.Fatal("pending reset was hidden by a committed configuration journal")
	}
	next := view["next_step"].(string)
	if !strings.Contains(next, "manual reboot") || !strings.Contains(next, "cannot restore app data") || strings.Contains(next, "restore the interrupted transaction") {
		t.Fatal("reset guidance implied that a configuration restore undoes app-data clearing")
	}
	if view["apply_available"] != false {
		t.Fatal("pending reset exposed an available Apply")
	}
	_, err := s.app.Verify(true, true, "0")
	requireCode(t, err, "E_RECOVERY")
	diagnosticNoVerification(t, s.app)
	// Corrupt reset metadata is preserved and described without echoing its data.
	testWrite(t, filepath.Join(s.app.Root, "reset-journal.json"), []byte("{\"state\":\"synthetic-sensitive-device-id\"}"))
	view = diagnosticStatus(t, s.app)
	if view["reset"].(map[string]string)["state"] != "invalid" {
		t.Fatal("invalid reset evidence was treated as no pending reset")
	}
}

func TestDiagnosticReadinessRequiresReviewedNumericUser(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	if _, err := s.app.Apply(s.planID); err != nil {
		t.Fatal("committed verification fixture failed")
	}
	for _, tc := range []struct {
		name string
		user []string
		code string
	}{
		{"empty", []string{""}, "E_CONFIRM"},
		{"symbolic", []string{"current"}, "E_CONFIRM"},
		{"negative", []string{"-1"}, "E_CONFIRM"},
		{"leading-zero", []string{"00"}, "E_CONFIRM"},
		{"unrelated-profile", []string{"10"}, "E_STALE"},
		{"multiple-reviews", []string{"0", "0"}, "E_CONFIRM"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.app.Verify(true, true, tc.user...)
			requireCode(t, err, tc.code)
			diagnosticNoVerification(t, s.app)
		})
	}
	view := diagnosticStatus(t, s.app)
	if view["device"].(map[string]any)["current_android_user"] != "0" {
		t.Fatal("fake current-user evidence dispatched Android or lost numeric binding")
	}
	s.app.Adoption = func() (map[string]any, error) {
		return map[string]any{"adoption": "pending", "current_android_user": "10", "wallet_acceptance": "unverified"}, nil
	}
	v, err := s.app.Verify(true, true, "0")
	if err != nil {
		t.Fatal("reviewed fake-user declaration failed")
	}
	report := v.(map[string]any)
	if report["current_android_user"] != "0" || report["wallet_readiness"] != "user-confirmed" || report["tap_to_pay"] != "user-confirmed" || report["adoption"] != "pending" {
		t.Fatal("readiness declaration changed user binding or upgraded adoption")
	}
	if _, err := os.Lstat(filepath.Join(s.app.Root, "last-verified.json")); !os.IsNotExist(err) {
		t.Fatal("user declaration created a verified signer checkpoint")
	}
	v, err = s.app.Verify(false, false)
	if err != nil || v.(map[string]any)["current_android_user"] != "0" || v.(map[string]any)["wallet_readiness"] != "unverified" {
		t.Fatal("ordinary verification required a declaration or reused previous readiness")
	}
	v, err = s.app.Verify(true, false)
	if err != nil || v.(map[string]any)["current_android_user"] != "0" {
		t.Fatal("legacy internal fake test bypassed deterministic user-zero binding")
	}
	requireRedacted(t, Response(v, nil))
}

func TestDiagnosticLateConfigurationChangeCannotRecordReadiness(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	if _, err := s.app.Apply(s.planID); err != nil {
		t.Fatal("committed verification fixture failed")
	}
	changed := false
	s.app.Fault = func(point string) error {
		if point == "before-verification-persist" {
			changed = true
			testWrite(t, filepath.Join(s.app.Active, "target.txt"), []byte("# external fixture writer\n"))
		}
		return nil
	}
	_, err := s.app.Verify(true, true, "0")
	requireCode(t, err, "E_STALE")
	if !changed {
		t.Fatal("late verification boundary was not exercised")
	}
	diagnosticNoVerification(t, s.app)
}

func TestDiagnosticStaleVerificationPreservesEarlierEvidence(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	if _, err := s.app.Apply(s.planID); err != nil {
		t.Fatal("committed verification fixture failed")
	}
	if _, err := s.app.Verify(false, false); err != nil {
		t.Fatal("initial ordinary verification failed")
	}
	reportPath := filepath.Join(s.app.Root, "verification.json")
	before, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal("initial verification evidence unavailable")
	}
	testWrite(t, filepath.Join(s.app.Active, "target.txt"), []byte("# external fixture writer\n"))
	_, err = s.app.Verify(true, true, "0")
	requireCode(t, err, "E_STALE")
	after, err := os.ReadFile(reportPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("stale verification overwrote prior private evidence")
	}
	view := diagnosticStatus(t, s.app)
	if view["device"].(map[string]any)["wallet_acceptance"] != "unverified" {
		t.Fatal("Status reused a previous readiness or tap declaration")
	}
}

func TestDiagnosticLateVerifiedBackupChangeCannotUpgradeCheckpoint(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	if _, err := s.app.Apply(s.planID); err != nil {
		t.Fatal("committed verification fixture failed")
	}
	s.app.Adoption = func() (map[string]any, error) {
		return map[string]any{"adoption": "verified", "wallet_acceptance": "unverified"}, nil
	}
	changed := false
	s.app.Fault = func(point string) error {
		if point == "after-backup" {
			changed = true
			testWrite(t, filepath.Join(s.app.Active, "target.txt"), []byte("# external writer during verified backup\n"))
		}
		return nil
	}
	_, err := s.app.Verify(false, false)
	requireCode(t, err, "E_STALE")
	if !changed {
		t.Fatal("late verified-backup boundary was not exercised")
	}
	diagnosticNoVerification(t, s.app)
	if _, err := os.Lstat(filepath.Join(s.app.Root, "last-verified.json")); !os.IsNotExist(err) {
		t.Fatal("changed verification context created a trusted checkpoint")
	}
}
