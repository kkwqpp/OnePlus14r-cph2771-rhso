package core

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These regressions use only ephemeral generated fixtures and temporary directories.
// Fake mode must prevent all Android command dispatch, including on Android itself.
func TestFinalRetainedKeyboxMustValidateAtPlanAndApply(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, kind := range []string{"missing", "malformed", "expired"} {
		t.Run("plan-"+kind, func(t *testing.T) {
			s := newSandbox(t, fixture)
			switch kind {
			case "missing":
				if err := os.Remove(filepath.Join(s.app.Active, "keybox.xml")); err != nil {
					t.Fatal("could not prepare absent fixture")
				}
			case "malformed":
				testWrite(t, filepath.Join(s.app.Active, "keybox.xml"), []byte("not XML"))
			case "expired":
				s.app.Now = func() time.Time { return coreTestNow.Add(25 * time.Hour) }
			}
			before, err := s.app.snapshot()
			if err != nil {
				t.Fatal("fixture snapshot failed")
			}
			_, err = s.app.Plan("", true, "2026-09-05")
			requireCode(t, err, "E_VALIDATION")
			requireSnapshot(t, s.app, before)
		})
	}
	t.Run("expires-after-plan", func(t *testing.T) {
		s := newSandbox(t, fixture)
		view, err := s.app.Plan("", true, "2026-09-05")
		if err != nil {
			t.Fatal("valid retained-keybox plan failed")
		}
		id := view.(map[string]any)["id"].(string)
		s.app.Now = func() time.Time { return coreTestNow.Add(25 * time.Hour) }
		_, err = s.app.Apply(id)
		requireCode(t, err, "E_VALIDATION")
		requireSnapshot(t, s.app, s.old)
		if _, err := os.Lstat(filepath.Join(s.app.Root, "journal.json")); !os.IsNotExist(err) {
			t.Fatal("expired retained keybox reached the transaction journal")
		}
		backups, err := os.ReadDir(filepath.Join(s.app.Root, "backups"))
		if err != nil || len(backups) != 0 {
			t.Fatal("expired retained keybox reached backup or mutation")
		}
	})
}

func TestFinalRollbackCanRestoreOriginallyInvalidKeybox(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	testWrite(t, filepath.Join(s.app.Active, "keybox.xml"), []byte("original invalid XML, deliberately preserved"))
	original, err := s.app.snapshot()
	if err != nil {
		t.Fatal("original snapshot failed")
	}
	v, err := s.app.Plan(s.stageID+":0:0:ecdsa,"+s.stageID+":0:1:rsa", true, "2026-09-05")
	if err != nil {
		t.Fatal("validated replacement plan failed")
	}
	if _, err = s.app.Apply(v.(map[string]any)["id"].(string)); err != nil {
		t.Fatal("validated replacement apply failed")
	}
	if _, err = s.app.Rollback("previous"); err != nil {
		t.Fatal("retained-keybox guard prevented restoration of original bytes")
	}
	requireSnapshot(t, s.app, original)
}

func finalResetFixture() resetJournal {
	return resetJournal{Schema: 1, State: "awaiting-manual-reboot", Boot: "synthetic-previous-boot", User: "0", ReviewHash: hash([]byte("review")), Scripts: map[string]string{"action.sh": hash([]byte("action")), "autopif4.sh": hash([]byte("autopif")), "killpi.sh": hash([]byte("kill"))}, Step: 5, Time: coreTestNow.Format(time.RFC3339), Backup: strings.Repeat("a", 32), PIFHash: hash([]byte("pif"))}
}

func TestFinalResetJournalCorruptionFailsClosed(t *testing.T) {
	fixture := syntheticKeybox(t)
	cases := map[string]func(*resetJournal){
		"schema":              func(r *resetJournal) { r.Schema = 99 },
		"terminal-step":       func(r *resetJournal) { r.State = "completed"; r.Step = 4 },
		"unknown-state":       func(r *resetJournal) { r.State = "synthetic-sensitive-reset-field" },
		"missing-review-hash": func(r *resetJournal) { r.ReviewHash = "" },
		"missing-script":      func(r *resetJournal) { delete(r.Scripts, "autopif4.sh") },
		"invalid-time":        func(r *resetJournal) { r.Time = "synthetic-sensitive-reset-field" },
		"invalid-backup":      func(r *resetJournal) { r.Backup = "../outside" },
		"invalid-user":        func(r *resetJournal) { r.User = "current" },
		"attempted-step":      func(r *resetJournal) { r.State = "attempting-clear"; r.Step = 5 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := newSandbox(t, fixture)
			r := finalResetFixture()
			change(&r)
			body, err := json.Marshal(r)
			if err != nil {
				t.Fatal("fixture encoding failed")
			}
			path := filepath.Join(s.app.Root, "reset-journal.json")
			testWrite(t, path, body)
			for _, action := range []string{"status", "resume", "complete"} {
				view, err := s.app.Reset(action, "PIF ACTION AND GMS FORCE-STOP COMPLETED", "")
				requireCode(t, err, "E_RECOVERY")
				finalAssertNoMarker(t, Response(view, err), "synthetic-sensitive-reset-field")
			}
			if !s.app.unfinished() {
				t.Fatal("corrupt terminal reset journal did not block another mutation")
			}
			_, err = s.app.Plan("", true, "")
			requireCode(t, err, "E_RECOVERY")
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, body) {
				t.Fatal("corrupt reset evidence was changed")
			}
			requireSnapshot(t, s.app, s.old)
		})
	}
	t.Run("malformed-is-not-none", func(t *testing.T) {
		s := newSandbox(t, fixture)
		testWrite(t, filepath.Join(s.app.Root, "reset-journal.json"), []byte("{"))
		_, err := s.app.Reset("status", "", "")
		requireCode(t, err, "E_RECOVERY")
		if !s.app.unfinished() {
			t.Fatal("malformed reset journal did not block mutation")
		}
	})
}

func TestFinalResetUserAndBootRequireSupportedFormats(t *testing.T) {
	a := &App{Fake: false}
	for _, token := range []string{"", "garbage", strings.Repeat("-", 36), strings.Repeat("a", 36)} {
		r := finalResetFixture()
		r.Boot = token
		requireCode(t, a.validateReset(r, false), "E_RECOVERY")
	}
	for _, user := range []string{"", "current", "-1", "0; command", "synthetic-sensitive-private-metadata"} {
		r := finalResetFixture()
		r.User = user
		r.Boot = "00000000-0000-0000-0000-000000000001"
		requireCode(t, a.validateReset(r, false), "E_RECOVERY")
	}
}

func TestFinalResetReviewAndResumeBindUserAndBoot(t *testing.T) {
	a := &App{Fake: true}
	r := finalResetFixture()
	config := map[string]FileState{"keybox.xml": {SHA256: hash([]byte("keybox"))}, "target.txt": {SHA256: hash([]byte("targets"))}, "security_patch.txt": {SHA256: hash([]byte("patch"))}}
	if resetHash(r.Scripts, []byte("pif"), config, "0") == resetHash(r.Scripts, []byte("pif"), config, "10") {
		t.Fatal("reset review was not bound to the reviewed Android user")
	}
	r.User = "10"
	requireCode(t, a.resetResumeContext(r), "E_STALE")
	r.User = "0"
	r.Boot = bootID()
	requireCode(t, a.resetResumeContext(r), "E_CONFIRM")
	r.Boot = "synthetic-previous-boot"
	if err := a.resetResumeContext(r); err != nil {
		t.Fatal("fake verified resume context was rejected")
	}
}

func TestFinalFakeResetNeverDispatchesOrCreatesDestructiveJournal(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	_, err := s.app.Reset("confirm", resetPhrase, strings.Repeat("a", 64))
	requireCode(t, err, "E_CAPABILITY")
	for _, name := range []string{"reset-journal.json", "journal.json"} {
		if _, err := os.Lstat(filepath.Join(s.app.Root, name)); !os.IsNotExist(err) {
			t.Fatal("fake reset created a destructive operation journal")
		}
	}
	entries, err := os.ReadDir(filepath.Join(s.app.Root, "backups"))
	if err != nil || len(entries) != 0 {
		t.Fatal("fake reset reached preparation before capability rejection")
	}
	requireSnapshot(t, s.app, s.old)
}

func TestFinalReviewedResetResumePreservesUnknownPIFContract(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	r := finalResetFixture()
	for name, body := range map[string]string{"action.sh": "action", "autopif4.sh": "autopif", "killpi.sh": "kill"} {
		// These are inert fixture strings, never executable programs.
		testWrite(t, filepath.Join(s.app.Modules, "playintegrityfix", name), []byte(body))
	}
	path := filepath.Join(s.app.Root, "reset-journal.json")
	if err := writeJSON(path, r); err != nil {
		t.Fatal("reset fixture write failed")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("reset fixture read failed")
	}
	v, err := s.app.Reset("resume", "", "")
	requireCode(t, err, "E_CAPABILITY")
	if v.(map[string]any)["state"] != "awaiting-manual-reboot" {
		t.Fatal("unverified network contract was reported as completed")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("blocked PIF resume changed the one-shot journal")
	}
	requireSnapshot(t, s.app, s.old)
	finalAssertNoMarker(t, Response(v, err), "synthetic-sensitive-private-metadata")
}

func TestFinalOwnerlessAndMalformedLocksRemainVisibleAndBlocked(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, kind := range []string{"ownerless", "invalid-json", "invalid-pid", "invalid-boot"} {
		t.Run(kind, func(t *testing.T) {
			s := newSandbox(t, fixture)
			lock := filepath.Join(s.app.Root, "operation.lock")
			if err := os.Mkdir(lock, 0700); err != nil {
				t.Fatal("lock fixture creation failed")
			}
			switch kind {
			case "invalid-json":
				testWrite(t, filepath.Join(lock, "owner.json"), []byte("{"))
			case "invalid-pid":
				if err := writeJSON(filepath.Join(lock, "owner.json"), lockRecord{-1, bootID()}); err != nil {
					t.Fatal("lock fixture write failed")
				}
			case "invalid-boot":
				// Recovery release does not run Android diagnostics. Real-mode record
				// validation must reject malformed boot tokens even on Windows.
				s.app.Fake = false
				if err := writeJSON(filepath.Join(lock, "owner.json"), lockRecord{os.Getpid(), "garbage"}); err != nil {
					t.Fatal("lock fixture write failed")
				}
			}
			view, err := s.app.Recovery("status")
			if err != nil {
				t.Fatal("damaged lock status should remain inspectable")
			}
			d := view.(map[string]any)
			if d["lock_present"] != true || d["lock_owner_verified"] != false {
				t.Fatal("damaged lock was hidden or its owner was declared verified")
			}
			_, err = s.app.Recovery("release-lock")
			requireCode(t, err, "E_BUSY")
			if _, err := os.Lstat(lock); err != nil {
				t.Fatal("unsafe lock release removed evidence")
			}
			requireSnapshot(t, s.app, s.old)
		})
	}
}

func finalAssertNoMarker(t *testing.T, v any, marker string) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil || bytes.Contains(b, []byte(marker)) {
		t.Fatal("private metadata or unknown fields reached a public response")
	}
	requireRedacted(t, v)
}

func TestFinalSupportDoesNotReflectUnknownOrCorruptMetadata(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	const marker = "synthetic-sensitive-private-metadata"
	if _, err := s.app.Apply(s.planID); err != nil {
		t.Fatal("fixture apply failed")
	}
	// A valid history record with an unknown token field must not reflect it.
	if err := writeJSON(filepath.Join(s.app.Root, "history.json"), []map[string]string{{"time": coreTestNow.Format(time.RFC3339), "type": "ingest", "id": s.stageID, "state": "staged", "token": marker}, {"time": marker, "type": marker, "id": marker, "state": marker}}); err != nil {
		t.Fatal("history fixture write failed")
	}
	stage := Stage{99, s.stageID, hash([]byte("stage")), marker, 1}
	if err := writeJSON(filepath.Join(s.app.Root, "staged", s.stageID, "stage.json"), stage); err != nil {
		t.Fatal("inventory fixture write failed")
	}
	j := mustJournal(t, s.app)
	backupPath := filepath.Join(s.app.Root, "backups", j.Backup, "backup.json")
	var b Backup
	if err := readJSON(backupPath, &b); err != nil {
		t.Fatal("backup fixture read failed")
	}
	b.Time, b.Type, b.Adoption = marker, marker, marker
	if err := writeJSON(backupPath, b); err != nil {
		t.Fatal("backup fixture write failed")
	}
	for _, command := range []string{"status", "diagnose", "backups"} {
		var v any
		var err error
		switch command {
		case "status":
			v, err = s.app.Status()
		case "diagnose":
			v, err = s.app.Diagnose()
		case "backups":
			v, err = s.app.Backups()
		}
		finalAssertNoMarker(t, Response(v, err), marker)
	}
	st := j.Intended["keybox.xml"]
	st.SHA256 = marker
	st.Metadata.SELinux = marker
	j.Intended["keybox.xml"] = st
	if err := writeJSON(filepath.Join(s.app.Root, "journal.json"), j); err != nil {
		t.Fatal("journal fixture write failed")
	}
	v, err := s.app.Recovery("status")
	requireCode(t, err, "E_RECOVERY")
	finalAssertNoMarker(t, Response(v, err), marker)
}

func TestFinalAtomicWritePreservesRequestedMetadataAndRejectsLinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "original")
	testWrite(t, path, []byte("original fixture"))
	m, err := getMetadata(path)
	if err != nil {
		t.Fatal("metadata fixture read failed")
	}
	m.Mode = 0400
	if err := atomicWrite(path, []byte("replacement fixture"), m); err != nil {
		t.Fatal("atomic metadata write failed")
	}
	after, err := getMetadata(path)
	if err != nil || after != m {
		t.Fatal("replacement did not retain the requested metadata")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Skip("host denies symlink fixtures; Android suite must exercise link guards")
	}
	requireCode(t, atomicWrite(link, []byte("must not write"), m), "E_PATH")
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, []byte("replacement fixture")) {
		t.Fatal("direct symlink write changed the target")
	}
	outside := filepath.Join(dir, "outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal("outside fixture creation failed")
	}
	rootLink := filepath.Join(dir, "private-root")
	if err := os.Symlink(outside, rootLink); err != nil {
		t.Fatal("root symlink fixture creation failed")
	}
	a := New(rootLink, filepath.Join(dir, "active"), filepath.Join(dir, "modules"), true)
	requireCode(t, a.Init(), "E_PATH")
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal("private root symlink was followed during initialization")
	}
	requireCode(t, atomicWrite(filepath.Join(rootLink, "child"), []byte("must not write"), m), "E_PATH")
}

func TestFinalStorageFormatIsIdempotentAndUnsupportedMigrationRefused(t *testing.T) {
	fixture := syntheticKeybox(t)
	for _, body := range []string{"{", "{}", `{"schema":2,"kind":"wallet-diagnostic-private-store"}`, `{"schema":1,"kind":"unsupported-store"}`} {
		t.Run("refusal-"+hash([]byte(body))[:8], func(t *testing.T) {
			s := newSandbox(t, fixture)
			formatPath := filepath.Join(s.app.Root, "format.json")
			testWrite(t, formatPath, []byte(body))
			stagedPath := filepath.Join(s.app.Root, "staged", s.stageID, "input.xml")
			before, err := os.ReadFile(stagedPath)
			if err != nil {
				t.Fatal("private fixture read failed")
			}
			requireCode(t, s.app.Init(), "E_FORMAT")
			_, err = s.app.Plan("", true, "")
			requireCode(t, err, "E_FORMAT")
			_, err = s.app.Apply(s.planID)
			requireCode(t, err, "E_FORMAT")
			gotFormat, err := os.ReadFile(formatPath)
			if err != nil || !bytes.Equal(gotFormat, []byte(body)) {
				t.Fatal("unsupported format was automatically rewritten")
			}
			after, err := os.ReadFile(stagedPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refused migration changed private staged material")
			}
			requireSnapshot(t, s.app, s.old)
		})
	}
	t.Run("supported-init-is-idempotent", func(t *testing.T) {
		s := newSandbox(t, fixture)
		path := filepath.Join(s.app.Root, "format.json")
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("private format marker was not created")
		}
		for i := 0; i < 2; i++ {
			if err := s.app.Init(); err != nil {
				t.Fatal("supported existing private format was rejected")
			}
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("idempotent init rewrote the format marker")
		}
		requireSnapshot(t, s.app, s.old)
	})
	t.Run("nonempty-unmarked-store-is-not-reinterpreted", func(t *testing.T) {
		s := newSandbox(t, fixture)
		path := filepath.Join(s.app.Root, "format.json")
		if err := os.Remove(path); err != nil {
			t.Fatal("unmarked private store fixture failed")
		}
		stagedPath := filepath.Join(s.app.Root, "staged", s.stageID, "input.xml")
		before, err := os.ReadFile(stagedPath)
		if err != nil {
			t.Fatal("legacy fixture read failed")
		}
		requireCode(t, s.app.Init(), "E_FORMAT")
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("nonempty unmarked store was silently assigned a schema")
		}
		after, err := os.ReadFile(stagedPath)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("refused unmarked migration changed private material")
		}
		requireSnapshot(t, s.app, s.old)
	})
}

func TestFinalRecoveryPreservesCurrentPartialSetBeforeRestoration(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	b, err := s.app.backup("apply", s.old)
	if err != nil {
		t.Fatal("original backup fixture failed")
	}
	testWrite(t, filepath.Join(s.app.Active, "security_patch.txt"), []byte("# partially applied fixture\nall=2026-07-05\n"))
	partial, err := s.app.snapshot()
	if err != nil {
		t.Fatal("partial snapshot fixture failed")
	}
	j := Journal{1, s.planID, b.ID, "recovery-required", s.app.time(), mustPlan(t, s).Intended}
	if err := writeJSON(filepath.Join(s.app.Root, "journal.json"), j); err != nil {
		t.Fatal("recovery journal fixture failed")
	}
	s.app.Fault = func(point string) error {
		if point == "before-backup" {
			return os.ErrPermission
		}
		return nil
	}
	if _, err := s.app.Recovery("restore"); err == nil {
		t.Fatal("recovery ignored failure to preserve the current partial set")
	}
	requireSnapshot(t, s.app, partial)
	if !s.app.unfinished() || mustJournal(t, s.app).State != "recovery-required" {
		t.Fatal("failed preservation lost the unfinished recovery state")
	}
	s.app.Fault = nil
	if _, err := s.app.Recovery("restore"); err != nil {
		t.Fatal("recovery did not succeed after storage failure was resolved")
	}
	requireSnapshot(t, s.app, s.old)
	entries, err := os.ReadDir(filepath.Join(s.app.Root, "backups"))
	if err != nil {
		t.Fatal("backup inventory fixture failed")
	}
	found := false
	for _, entry := range entries {
		if !entry.IsDir() || !validID.MatchString(entry.Name()) {
			continue
		}
		preserved, err := s.app.loadBackup(entry.Name())
		if err != nil {
			t.Fatal("recovery created an invalid backup")
		}
		if preserved.Type == "pre-recovery" && equal(preserved.Files, partial) {
			found = true
		}
	}
	if !found {
		t.Fatal("complete partial-set evidence was not retained before restoration")
	}
}

func TestFinalLateBackupChangeRejectedBeforeActiveWrite(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	if _, err := s.app.Apply(s.planID); err != nil {
		t.Fatal("late-backup fixture apply failed")
	}
	before, err := s.app.snapshot()
	if err != nil {
		t.Fatal("late-backup fixture snapshot failed")
	}
	j := mustJournal(t, s.app)
	j.State = "recovery-required"
	if err := writeJSON(filepath.Join(s.app.Root, "journal.json"), j); err != nil {
		t.Fatal("late-backup recovery fixture failed")
	}
	changed := false
	s.app.Fault = func(point string) error {
		if point == "before-restore-keybox.xml" && !changed {
			changed = true
			return os.WriteFile(filepath.Join(s.app.Root, "backups", j.Backup, "keybox.xml"), []byte("late changed backup bytes must never reach active"), 0600)
		}
		return nil
	}
	if _, err := s.app.Recovery("restore"); err == nil {
		t.Fatal("recovery accepted a backup changed after initial validation")
	}
	if !changed {
		t.Fatal("late-backup mutation checkpoint was not reached")
	}
	requireSnapshot(t, s.app, before)
	if !s.app.unfinished() {
		t.Fatal("late-backup rejection discarded pending recovery evidence")
	}
}

func TestFinalLastVerifiedRequiresTrustedIdentityEvidence(t *testing.T) {
	s := newSandbox(t, syntheticKeybox(t))
	if _, err := s.app.Apply(s.planID); err != nil {
		t.Fatal("verification fixture apply failed")
	}
	verifiedState, err := s.app.snapshot()
	if err != nil {
		t.Fatal("verification snapshot failed")
	}
	v, err := s.app.Verify(true, true)
	if err != nil || v.(map[string]any)["adoption"] != "pending" {
		t.Fatal("user declarations upgraded signer adoption")
	}
	if _, err := os.Lstat(filepath.Join(s.app.Root, "last-verified.json")); !os.IsNotExist(err) {
		t.Fatal("user declarations created a last-verified checkpoint")
	}
	_, err = s.app.Rollback("last-verified")
	requireCode(t, err, "E_BACKUP")
	// A parseable pointer to an ordinary backup is still not identity evidence.
	if err := writeJSON(filepath.Join(s.app.Root, "last-verified.json"), map[string]string{"backup": mustJournal(t, s.app).Backup}); err != nil {
		t.Fatal("unverified pointer fixture failed")
	}
	_, err = s.app.Rollback("last-verified")
	requireCode(t, err, "E_BACKUP")
	requireSnapshot(t, s.app, verifiedState)
	// This is a test-only trusted internal verifier. No request/CLI flag can set it.
	s.app.Adoption = func() (map[string]any, error) {
		return map[string]any{"adoption": "verified", "health": "healthy", "identity_evidence": "synthetic independently verified signer identity", "wallet_acceptance": "unverified"}, nil
	}
	v, err = s.app.Verify(false, false)
	if err != nil {
		t.Fatal("trusted identity fixture verification failed")
	}
	id, ok := v.(map[string]any)["verified_backup"].(string)
	if !ok || !validID.MatchString(id) {
		t.Fatal("trusted verifier did not create a named verified snapshot")
	}
	b, err := s.app.loadBackup(id)
	if err != nil || !b.Verified || b.Adoption != "verified" || !equal(b.Files, verifiedState) {
		t.Fatal("verified snapshot omitted identity state or current configuration")
	}
	testWrite(t, filepath.Join(s.app.Active, "target.txt"), []byte("# subsequent fixture change\n"))
	if _, err = s.app.Rollback("last-verified"); err != nil {
		t.Fatal("named verified checkpoint could not be restored")
	}
	requireSnapshot(t, s.app, verifiedState)
	finalAssertNoMarker(t, Response(v, nil), "synthetic-sensitive-private-metadata")
}
